"""GitHub authority predicates; only a trusted live invocation has provenance."""
import re
import json
import base64
import subprocess
from datetime import datetime, timezone
from urllib.parse import quote
from typing import Any


class HostReadError(RuntimeError):
    """Unavailable or malformed host facts must hold the gate."""


def _api(path, paginate=False) -> Any:
    command = ['gh', 'api', '--hostname', 'github.com', '--method', 'GET',
               '-H', 'Accept: application/vnd.github+json',
               '-H', 'X-GitHub-Api-Version: 2022-11-28']
    if paginate:
        command.extend(['--paginate', '--slurp'])
        path += ('&' if '?' in path else '?') + 'per_page=100'
    command.append(path)
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=30)
        if result.returncode:
            raise HostReadError('Host read unavailable; check identity, access and endpoint configuration.')
        value = json.loads(result.stdout)
        if paginate:
            if not isinstance(value, list) or any(not isinstance(page, list) for page in value):
                raise HostReadError('Malformed paginated host response.')
            return [item for page in value for item in page]
        return value
    except (OSError, subprocess.TimeoutExpired, ValueError) as error:
        raise HostReadError('Host transport or JSON decoding failed.') from None


def collect_github(repo, pr_number, environment, read=None):
    """Read current public-host state twice; never load a supplied fact file."""
    if (not isinstance(repo, str) or not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repo)
            or type(pr_number) is not int or pr_number <= 0
            or not isinstance(environment, str) or not re.fullmatch(r'[A-Za-z0-9_.-]+', environment)):
        raise HostReadError('Malformed repository, pull request or environment identifier.')
    read = read or _api
    prefix = 'repos/' + repo
    try:
        repository = read(prefix)
        if repository['full_name'] != repo or repository['visibility'] != 'public':
            raise HostReadError('Only an exact public repository target is supported.')
        branch = quote(repository['default_branch'], safe='')
        commit = read(prefix + '/branches/' + branch)['commit']['sha']

        def controls():
            rules = read(prefix + '/rulesets', paginate=True)
            return {
                'protection': read(prefix + '/branches/' + branch + '/protection'),
                'environment': read(prefix + '/environments/' + quote(environment, safe='')),
                'workflow_permissions': read(prefix + '/actions/permissions/workflow'),
                'rulesets': [read(prefix + '/rulesets/' + str(r['id'])) for r in rules],
            }

        first = controls()
        pr = read(prefix + '/pulls/' + str(pr_number))
        reviews = read(prefix + '/pulls/' + str(pr_number) + '/reviews', paginate=True)
        document = read(prefix + '/contents/.rds-policy.json?ref=' + commit)
        if document.get('encoding') != 'base64':
            raise HostReadError('Trusted policy is not a normal repository file.')
        policy_document = json.loads(base64.b64decode(document['content'], validate=False).decode('utf-8'))
        final = controls()
        final_pr = read(prefix + '/pulls/' + str(pr_number))
        final_reviews = read(prefix + '/pulls/' + str(pr_number) + '/reviews', paginate=True)
        final_commit = read(prefix + '/branches/' + branch)['commit']['sha']
        return dict(first, repository=repository, policy_commit=commit,
                    policy_document=policy_document, final_policy_commit=final_commit,
                    pr=pr, final_head=final_pr['head']['sha'], reviews=reviews,
                    complete=(first == final and reviews == final_reviews and pr == final_pr),
                    observed_on=datetime.now(timezone.utc).isoformat())
    except (KeyError, ValueError, TypeError, AttributeError, UnicodeError):
        raise HostReadError('Host response shape is incomplete or malformed.') from None


def evaluate_github(policy, facts, target_commit, pr_number):
    """Pure predicate check. Caller must collect facts in an isolated trusted job."""
    reasons = []
    try:
        if (not re.fullmatch(r'[0-9a-f]{40}', target_commit)
                or not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', policy['repository'])
                or type(pr_number) is not int or pr_number <= 0
                or not re.fullmatch(r'[0-9a-f]{40}', policy['policy_commit'])
                or not policy['reviewer_ids']
                or any(type(i) is not int or i <= 0 for i in policy['reviewer_ids'])):
            reasons.append('INVALID_IDENTIFIER')
        if facts.get('complete') is not True:
            reasons.append('INCOMPLETE_FACTS')
        if facts['repository']['full_name'] != policy['repository']:
            reasons.append('REPOSITORY_MISMATCH')
        if facts['repository']['visibility'] != 'public':
            reasons.append('UNSUPPORTED_VISIBILITY')
        pr = facts['pr']
        if (pr['number'] != pr_number or pr['head']['repo']['full_name'] != policy['repository']
                or pr['base']['repo']['full_name'] != policy['repository']
                or pr['base']['ref'] != policy['branch'] or pr['state'] != 'open' or pr['draft']):
            reasons.append('PR_SCOPE')
        if pr['head']['sha'] != target_commit or facts['final_head'] != target_commit:
            reasons.append('HEAD_MOVED')
        if facts['policy_commit'] != policy['policy_commit'] or facts['final_policy_commit'] != policy['policy_commit']:
            reasons.append('POLICY_MOVED')
        if facts['policy_document'] != {k: v for k, v in policy.items() if k != 'policy_commit'}:
            reasons.append('POLICY_MISMATCH')
        if pr['mergeable_state'] != 'clean':
            reasons.append('HOST_REVIEW_REQUIREMENTS')
        protection = facts['protection']
        required = protection['required_pull_request_reviews']
        if (protection['enforce_admins']['enabled'] is not True
                or protection['allow_force_pushes']['enabled'] is not False
                or protection['allow_deletions']['enabled'] is not False
                or required['required_approving_review_count'] < 1
                or required['dismiss_stale_reviews'] is not True
                or required['require_code_owner_reviews'] is not True
                or any(required.get('bypass_pull_request_allowances', {}).values())):
            reasons.append('BRANCH_PROTECTION')
        if any(x.get('enforcement') == 'active' and x.get('bypass_actors') for x in facts['rulesets']):
            reasons.append('RULESET_BYPASS')
        if facts['workflow_permissions']['default_workflow_permissions'] != 'read':
            reasons.append('WORKFLOW_PERMISSIONS')
        env = facts['environment']
        controls = [x for x in env['protection_rules'] if x.get('type') == 'required_reviewers']
        branch_policy = env['deployment_branch_policy']
        if (env['name'] != policy['environment'] or env.get('can_admins_bypass') is not False
                or branch_policy.get('protected_branches') is not True
                or branch_policy.get('custom_branch_policies') is not False
                or len(controls) != 1 or controls[0].get('prevent_self_review') is not True
                or not controls[0].get('reviewers')
                or any(r.get('type') != 'User' or r['reviewer']['id'] not in policy['reviewer_ids']
                       for r in controls[0]['reviewers'])):
            reasons.append('ENVIRONMENT_PROTECTION')
        latest = {}
        for review in sorted(facts['reviews'], key=lambda r: r['id']):
            if review['state'] in ('APPROVED', 'DISMISSED', 'CHANGES_REQUESTED'):
                latest[review['user']['id']] = review
        eligible = [r for actor, r in latest.items() if actor in policy['reviewer_ids']
                    and actor != pr['user']['id'] and r['user']['type'] == 'User'
                    and r['state'] == 'APPROVED']
        if not eligible or any(r['state'] == 'CHANGES_REQUESTED' for actor, r in latest.items()
                               if actor in policy['reviewer_ids']):
            reasons.append('APPROVAL_AUTHORITY')
        if not any(r['commit_id'] == target_commit for r in eligible):
            reasons.append('APPROVAL_COMMIT_MISMATCH')
        if sum(r['commit_id'] == target_commit for r in eligible) < required['required_approving_review_count']:
            reasons.append('APPROVAL_COUNT')
    except (KeyError, ValueError, TypeError, AttributeError):
        reasons.append('MALFORMED_FACTS')
    return {'status': 'blocked' if reasons else 'eligible', 'reasons': reasons,
            'scope': 'Host predicates only, not product verification or an electronic signature.'}
