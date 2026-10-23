"""Trusted fixed synthetic request controller, never exposed to agent code."""
import argparse
import base64
import json
import os
from pathlib import Path
import re
import sys

from probe_permissions import APPROVED_SANDBOX, request


def _target(repo, run_id):
    if repo != APPROVED_SANDBOX or not re.fullmatch(r'[0-9]+', run_id):
        raise ValueError('Only the named synthetic sandbox is authorised.')


def prepare(repo, run_id, request=request):
    _target(repo, run_id)
    prefix = 'repos/' + repo

    def call(method, path, payload=None, expected=(200,)):
        status, value = request(method, prefix + path, payload)
        if status not in expected:
            raise RuntimeError('Synthetic controller request failed with HTTP ' + str(status))
        return value

    target = call('GET', '')
    if target['full_name'] != repo or target['visibility'] != 'public':
        raise ValueError('Synthetic sandbox identity/visibility mismatch.')
    base = call('GET', '/branches/main')['commit']['sha']
    branch = 'synthetic-request-' + run_id
    call('POST', '/git/refs', {'ref': 'refs/heads/' + branch, 'sha': base}, (201,))
    current = call('GET', '/contents/synthetic-record.json?ref=' + branch)
    content = json.dumps({'synthetic': True, 'run_id': run_id,
                          'purpose': 'Permission and human-authority test only. No device or customer evidence.'}, indent=2) + '\n'
    changed = call('PUT', '/contents/synthetic-record.json', {
        'message': 'Create synthetic approval request', 'branch': branch,
        'sha': current['sha'], 'content': base64.b64encode(content.encode()).decode()}, (200, 201))
    commit = changed['commit']['sha']
    pr = call('POST', '/pulls', {'title': 'Synthetic release authority request ' + run_id,
                               'head': branch, 'base': 'main', 'draft': False,
                               'body': 'Synthetic fixtures only. Review the exact commit and approve in GitHub if acceptable. This does not approve a medical product or regulatory guidance.'}, (201,))
    call('POST', '/actions/workflows/release.yml/dispatches', {
        'ref': 'main', 'inputs': {'pr': str(pr['number']), 'commit': commit}}, (204,))
    return {'pr': pr['number'], 'commit': commit, 'review_url': pr['html_url'], 'branch': branch}


def publish(repo, pr_number, commit, run_id, policy_commit, request=request, authorise=None):
    _target(repo, run_id)
    if (type(pr_number) is not int or pr_number < 1 or not re.fullmatch(r'[0-9a-f]{40}', commit)
            or not re.fullmatch(r'[0-9a-f]{40}', policy_commit)):
        raise ValueError('Malformed synthetic release revision/request.')
    if authorise is None:
        sys.path.insert(0, str(Path(__file__).resolve().parent / 'tools'))
        from rds_github import collect_github, evaluate_github
        policy = json.loads(Path(__file__).with_name('.rds-policy.json').read_text())
        policy['policy_commit'] = policy_commit
        authorise = lambda: evaluate_github(policy, collect_github(repo, pr_number, 'synthetic-release'), commit, pr_number)
    if authorise().get('status') != 'eligible':
        raise RuntimeError('Synthetic release remains blocked by current authority checks.')
    prefix = 'repos/' + repo
    tag = 'synthetic-approved-' + run_id
    status, result = request('POST', prefix + '/releases', {
        'tag_name': tag, 'target_commitish': commit, 'name': 'Approved synthetic authority probe ' + run_id,
        'body': 'Synthetic non-production fixture only. Reviewed request #' + str(pr_number) + ', commit ' + commit,
        'draft': False, 'prerelease': True, 'make_latest': 'false', 'generate_release_notes': False})
    if status != 201:
        raise RuntimeError('Synthetic release creation failed; no success claimed.')
    status, observed = request('GET', prefix + '/releases/tags/' + tag)
    ref_status, ref = request('GET', prefix + '/git/ref/tags/' + tag)
    if (status != 200 or ref_status != 200 or observed['target_commitish'] != commit
            or observed['draft'] is not False or observed['prerelease'] is not True
            or ref['object']['type'] != 'commit' or ref['object']['sha'] != commit):
        raise RuntimeError('Synthetic release read-back did not establish the exact target.')
    return {'status': 'observed_synthetic_release', 'commit': commit, 'url': observed['html_url']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('prepare', 'release'))
    args = parser.parse_args()
    if os.environ.get('GITHUB_ACTIONS') != 'true':
        parser.exit(1, 'Trusted isolated GitHub job required.\n')
    repo = os.environ.get('GITHUB_REPOSITORY', '')
    run_id = os.environ.get('GITHUB_RUN_ID', '')
    try:
        if args.command == 'prepare':
            result = prepare(repo, run_id)
        else:
            expected = repo + '/.github/workflows/release.yml@refs/heads/main'
            if os.environ.get('GITHUB_WORKFLOW_REF') != expected:
                raise ValueError('Trusted main release workflow required.')
            result = publish(repo, int(os.environ['SYNTHETIC_PR']), os.environ['SYNTHETIC_COMMIT'],
                             run_id, os.environ['GITHUB_SHA'])
        print(json.dumps(result, indent=2))
    except (RuntimeError, ValueError, KeyError, OSError):
        parser.exit(1, 'Synthetic authority operation incomplete; inspect host state, no success claimed.\n')


if __name__ == '__main__':
    main()
