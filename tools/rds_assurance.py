"""Inspect assurance declarations. This does not authenticate their author."""
import json
import argparse
import html
import hashlib
import re
import os
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

KINDS = ('claims', 'support', 'regulatory-review', 'record-system-assessment')
STATES = {'declared', 'instruction_observed', 'host_observed', 'failed',
          'unsupported', 'unassessed', 'stale'}


def _public_ref(value):
    if not isinstance(value, str):
        return False
    url = urlsplit(value)
    return url.scheme == 'https' and bool(url.hostname) and not url.username and not url.password


def _date(value):
    if not isinstance(value, str):
        return False
    try:
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed <= datetime.now(timezone.utc)
    except (ValueError, TypeError):
        return False


def validate_bundle(root):
    """Return structural findings, never an authenticated assurance verdict."""
    root = Path(root).resolve()
    findings = []
    for kind in KINDS:
        path = root / 'assurance' / (kind + '.json')
        relative = 'assurance/' + kind + '.json'

        def issue(code, message):
            findings.append({'code': code, 'path': relative, 'message': message})

        try:
            data = json.loads(path.read_text(encoding='utf-8'))
        except (OSError, ValueError, UnicodeError):
            issue('ASSURANCE_INPUT', 'Cannot read assurance JSON.')
            continue
        if (not isinstance(data, dict) or data.get('schema_version') != 1
                or data.get('kind') != kind or not isinstance(data.get('items'), list)):
            issue('ASSURANCE_INPUT', 'Expected version 1 envelope with matching kind and items list.')
            continue
        seen = set()
        for item in data['items']:
            if not isinstance(item, dict):
                issue('ASSURANCE_INPUT', 'Each item must be an object.')
                continue
            ident = item.get('id')
            if not isinstance(ident, str) or not re.fullmatch(r'[a-z0-9][a-z0-9.-]*', ident) or ident in seen:
                issue('ASSURANCE_ID', 'Item ID must be nonempty, stable and unique within its register.')
            else:
                seen.add(ident)
            if not isinstance(item.get('scope'), str) or not item['scope'].strip():
                issue('ASSURANCE_SCOPE', 'State the scope of this claim.')
            if item.get('status') not in STATES:
                issue('ASSURANCE_STATE', 'Unsupported assurance state.')
            if re.search(r'/Users/|/home/|file://|\.ts\.net|(?:gh[pousr]_|github_pat_)[A-Za-z0-9_]{12}', json.dumps(item)):
                issue('ASSURANCE_PRIVATE', 'Public assurance must not contain private paths, hosts or credentials.')
            if 'skills_revision' in item and not re.fullmatch(r'[a-f0-9]{40}', str(item['skills_revision'])):
                issue('ASSURANCE_REVISION', 'Expected an exact git revision, not a moving name.')
            if 'observed_on' in item and not _date(item['observed_on']):
                issue('ASSURANCE_DATE', 'Observation date is malformed or in the future.')
            bindings = item.get('bindings', [])
            if not isinstance(bindings, list):
                issue('ASSURANCE_BINDING', 'Bindings must be a list.')
                bindings = []
            for binding in bindings:
                if not isinstance(binding, dict):
                    issue('ASSURANCE_BINDING', 'Expected path/hash binding.')
                    continue
                name, digest = binding.get('path'), binding.get('sha256')
                if (not isinstance(name, str) or not name or Path(name).is_absolute()
                        or '..' in Path(name).parts
                        or not re.fullmatch(r'[0-9a-f]{64}', str(digest))):
                    issue('ASSURANCE_BINDING', 'Expected safe relative path and SHA-256.')
                    continue
                target = (root / name).resolve()
                try:
                    target.relative_to(root)
                    actual = hashlib.sha256(target.read_bytes()).hexdigest()
                except (OSError, ValueError):
                    issue('ASSURANCE_BINDING', 'Bound source is unavailable or outside root.')
                    continue
                if actual != digest and item.get('status') != 'stale':
                    issue('ASSURANCE_STALE', 'Bound content has changed; reconsider the claim/review.')
            review = item.get('review', {})
            if not isinstance(review, dict):
                issue('ASSURANCE_REVIEW_EVIDENCE', 'Review must be an object.')
                continue
            if review.get('status') == 'completed' and review.get('kind') != 'human':
                issue('ASSURANCE_REVIEW_KIND', 'Completed human review requires a human reviewer.')
            if review.get('status') == 'completed':
                if (not all(isinstance(review.get(k), str) and review[k].strip() for k in ('by', 'conclusion'))
                        or not _date(review.get('on')) or not _public_ref(review.get('evidence'))
                        or not bindings or not re.fullmatch(r'[0-9a-f]{40}', str(review.get('revision')))):
                    issue('ASSURANCE_REVIEW_EVIDENCE', 'Completed review needs identity, date, conclusion, revision, bindings and evidence.')
            elif review.get('status') == 'pending':
                if any(review.get(k) for k in ('by', 'on', 'conclusion', 'evidence')):
                    issue('ASSURANCE_PENDING_REVIEW', 'Pending review must not invent completed decision fields.')
            elif review:
                issue('ASSURANCE_REVIEW_EVIDENCE', 'Review status is pending or completed.')
            if item.get('status') in ('host_observed', 'instruction_observed'):
                config = item.get('configuration')
                if (not isinstance(config, dict) or not config or not bindings
                        or not _public_ref(item.get('evidence')) or not _date(item.get('observed_on'))
                        or not re.fullmatch(r'[a-f0-9]{40}', str(item.get('skills_revision')))):
                    issue('ASSURANCE_MEASUREMENT', 'Measured claim needs exact configuration, revision, bindings, observation date and evidence.')
                required_config = (('harness', 'harness_version', 'provider', 'model', 'model_version')
                                   if item['status'] == 'instruction_observed' else
                                   ('host', 'repository', 'policy_revision', 'workflow_revision', 'workflow', 'credential', 'runner'))
                if (not isinstance(config, dict)
                        or not all(isinstance(config.get(k), str) and config[k].strip() for k in required_config)
                        or (item['status'] == 'host_observed' and
                            (not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', str(config.get('repository')))
                             or any(not re.fullmatch(r'(?:[a-f0-9]{40}|[a-f0-9]{64})', str(config.get(k)))
                                    for k in ('policy_revision', 'workflow_revision'))))):
                    issue('ASSURANCE_CONFIGURATION', 'Measured state needs its applicable exact harness/model or host/policy/credential configuration.')
            if kind == 'regulatory-review':
                sources = item.get('sources')
                if (item.get('basis') not in ('obligation', 'interpretation', 'repository_rule')
                        or not isinstance(sources, list) or not sources
                        or any(not isinstance(s, dict) or not all(isinstance(s.get(k), str) and s[k].strip()
                               for k in ('title', 'edition', 'locator', 'authority')) for s in sources)):
                    issue('ASSURANCE_SOURCE', 'Each regulatory entry needs basis and independently locatable source/edition/authority.')
            if kind == 'record-system-assessment' and (item.get('assessment_status') == 'accepted'
                                                       or item.get('record_system_validated') is True):
                validation = item.get('validation')
                if (not isinstance(validation, dict)
                        or not all(validation.get(k) for k in ('intended_use', 'revision', 'accepted_by'))
                        or not re.fullmatch(r'(?:[0-9a-f]{40}|[0-9a-f]{64})', str(validation.get('revision')))
                        or not bindings
                        or not _date(validation.get('accepted_on')) or not _public_ref(validation.get('evidence'))
                        or item.get('gaps') != []
                        or not all(item.get('controls', {}).get(k) == 'assessed' for k in
                                   ('identity', 'authority', 'signature', 'audit_trail', 'integrity', 'correction', 'retention', 'retrieval'))):
                    issue('ASSURANCE_SYSTEM_VALIDATION', 'An accepted system assessment needs intended-use evidence, owner acceptance and assessed controls; not a boolean.')
    return findings


def render_summary(root):
    """Render declarations without elevating their assurance status."""
    findings = validate_bundle(root)
    if findings:
        raise ValueError('Invalid assurance bundle: ' + ', '.join(x['code'] for x in findings))
    views = {}
    for kind in KINDS:
        data = json.loads((Path(root) / 'assurance' / (kind + '.json')).read_text(encoding='utf-8'))
        lines = ['# ' + kind.replace('-', ' ').capitalize(), '',
                 'These are declarations, not authenticated decisions or product certification.', '',
                 'Generated from [the source register](../../assurance/' + kind + '.json). Structural checks do not authenticate the underlying evidence.', '']
        if data.get('coverage'):
            lines.extend(['## Review coverage', '', '```json',
                          json.dumps(data['coverage'], indent=2, sort_keys=True), '```', ''])
        for item in data['items']:
            lines.extend(['## ' + html.escape(item['id']), '',
                          '**State:** ' + item['status'], '', html.escape(item['scope']), ''])
            if item.get('limitations'):
                lines.extend(['**Limits:** ' + html.escape(item['limitations']), ''])
            for field, label in [('basis', 'Basis'), ('classes', 'Classes'), ('jurisdictions', 'Jurisdictions'),
                                 ('skills_revision', 'Skills revision'), ('observed_on', 'Observed on'),
                                 ('assessment_status', 'Assessment status')]:
                if field in item:
                    lines.extend(['**' + label + ':** ' + html.escape(str(item[field])), ''])
            for field, label in [('configuration', 'Configuration'), ('bindings', 'Content bindings'),
                                 ('controls', 'Controls'), ('gaps', 'Open gaps')]:
                if field in item:
                    lines.extend(['**' + label + ':**', '', '```json',
                                  json.dumps(item[field], indent=2, sort_keys=True), '```', ''])
            if item.get('sources'):
                lines.extend(['**Sources:** ' + '; '.join(html.escape(s['title'] + ' (' + s['edition'] + ') ' + s['locator'])
                                                          for s in item['sources']), ''])
            if 'review' in item:
                lines.extend(['**Human review:** ' + item['review']['status'], ''])
            if item.get('evidence'):
                lines.extend(['**Evidence:** ' + html.escape(item['evidence']), ''])
        views[kind] = '\n'.join(lines)
    return views


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    check = sub.add_parser('validate', help='Validate declarations, not host authorisation.')
    check.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1])
    host = sub.add_parser('github-preflight', help='Read host authority in a trusted GitHub job, never from a supplied snapshot.')
    host.add_argument('--repo', required=True)
    host.add_argument('--commit', required=True)
    host.add_argument('--pr', type=int, required=True)
    host.add_argument('--environment', required=True)
    host.add_argument('--policy', type=Path, required=True)
    host.add_argument('--policy-commit', required=True)
    args = parser.parse_args(argv)
    if args.command == 'github-preflight':
        # These context checks prevent accidental local use, not spoofing by a privileged process.
        # The real boundary is the isolated runner, scoped credentials and host-held human gate.
        from rds_github import collect_github, evaluate_github, HostReadError
        expected_ref = args.repo + '/.github/workflows/release.yml@refs/heads/main'
        if (os.environ.get('GITHUB_ACTIONS') != 'true'
                or os.environ.get('GITHUB_WORKFLOW_REF') != expected_ref
                or os.environ.get('GITHUB_SHA') != args.policy_commit):
            print(json.dumps({'status': 'blocked', 'reasons': ['HOST_CONTEXT']}))
            return 1
        try:
            policy = json.loads(args.policy.read_text(encoding='utf-8'))
            if not isinstance(policy, dict):
                raise ValueError('Policy must be an object.')
            policy['policy_commit'] = args.policy_commit
            facts = collect_github(args.repo, args.pr, args.environment)
            result = evaluate_github(policy, facts, args.commit, args.pr)
            result.update(repository=args.repo, commit=args.commit, policy_commit=args.policy_commit,
                          observed_on=facts['observed_on'])
        except (OSError, ValueError, UnicodeError, HostReadError):
            result = {'status': 'blocked', 'reasons': ['HOST_UNAVAILABLE_OR_INVALID_POLICY']}
        print(json.dumps(result, indent=2))
        return 0 if result['status'] == 'eligible' else 1
    findings = validate_bundle(args.root)
    print(json.dumps({'status': 'structural_only' if not findings else 'invalid', 'findings': findings}, indent=2))
    return 1 if findings else 0


if __name__ == '__main__':
    raise SystemExit(main())
