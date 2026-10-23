"""Destructive-attempt probes, synthetic sandbox only, with a restricted job token."""
import base64
import json
import os
import re
import urllib.error
import urllib.request

APPROVED_SANDBOX = 'miguelangeloazevedo/regulated-dev-skills-assurance-sandbox'


def request(method, path, payload=None):
    if not path.startswith('repos/' + APPROVED_SANDBOX + '/') and path != 'repos/' + APPROVED_SANDBOX:
        raise ValueError('Request outside the authorised synthetic sandbox.')
    token = os.environ.get('GH_TOKEN')
    if not token:
        raise RuntimeError('Restricted job credential is unavailable.')
    data = None if payload is None else json.dumps(payload).encode()
    req = urllib.request.Request('https://api.github.com/' + path, data=data, method=method,
                                 headers={'Authorization': 'Bearer ' + token,
                                          'Accept': 'application/vnd.github+json',
                                          'Content-Type': 'application/json',
                                          'X-GitHub-Api-Version': '2022-11-28'})
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            raw = response.read()
            return response.status, json.loads(raw) if raw else None
    except urllib.error.HTTPError as error:
        return error.code, None


def classify(status, before, after):
    if 200 <= status < 300:
        return 'unexpected_success'
    if before != after:
        return 'target_changed'
    return 'denied' if status == 403 else 'inconclusive'


def probe(repo, pr_number, commit, run_id, request=request):
    if (repo != APPROVED_SANDBOX or type(pr_number) is not int or pr_number < 1
            or not re.fullmatch(r'[0-9a-f]{40}', commit) or not re.fullmatch(r'[0-9]+', run_id)):
        raise ValueError('Probe target is not the named synthetic sandbox/configuration.')
    prefix = 'repos/' + repo

    def read(path):
        status, value = request('GET', prefix + path)
        if status != 200:
            raise RuntimeError('Probe target could not be read; denial is not established.')
        return value

    repository = read('')
    if repository.get('visibility') != 'public' or repository.get('full_name') != repo:
        raise ValueError('Target must be the exact public synthetic sandbox.')
    pr = read('/pulls/' + str(pr_number))
    if pr['head']['sha'] != commit or pr['head']['repo']['full_name'] != repo:
        raise ValueError('Synthetic request revision or repository does not match.')
    results = []

    def attempt(name, method, endpoint, payload, snapshot):
        before = snapshot()
        status, _ = request(method, prefix + endpoint, payload)
        after = snapshot()
        outcome = classify(status, before, after)
        results.append({'probe': name, 'http_status': status, 'outcome': outcome,
                        'target_unchanged': before == after})
        if outcome != 'denied':
            raise RuntimeError(json.dumps({'status': 'incomplete_or_failed', 'results': results}))

    attempt('unauthorised-approval', 'POST', '/pulls/' + str(pr_number) + '/reviews',
            {'commit_id': commit, 'event': 'APPROVE', 'body': 'Synthetic unauthorised permission probe, not a human approval.'},
            lambda: read('/pulls/' + str(pr_number) + '/reviews?per_page=100'))
    for name, path in [('protected-record', 'synthetic-record.json'), ('protected-policy', '.rds-policy.json'),
                       ('protected-workflow', '.github/workflows/release.yml')]:
        endpoint = '/contents/' + path
        current = read(endpoint + '?ref=main')
        attempt(name, 'PUT', endpoint,
                {'message': 'Synthetic unauthorised permission probe', 'content': current['content'],
                 'sha': current['sha'], 'branch': 'main'},
                lambda endpoint=endpoint: read(endpoint + '?ref=main')['sha'])
    attempt('unauthorised-release', 'POST', '/releases',
            {'tag_name': 'denied-probe-' + run_id, 'target_commitish': commit,
             'name': 'Synthetic denied probe', 'body': 'Synthetic permission probe only.',
             'draft': False, 'prerelease': True, 'make_latest': 'false', 'generate_release_notes': False},
            lambda: [r['id'] for r in read('/releases?per_page=100')])
    return {'status': 'observed_denials', 'repository': repo, 'commit': commit,
            'run_id': run_id, 'scope': 'Restricted host token, not agent/model behavior or product verification.',
            'results': results}


def main():
    if os.environ.get('GITHUB_ACTIONS') != 'true':
        raise SystemExit('Run only in the isolated restricted GitHub job.')
    try:
        result = probe(os.environ['GITHUB_REPOSITORY'], int(os.environ['SYNTHETIC_PR']),
                       os.environ['SYNTHETIC_COMMIT'], os.environ['GITHUB_RUN_ID'])
    except (ValueError, KeyError, RuntimeError, urllib.error.URLError) as error:
        # No HTTP response bodies or credentials are emitted.
        print(str(error) if isinstance(error, RuntimeError) else 'Probe setup/transport failed; not an observed denial.')
        return 1
    print(json.dumps(result, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
