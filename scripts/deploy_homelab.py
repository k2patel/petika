#!/usr/bin/env python3
"""Render or deploy the homelab overlay using local kubectl and Gitea settings."""
import argparse
import json
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def run(*args):
    return subprocess.check_output(args, cwd=ROOT, text=True)


def setting(name, default):
    if name in os.environ:
        return os.environ[name]
    value = json.loads(run('tea', 'api', f'repos/k2patel/petika/actions/variables/{name}'))
    return value.get('value', value.get('data', default))


def configure(document, image, https, cookie_secure, endpoint=""):
    if https not in ('off', 'on', 'both'):
        raise ValueError('HTTPS must be off, on, or both')
    if cookie_secure not in ('true', 'false'):
        raise ValueError('PETIKA_COOKIE_SECURE must be true or false')
    for item in document['items']:
        if item['kind'] == 'Service':
            ports = []
            if https in ('off', 'both'):
                ports.append({'name': 'http', 'port': 80, 'targetPort': 8080})
            if https in ('on', 'both'):
                ports.append({'name': 'https', 'port': 443, 'targetPort': 8443})
            item['spec']['ports'] = ports
        if item['kind'] == 'Deployment':
            spec = item['spec']['template']['spec']
            for container in spec['containers']:
                if container['name'] == 'petika':
                    container['image'] = image
                    container['env'].append({'name': 'PETIKA_COOKIE_SECURE', 'value': cookie_secure})
                    container['env'].append({'name': 'PETIKA_ENDPOINT', 'value': endpoint})
            if https == 'off':
                spec['containers'] = [c for c in spec['containers'] if c['name'] != 'tls']
                spec['volumes'] = [v for v in spec['volumes'] if v['name'] not in ('tls', 'proxy', 'proxy-tmp')]
    return document


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', required=True, help='Published registry image tag or digest')
    parser.add_argument('--apply', action='store_true', help='Apply and wait for rollout; otherwise render JSON')
    args = parser.parse_args()
    https = setting('HTTPS', 'off').lower()
    secure = setting('PETIKA_COOKIE_SECURE', 'true').lower()
    endpoint = setting('PETIKA_ENDPOINT', '')
    stream = run('kubectl', 'create', '--dry-run=client', '-k', 'deploy/homelab', '-o', 'json').strip()
    items = []
    while stream:
        item, end = json.JSONDecoder().raw_decode(stream)
        items.append(item)
        stream = stream[end:].strip()
    document = {'apiVersion': 'v1', 'kind': 'List', 'items': items}
    rendered = json.dumps(configure(document, args.image, https, secure, endpoint), indent=2)
    if args.apply:
        subprocess.run(['kubectl', 'apply', '-f', '-'], input=rendered, text=True, check=True)
        subprocess.run(['kubectl', '-n', 'petika', 'rollout', 'status', 'deployment/petika', '--timeout=300s'], check=True)
    else:
        print(rendered)


if __name__ == '__main__':
    main()
