#!/usr/bin/env python3
"""Fetch the current user's authorized encrypted data with a read-only Petika backup key."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import ssl
import subprocess
import tempfile
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import build_opener, HTTPRedirectHandler, HTTPSHandler, Request

from backup_recovery import inventory, private_copy

ID = re.compile(r'[0-9a-f]{64}')


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, new_url):
        raise ValueError('Backup API redirects are not allowed')


def private_file(path):
    if path.is_symlink() or not path.is_file() or (os.name == 'posix' and path.stat().st_mode & 0o077):
        raise ValueError('Credential file must be a regular owner-only file')


def origin(value):
    url = urlsplit(value)
    if (url.scheme not in ('http', 'https') or not url.hostname or url.username or url.password
            or url.path not in ('', '/') or url.query or url.fragment
            or (url.scheme == 'http' and url.hostname not in ('localhost', '127.0.0.1', '::1'))):
        raise ValueError('Use an HTTPS origin (HTTP is allowed only on loopback)')
    return value.rstrip('/')


class API:
    def __init__(self, server, key_file, ca_file=None):
        self.server = origin(server)
        private_file(key_file)
        self.key = key_file.read_text().strip()
        if not re.fullmatch(r'pbk_[0-9a-f]{64}_[0-9a-f]{64}', self.key):
            raise ValueError('Invalid backup key file')
        self.opener = build_opener(NoRedirect(), HTTPSHandler(context=ssl.create_default_context(cafile=ca_file)))

    def get(self, path):
        request = Request(self.server + path, headers={'Authorization': 'Bearer ' + self.key})
        try:
            with self.opener.open(request, timeout=60) as response:
                if response.status != 200 or response.headers.get_content_type() != 'application/json':
                    raise ValueError('Unexpected backup API response')
                content = response.read(16 * 1024 * 1024 + 1)
        except HTTPError as error:
            raise ValueError(f'Backup API returned HTTP {error.code}; check the key and current permissions') from None
        if len(content) > 16 * 1024 * 1024:
            raise ValueError('Backup API response exceeds size limit')
        return json.loads(content)


def check_index(index):
    if (not isinstance(index, dict) or index.get('backup_version') != 1 or index.get('kind') != 'user'
            or not ID.fullmatch(index.get('deployment_id', ''))
            or not ID.fullmatch(index.get('user', {}).get('id', ''))):
        raise ValueError('Invalid user backup index')
    collections = index.get('collections')
    if not isinstance(collections, list) or len(collections) > 1000:
        raise ValueError('Invalid collection index')
    ids = [c.get('id', '') for c in collections]
    if any(not ID.fullmatch(value) for value in ids) or len(ids) != len(set(ids)):
        raise ValueError('Invalid or duplicate collection ID')


def verify_user_bundle(directory):
    actual = inventory(directory)
    if 'manifest.json' not in actual:
        raise ValueError('User backup manifest missing')
    manifest = json.loads((directory / 'manifest.json').read_text())
    actual.pop('manifest.json')
    if (manifest.get('kind') != 'user' or manifest.get('backup_version') != 1
            or manifest.get('files') != actual):
        raise ValueError('User backup integrity check failed')
    index = json.loads((directory / 'index.json').read_text())
    check_index(index)
    expected = {'index.json', 'collections'} | {'collections/' + c['id'] + '.json' for c in index['collections']}
    if set(actual) != expected:
        raise ValueError('User backup is missing collections or contains unexpected files')
    if manifest.get('owner_id') != index['user']['id'] or manifest.get('deployment_id') != index['deployment_id']:
        raise ValueError('User backup ownership mismatch')
    for collection in index['collections']:
        validate_collection(json.loads((directory / 'collections' / (collection['id'] + '.json')).read_text()), index, collection['id'])
    return manifest


def validate_collection(saved, index, collection_id):
    if saved.get('backup_version') != 1 or saved.get('collection_id') != collection_id or 'snapshot' not in saved:
        raise ValueError('Invalid collection backup')
    if saved['snapshot'] is None:
        return
    if saved.get('deployment_id') != index['deployment_id'] or saved.get('owner_id') != index['user']['id']:
        raise ValueError('Collection backup ownership mismatch')
    if (type(saved['snapshot'].get('revision')) is not int or saved['snapshot']['revision'] < 1
            or not isinstance(saved['snapshot'].get('encrypted'), str)):
        raise ValueError('Invalid encrypted snapshot')
    for package in saved.get('packages', []):
        if package.get('recipient_user_id') != index['user']['id']:
            raise ValueError('Backup contains another recipient grant')


def write_json(path, value):
    with path.open('x') as stream:
        os.chmod(path, 0o600)
        json.dump(value, stream, indent=2)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())


def fetch(api, output):
    if output.exists() or output.is_symlink():
        raise ValueError('Output exists; choose a new directory')
    index = api.get('/v1/backup/index')
    check_index(index)
    with tempfile.TemporaryDirectory(prefix='.petika-user-backup-', dir=output.parent) as temporary:
        stage = Path(temporary)
        (stage / 'collections').mkdir(mode=0o700)
        write_json(stage / 'index.json', index)
        for collection in index['collections']:
            saved = api.get('/v1/backup/collections/' + collection['id'])
            validate_collection(saved, index, collection['id'])
            write_json(stage / 'collections' / (collection['id'] + '.json'), saved)
        latest = api.get('/v1/backup/index')
        check_index(latest)
        for field in ('deployment_id', 'user', 'identity', 'collections'):
            if index.get(field) != latest.get(field):
                raise ValueError('Account, identity, or membership changed during capture; retry into a new directory')
        write_json(stage / 'manifest.json', {'backup_version': 1, 'kind': 'user',
                   'owner_id': index['user']['id'], 'deployment_id': index['deployment_id'],
                   'created_utc': datetime.now(timezone.utc).isoformat(), 'files': inventory(stage)})
        verify_user_bundle(stage)
        private_copy(stage, output)
        verify_user_bundle(output)
    print('Verified current-user encrypted backup saved. No full-server account database is included.')


def recover(args):
    verify_user_bundle(args.recover_from)
    if not ID.fullmatch(args.collection or ''):
        raise ValueError('Choose an exact collection ID from index.json')
    saved = json.loads((args.recover_from / 'collections' / (args.collection + '.json')).read_text())
    if saved['snapshot'] is None:
        raise ValueError('This collection has no saved snapshot')
    if args.output.exists() or args.output.is_symlink():
        raise ValueError('Output exists; choose a new file')
    with tempfile.TemporaryDirectory(prefix='.petika-user-recovery-', dir=args.output.parent) as temporary:
        candidate = Path(temporary) / 'recovered.petika'
        candidate.write_text(saved['snapshot']['encrypted'])
        candidate.chmod(0o600)
        command = [str(args.cli), '--store', str(candidate)]
        if args.passphrase_stdin:
            command.append('--passphrase-stdin')
        result = subprocess.run(command + ['list'], stdout=subprocess.DEVNULL, check=False)
        if result.returncode:
            raise ValueError('Recovery passphrase authentication failed; no file was published')
        os.link(candidate, args.output)
    print('Authenticated collection recovered locally. Server unchanged.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--server')
    parser.add_argument('--api-key-file', type=Path)
    parser.add_argument('--recover-from', type=Path)
    parser.add_argument('--collection')
    parser.add_argument('--cli', type=Path, default=Path('target/debug/petika'))
    parser.add_argument('--passphrase-stdin', action='store_true')
    parser.add_argument('--ca-file', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.recover_from:
            recover(args)
        elif args.server and args.api_key_file:
            fetch(API(args.server, args.api_key_file, args.ca_file), args.output)
        else:
            raise ValueError("Supply --server and --api-key-file, or --recover-from and --collection")
    except (ValueError, OSError, KeyError, TypeError) as error:
        parser.exit(1, f'Error: {error}\n')


if __name__ == '__main__':
    main()
