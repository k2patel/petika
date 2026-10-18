#!/usr/bin/env python3
"""Encrypt verified Petika bundles into S3/SFTP restic repositories; verify by downloading."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
from urllib.parse import urlsplit

from backup_recovery import verify as verify_server, private_copy, separate
from user_backup import private_file, verify_user_bundle, write_json

TAG = 'petika-backup-v1'


def verify_bundle(path):
    # Validate the whole file tree before following manifest paths.
    from backup_recovery import inventory
    inventory(path)
    manifest = json.loads((path / 'manifest.json').read_text())
    if manifest.get('kind') == 'user':
        return verify_user_bundle(path)
    return verify_server(path)


def transport(repository, allow_local=False):
    if repository.startswith('s3:'):
        url = urlsplit(repository[3:])
        if (url.scheme != 'https' or not url.hostname or url.username or url.password
                or url.query or url.fragment or not url.path.strip('/')):
            raise ValueError('S3 requires an HTTPS endpoint/bucket URL without embedded credentials')
        return 's3'
    if repository.startswith('sftp://'):
        url = urlsplit(repository)
        if (not url.hostname or url.hostname.startswith('-') or not re.fullmatch(r'[A-Za-z0-9._:-]+', url.hostname)
                or not url.username or url.password or url.query or url.fragment
                or not url.path.startswith('//') or len(url.path) < 3
                or not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.-]*', url.username)):
            raise ValueError('Use sftp://user@host//absolute/repository/path with SSH key authentication')
        return 'sftp'
    if allow_local and Path(repository).is_absolute():
        return 'local-test'
    raise ValueError('Choose S3 or SFTP; a local test repository requires --allow-local-repository')


class Restic:
    def __init__(self, executable, repository, password_file, repository_id=None, allow_local=False):
        private_file(password_file)
        self.repository = repository
        self.transport = transport(repository, allow_local)
        self.command = [str(executable), '--no-cache', '--retry-lock', '30s']
        if self.transport == 'sftp':
            self.command += ['-o', 'sftp.args=-oBatchMode=yes -oStrictHostKeyChecking=yes']
        self.environment = dict(os.environ)
        for name in ('RESTIC_PASSWORD', 'RESTIC_PASSWORD_COMMAND', 'RESTIC_REPOSITORY_FILE'):
            self.environment.pop(name, None)
        self.environment.update(RESTIC_REPOSITORY=repository, RESTIC_PASSWORD_FILE=str(password_file.resolve()))
        self.repository_id = repository_id

    def run(self, *arguments):
        result = subprocess.run(self.command + list(arguments), env=self.environment,
                                capture_output=True, text=True, timeout=3600, stdin=subprocess.DEVNULL)
        if result.returncode:
            # Provider diagnostics can contain URLs/credentials. Never echo them to logs.
            reason = {10: 'repository does not exist', 11: 'repository is locked', 12: 'wrong repository password'}.get(result.returncode, 'operation failed')
            raise ValueError(f'Restic {arguments[0]}: {reason} (exit {result.returncode}); no verification receipt was issued')
        return result.stdout

    def identity(self, required=True):
        value = json.loads(self.run('cat', 'config'))['id']
        if not re.fullmatch(r'[0-9a-f]{64}', value):
            raise ValueError('Invalid restic repository identity')
        if required and (not self.repository_id or value != self.repository_id):
            raise ValueError('Repository ID mismatch; use the independently retained repository ID')
        return value

    def snapshot(self, snapshot_id):
        if not re.fullmatch(r'[0-9a-f]{8,64}', snapshot_id):
            raise ValueError('Invalid snapshot ID')
        records = json.loads(self.run('--json', 'snapshots', snapshot_id))
        if len(records) != 1 or TAG not in records[0].get('tags', []):
            raise ValueError('Not a Petika backup snapshot')
        saved = records[0]
        if not re.fullmatch(r'[0-9a-f]{64}', saved['id']) or len(saved.get('paths', [])) != 1:
            raise ValueError('Invalid snapshot metadata')
        path = saved['paths'][0]
        if not path.startswith('/') or '..' in Path(path).parts:
            raise ValueError('Invalid backup root')
        return saved

    def download(self, snapshot, output):
        self.run('restore', snapshot['id'] + ':' + snapshot['paths'][0], '--target', str(output), '--verify', '--overwrite', 'never')
        return verify_bundle(output)


def receipt(path, value):
    if path.exists() or path.is_symlink():
        raise ValueError('Receipt exists; choose a new file')
    with tempfile.TemporaryDirectory(prefix='.petika-receipt-', dir=path.parent) as temporary:
        source = Path(temporary) / 'receipt.json'
        write_json(source, value)
        os.link(source, path)


def publish(client, backup, host, receipt_path, scratch=None):
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,99}', host):
        raise ValueError('Use a stable simple backup-host label')
    separate([backup, receipt_path])
    if receipt_path.exists() or receipt_path.is_symlink():
        raise ValueError('Receipt exists; choose a new file')
    if scratch:
        separate([backup, scratch])
    original = verify_bundle(backup)
    manifest_digest = hashlib.sha256((backup / 'manifest.json').read_bytes()).hexdigest()
    repository_id = client.identity()
    messages = client.run('backup', '--json', '--host', host, '--tag', TAG, '--', str(backup.resolve()))
    summaries = [m for line in messages.splitlines() if (m := json.loads(line)).get('message_type') == 'summary']
    if len(summaries) != 1 or not summaries[0].get('snapshot_id'):
        raise ValueError('No complete backup snapshot; no receipt was issued')
    saved = client.snapshot(summaries[0]['snapshot_id'])
    if saved.get('hostname') != host or saved['paths'] != [str(backup.resolve())]:
        raise ValueError('Uploaded snapshot does not match the requested bundle')
    # No cache: this downloads the repository copy, not locally retained source data.
    with tempfile.TemporaryDirectory(prefix='petika-remote-check-', dir=scratch) as temporary:
        recovered = Path(temporary) / 'bundle'
        restored = client.download(saved, recovered)
        if (restored != original or hashlib.sha256((recovered / 'manifest.json').read_bytes()).hexdigest() != manifest_digest
                or verify_bundle(backup) != original):
            raise ValueError('Source changed or remote copy differs; no receipt was issued')
    value = {'receipt_version': 1, 'repository_id': repository_id, 'snapshot_id': saved['id'],
             'manifest_sha256': manifest_digest, 'kind': original.get('kind', 'server'),
             'transport': client.transport, 'host': host, 'backup_created_utc': original['created_utc'],
             'verified_utc': datetime.now(timezone.utc).isoformat(), 'verification': 'download-and-manifest-check'}
    receipt(receipt_path, value)
    print(f'Uploaded and downloaded verified encrypted backup: {saved["id"]}')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--restic', default='restic')
    parser.add_argument('--profile-file', type=Path, help='Downloaded S3/SSH destination profile; never contains credentials')
    parser.add_argument('--password-file', type=Path, required=True)
    parser.add_argument('--repository-id', help='Full repository ID retained after init')
    parser.add_argument('--allow-local-repository', action='store_true', help='Synthetic tests only; not off-site protection')
    commands = parser.add_subparsers(dest='command', required=True)
    command = commands.add_parser('init')
    command.add_argument('--receipt', type=Path, required=True)
    command = commands.add_parser('publish')
    command.add_argument('backup', type=Path)
    command.add_argument('--host', required=True)
    command.add_argument('--receipt', type=Path, required=True)
    command.add_argument('--scratch-dir', type=Path)
    command = commands.add_parser('fetch')
    command.add_argument('--snapshot', required=True)
    command.add_argument('--output', type=Path, required=True)
    commands.add_parser('check', help='Read and authenticate all repository data')
    command = commands.add_parser('retention-plan', help='Preview 7 daily, 4 weekly, 12 monthly retention; never deletes')
    command.add_argument('--host', required=True)
    args = parser.parse_args()
    try:
        repository = os.environ.get('RESTIC_REPOSITORY', '')
        if args.profile_file:
            repository = json.loads(args.profile_file.read_text())['repository']
        if not repository:
            raise ValueError('Set RESTIC_REPOSITORY or use --profile-file')
        client = Restic(args.restic, repository, args.password_file, args.repository_id, args.allow_local_repository)
        if args.command == 'init':
            if args.receipt.exists() or args.receipt.is_symlink():
                raise ValueError('Receipt exists; choose a new file')
            client.run('init', '--repository-version', '2')
            receipt(args.receipt, {'repository_id': client.identity(required=False), 'transport': client.transport,
                                  'created_utc': datetime.now(timezone.utc).isoformat()})
            print('Encrypted repository initialized. Retain the password and repository ID independently.')
        elif args.command == 'publish':
            publish(client, args.backup, args.host, args.receipt, args.scratch_dir)
        else:
            client.identity()
            if args.command == 'check':
                client.run('check', '--read-data')
                print('All repository data authenticated successfully.')
            elif args.command == 'retention-plan':
                print(client.run('--json', 'forget', '--dry-run', '--tag', TAG, '--host', args.host,
                                 '--group-by', 'host,tags', '--keep-last', '2', '--keep-daily', '7',
                                 '--keep-weekly', '4', '--keep-monthly', '12'))
            elif args.command == 'fetch':
                if not re.fullmatch(r'[0-9a-f]{64}', args.snapshot):
                    raise ValueError('Use an exact full snapshot ID, not latest')
                if args.output.exists() or args.output.is_symlink():
                    raise ValueError('Output exists; choose a new directory')
                saved = client.snapshot(args.snapshot)
                with tempfile.TemporaryDirectory(prefix='.petika-fetch-', dir=args.output.parent) as temporary:
                    source = Path(temporary) / 'bundle'
                    client.download(saved, source)
                    private_copy(source, args.output)
                    verify_bundle(args.output)
                print('Repository backup downloaded and verified. Server state unchanged.')
    except (ValueError, OSError, KeyError, TypeError, subprocess.TimeoutExpired) as error:
        parser.exit(1, f'Error: {error}\n')


if __name__ == '__main__':
    main()
