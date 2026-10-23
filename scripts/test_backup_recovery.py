#!/usr/bin/env python3
"""Backup safety tests and clean-directory recovery drill using real native binaries."""
import argparse
import http.cookiejar
import hashlib
from unittest import mock
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from urllib.error import HTTPError
from urllib.request import build_opener, HTTPCookieProcessor, Request

import backup_recovery as backup

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / 'scripts/backup_recovery.py'
CLI = ROOT / 'target/debug/petika'
SERVER = ROOT / 'target/debug/petika-server'
PASSWORD = 'synthetic account password'
PASSPHRASE = 'synthetic recovery passphrase'
IDENTITY = 'synthetic identity passphrase'


def run(command, lines=None, ok=True):
    result = subprocess.run([str(x) for x in command],
                            input=None if lines is None else '\n'.join(lines) + '\n',
                            text=True, capture_output=True, timeout=90)
    if ok and result.returncode:
        raise AssertionError(result.stderr)
    if not ok and not result.returncode:
        raise AssertionError('Command unexpectedly succeeded')
    return result.stdout


def tool(*args, lines=None, ok=True):
    return run([sys.executable, TOOL, *args], lines, ok)


class BackupSafety(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for name in backup.ROOTS:
            (self.root / name).mkdir()
            (self.root / name / 'empty').mkdir()
            (self.root / name / 'file').write_bytes(b'synthetic backup data')
        self.args = argparse.Namespace(**{n: self.root / n for n in backup.ROOTS},
                                       output=self.root / 'backup', release='test-release', offline=True)

    def test_full_backup_restore_and_no_clobber(self):
        backup.create(self.args)
        restore = argparse.Namespace(backup=self.args.output, output=self.root / 'restored', release='test-release')
        backup.restore(restore)
        for name in backup.ROOTS:
            self.assertEqual(backup.inventory(self.root / name), backup.inventory(restore.output / name))
        with self.assertRaises(FileExistsError):
            backup.restore(restore)
        with self.assertRaises(FileExistsError):
            backup.create(self.args)
        if os.name != 'nt':
            self.assertEqual((restore.output / 'data/file').stat().st_mode & 0o777, 0o600)
            self.assertEqual(restore.output.stat().st_mode & 0o777, 0o700)
        restore.output = self.root / 'wrong-release'
        restore.release = 'wrong'
        with self.assertRaises(ValueError):
            backup.restore(restore)
        self.assertFalse(restore.output.exists())

    def test_reconcile_guards_and_failed_publication_has_no_completion_marker(self):
        backup.create(self.args)
        baseline, expected = self.root / 'baseline.json', self.root / 'expected.json'
        baseline.write_text('{}')
        expected.write_text('{}')
        args = argparse.Namespace(backup=self.args.output, output=self.root / 'reconciled',
                                  baseline_report=baseline, expected_report=expected, release='test-release',
                                  recovery_tool=Path('unused-tool'), expected_manifest_sha256='0' * 64)
        with mock.patch.object(backup.subprocess, 'run') as native:
            with self.assertRaises(ValueError):
                backup.reconcile(args)
            native.assert_not_called()
        self.assertFalse(args.output.exists())
        args.expected_manifest_sha256 = hashlib.sha256((args.backup / 'manifest.json').read_bytes()).hexdigest()
        before = backup.inventory(args.backup)
        # Isolate publication failure from cryptographic validation, covered by the real drill.
        exact = {'version': 1, 'exact_match': True, 'collections': [{'status': 'matches'}]}
        newer = {'version': 1, 'exact_match': False, 'collections': [{'status': 'retained-head-in-local-history'}]}
        responses = [subprocess.CompletedProcess([], code, json.dumps(value).encode())
                     for code, value in [(0, exact), (2, newer)]]
        copy = backup.private_copy
        def fail_publication(source, destination):
            if destination == args.output:
                destination.mkdir()
                (destination / 'partial').write_bytes(b'partial ciphertext')
                raise OSError('injected storage failure')
            copy(source, destination)
        with mock.patch.object(backup.subprocess, 'run', side_effect=responses), \
                mock.patch.object(backup, 'private_copy', side_effect=fail_publication):
            with self.assertRaises(OSError):
                backup.reconcile(args)
        self.assertFalse((args.output / 'RECONCILIATION.json').exists())
        self.assertFalse((args.output / 'RESTORE.json').exists())
        self.assertEqual(backup.inventory(args.backup), before)
        with self.assertRaises(ValueError):
            backup.reconcile(args)
        args.output = self.root / 'failed-marker'
        def fail_marker(path, value):
            path.write_text(json.dumps(value))
            raise OSError('injected marker fsync failure')
        with mock.patch.object(backup.subprocess, 'run', side_effect=responses), \
                mock.patch.object(backup, 'durable_json', side_effect=fail_marker):
            with self.assertRaises(OSError):
                backup.reconcile(args)
        self.assertFalse((args.output / 'RECONCILIATION.json').exists())
        self.assertFalse((args.output / 'RESTORE.json').exists())
        self.assertEqual(backup.inventory(args.backup), before)
        args.output = self.root / 'completed-reconciliation'
        with mock.patch.object(backup.subprocess, 'run', side_effect=responses):
            backup.reconcile(args)
        marker = json.loads((args.output / 'RECONCILIATION.json').read_text())
        self.assertEqual(marker['manifest_sha256'], args.expected_manifest_sha256)
        self.assertFalse((args.output / 'RESTORE.json').exists())
        self.assertEqual(backup.inventory(args.backup), before)

    def test_missing_changed_extra_files_and_manifest(self):
        backup.create(self.args)
        path = self.args.output / 'data/file'
        original = path.read_bytes()
        path.unlink()
        with self.assertRaises(ValueError):
            backup.verify(self.args.output)
        path.write_bytes(b'corrupt')
        with self.assertRaises(ValueError):
            backup.verify(self.args.output)
        path.write_bytes(original)
        extra = self.args.output / 'data/extra'
        extra.write_text('extra')
        with self.assertRaises(ValueError):
            backup.verify(self.args.output)
        extra.unlink()
        (self.args.output / 'manifest.json').unlink()
        with self.assertRaises(ValueError):
            backup.verify(self.args.output)

    def test_offline_overlap_and_symlink_rejected(self):
        self.args.offline = False
        with self.assertRaises(ValueError):
            backup.create(self.args)
        self.args.offline = True
        self.args.output = self.root / 'data/nested'
        with self.assertRaises(ValueError):
            backup.create(self.args)
        self.args.output = self.root / 'backup'
        (self.root / 'data/link').symlink_to(self.root / 'config/file')
        with self.assertRaises(ValueError):
            backup.create(self.args)
        self.assertFalse(self.args.output.exists())


    def test_git_revision_gap_and_invalid_commit(self):
        repo = self.root / 'history.git'
        run(['git', 'init', '--bare', repo])
        def commit(revision, parent=None):
            file = self.root / 'snapshot.json'
            file.write_text(json.dumps({'schema_version': 1, 'revision': revision, 'encrypted': '{}'}))
            blob = backup.git(repo, 'hash-object', '-w', str(file)).decode().strip()
            tree = run(['git', '-C', repo, 'mktree'], [f'100644 blob {blob}\tsnapshot.json']).strip()
            command = ['git', '-C', repo, '-c', 'user.name=Test', '-c', 'user.email=test@localhost',
                       'commit-tree', tree, '-m', 'Synthetic revision']
            if parent:
                command += ['-p', parent]
            return run(command).strip()
        first = commit(1)
        self.assertEqual(backup.complete_history(repo, first), [(first, 1)])
        for tip in [commit(2), commit(3, first)]:
            with self.assertRaises(ValueError):
                backup.complete_history(repo, tip)
        for invalid in ['HEAD', '--help', 'a' * 40]:
            with self.assertRaises(ValueError):
                backup.snapshot(repo, invalid)


class Server:
    def __init__(self, home, provision=False, overrides=None, mirror=True, port=None):
        self.home = home
        with socket.socket() as sock:
            if port is not None:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(('127.0.0.1', 0 if port is None else port))
            port = sock.getsockname()[1]
        self.origin = f'http://127.0.0.1:{port}'
        self.opener = build_opener(HTTPCookieProcessor(http.cookiejar.CookieJar()))
        env = {k: v for k, v in os.environ.items() if not k.startswith('PETIKA_')}
        env.update(PETIKA_DATA_DIR=str(home / 'data'),
                   PETIKA_TOKEN_FILE=str(home / 'config/token'), PETIKA_LISTEN=f'127.0.0.1:{port}',
                   PETIKA_COOKIE_SECURE='false', PETIKA_SETUP_MODE='auto' if provision else 'disabled',
                   PETIKA_WEB_DIR=str(ROOT / 'clients/web'))
        if mirror:
            env['PETIKA_GIT_MIRROR'] = str(home / 'mirror')
        if provision:
            env.update(PETIKA_ADMIN_USERNAME='alice', PETIKA_ADMIN_PASSWORD_FILE=str(home / 'config/password'))
        env.update(overrides or {})
        self.process = subprocess.Popen([str(SERVER)], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            for _ in range(100):
                if self.process.poll() is not None:
                    raise AssertionError('Disposable server failed to start')
                try:
                    self.api('/healthz')
                    break
                except OSError:
                    time.sleep(.1)
            else:
                raise AssertionError('Disposable server never became ready')
        except BaseException:
            self.stop()
            raise

    def api(self, path, body=None, method=None, headers=None, expected=200, raw=False):
        request = Request(self.origin + path,
                          data=(body if isinstance(body, bytes) else json.dumps(body).encode()) if body is not None else None,
                          headers={'Content-Type': 'application/json', 'X-Petika-Request': '1', **(headers or {})},
                          method=method)
        try:
            response = self.opener.open(request, timeout=30)
        except HTTPError as error:
            response = error
        with response:
            assert response.status == expected, (path, response.status, expected, response.read())
            data = response.read()
            return data if raw else json.loads(data)

    def login(self, client, username='alice'):
        user = self.api('/v1/auth/login', {'username': username, 'password': PASSWORD})
        grant = self.api('/v1/auth/device/start', {})
        self.api('/v1/auth/device/approve', {'user_code': grant['user_code'], 'password': PASSWORD, 'approve': True})
        token = self.api('/v1/auth/device/poll', {'device_code': grant['device_code']})['token']
        client.mkdir(mode=0o700)
        session = client / 'session.json'
        session.write_text(json.dumps({'version': 1, 'server': self.origin, 'token': token}))
        session.chmod(0o600)
        return user

    def stop(self):
        self.process.terminate()
        self.process.wait(timeout=15)


def cli(client, args, lines, store=None, identity=False, ok=True):
    command = [CLI, '--session-file', client / 'session.json', '--passphrase-stdin']
    if identity:
        command += ['--identity-file', client / 'identity.json']
    if store:
        command += ['--store', store]
    return run(command + args, lines, ok)


def drill():
    with tempfile.TemporaryDirectory(prefix='petika-recovery-drill-') as temporary:
        root = Path(temporary)
        original = root / 'original'
        original.mkdir()
        (original / 'config').mkdir()
        (original / 'config/token').write_text(secrets.token_hex(32))
        (original / 'config/password').write_text(PASSWORD)
        client = root / 'original-client'
        server = Server(original, provision=True)
        try:
            user = server.login(client)
            cli(client, ['keys', 'enroll'], [IDENTITY, IDENTITY, PASSWORD], identity=True)
            fingerprint = server.api('/v1/keys/identity')['public_identity']['fingerprint']
            groups = []
            for mode in ['standard', 'hybrid-post-quantum']:
                group = server.api('/v1/admin/groups', {'name': mode, 'members': [{'user_id': user['id'], 'edit': True}]})
                store = client / (mode + '.petika')
                cli(client, ['init', '--encryption', mode], [PASSPHRASE, PASSPHRASE], store)
                cli(client, ['put', 'recovery-test', '--password-stdin'], [PASSPHRASE, 'synthetic secret'], store)
                cli(client, ['push', '--collection', group['id'], '--revision', '0'], [PASSPHRASE], store)
                cli(client, ['keys', 'migrate', '--collection', group['id']],
                    [IDENTITY, PASSPHRASE, PASSPHRASE, PASSPHRASE], identity=True)
                cli(client, ['keys', 'rotate', '--collection', group['id']],
                    [IDENTITY, PASSPHRASE, PASSPHRASE], identity=True)
                groups.append(group)
            # Separate legacy history exercises safe historical publication with CAS.
            encrypted = store.read_bytes()
            auth = {'Authorization': 'Bearer ' + (original / 'config/token').read_text()}
            for revision in [0, 1]:
                server.api('/v1/snapshot', encrypted, 'PUT', {**auth, 'If-Match': f'"{revision}"'})
            for _ in range(100):
                try:
                    for group in groups:
                        repo = original / 'mirror' / group['id'] / 'repository.git'
                        assert backup.snapshot(repo, backup.git(repo, 'rev-parse', 'HEAD').decode().strip())['revision'] == 3
                    assert server.api('/v1/status', headers=auth)['mirror_revision'] == 2
                    break
                except (AssertionError, ValueError, OSError):
                    time.sleep(.1)
            else:
                raise AssertionError('Mirror did not catch up')
        finally:
            server.stop()
        full = root / 'full-backup'
        tool('create', '--offline', '--data', original / 'data', '--mirror', original / 'mirror',
             '--config', original / 'config', '--release', 'drill-release', '--output', full)
        # Simulate off-host replication as independent bare clones with deployment branch names.
        for group in groups:
            remote = root / (group['name'] + '.git')
            run(['git', 'clone', '--bare', '--no-local', original / 'mirror' / group['id'] / 'repository.git', remote])
            head = backup.git(remote, 'rev-parse', 'HEAD').decode().strip()
            backup.git(remote, 'update-ref', 'refs/heads/collections/' + group['id'], head)
        # Remove original server and client entirely before starting recovery.
        shutil.rmtree(original)
        shutil.rmtree(client)
        restored = root / 'clean-host'
        tool('restore', full, '--release', 'drill-release', '--output', restored)
        fresh = root / 'fresh-client'
        server = Server(restored)
        try:
            restored_user = server.login(fresh)
            assert restored_user['id'] == user['id']
            cli(fresh, ['keys', 'restore', '--fingerprint', fingerprint], [IDENTITY], identity=True)
            for group in groups:
                local = fresh / (group['name'] + '.petika')
                cli(fresh, ['keys', 'pull', '--collection', group['id']], [IDENTITY], local, identity=True)
                assert 'synthetic secret' in cli(fresh, ['get', 'recovery-test', '--reveal'], [IDENTITY], local, identity=True)
                remote = root / (group['name'] + '.git')
                history = tool('history', remote, '--branch', 'collections/' + group['id']).splitlines()
                assert len(history) == 3
                for index, line in enumerate(history):
                    commit = line.split()[0]
                    recovered = root / f'recovered-{group["name"]}-{index}.petika'
                    for secret_input in [[], ['wrong passphrase']]:
                        tool('recover', remote, '--commit', commit, '--output', recovered,
                             '--cli', CLI, '--passphrase-stdin', lines=secret_input, ok=False)
                    assert not recovered.exists()
                    tool('recover', remote, '--commit', commit, '--output', recovered,
                         '--cli', CLI, '--passphrase-stdin', lines=[PASSPHRASE])
                    assert 'synthetic secret' in cli(fresh, ['get', 'recovery-test', '--reveal'], [PASSPHRASE], recovered)
                    tool('recover', remote, '--commit', commit, '--output', recovered,
                         '--cli', CLI, '--passphrase-stdin', lines=[PASSPHRASE], ok=False)
                # Incomplete history and broken ciphertext are rejected without publication.
                shallow = root / (group['name'] + '-shallow.git')
                run(['git', 'clone', '--bare', '--depth=1', remote.as_uri(), shallow])
                tool('recover', shallow, '--commit', history[0].split()[0], '--output', root / 'incomplete',
                     '--cli', CLI, '--passphrase-stdin', lines=[PASSPHRASE], ok=False)
                assert not (root / 'incomplete').exists()
            # Restore historical legacy data as a new revision; stale CAS cannot overwrite.
            repo = restored / 'mirror/repository.git'
            old = backup.git(repo, 'rev-parse', 'HEAD~1').decode().strip()
            recovered = root / 'legacy.petika'
            tool('recover', repo, '--commit', old, '--output', recovered, '--cli', CLI,
                 '--passphrase-stdin', lines=[PASSPHRASE])
            auth = {'Authorization': 'Bearer ' + (restored / 'config/token').read_text()}
            server.api('/v1/snapshot', recovered.read_bytes(), 'PUT', {**auth, 'If-Match': '"1"'}, expected=409)
            server.api('/v1/snapshot', recovered.read_bytes(), 'PUT', {**auth, 'If-Match': '"2"'})
            assert server.api('/v1/status', headers=auth)['revision'] == 3
            # Mutating a Git blob into another valid Git commit must still fail crypto authentication.
            damaged = backup.snapshot(repo, old)
            envelope = json.loads(damaged['encrypted'])
            ciphertext = envelope['ciphertext']
            if isinstance(ciphertext, list):
                ciphertext[0] ^= 1
            else:
                envelope['ciphertext'] = ('A' if ciphertext[0] != 'A' else 'B') + ciphertext[1:]
            damaged['encrypted'] = json.dumps(envelope)
            candidate = root / 'damaged.json'
            candidate.write_text(json.dumps(damaged))
            blob = backup.git(repo, 'hash-object', '-w', str(candidate)).decode().strip()
            tree = run(['git', '-C', repo, 'mktree'], [f'100644 blob {blob}\tsnapshot.json']).strip()
            bad = run(['git', '-C', repo, '-c', 'user.name=Test', '-c', 'user.email=test@localhost',
                       'commit-tree', tree, '-m', 'Synthetic damaged snapshot']).strip()
            tool('recover', repo, '--commit', bad, '--output', root / 'damaged.petika', '--cli', CLI,
                 '--passphrase-stdin', lines=[PASSPHRASE], ok=False)
            assert not (root / 'damaged.petika').exists()
        finally:
            server.stop()
        print('Clean-directory drill passed: both modes, v1/v2 history, rotation, account/grant/identity restore, wrong keys, incomplete mirrors, corruption, no-clobber, and revision conflicts.')


if __name__ == '__main__':
    if '--drill' in sys.argv:
        drill()
    else:
        unittest.main()
