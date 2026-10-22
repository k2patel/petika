#!/usr/bin/env python3
"""Disposable real-server entry migration, rotation and full recovery drill."""
import hashlib
import json
from pathlib import Path
import secrets
import shutil
import tempfile
import time

import backup_recovery as backup
import user_backup
from test_backup_recovery import Server, cli as native_cli, run, tool, ROOT, PASSWORD, PASSPHRASE, IDENTITY

AUDIT = ROOT / 'target/debug/petika-entry-recovery'


def cli(client, args, lines, store=None, identity=False, ok=True):
    return native_cli(client, ["--no-config", *args], lines, store, identity, ok)


def write(path, data):
    path.write_bytes(data)
    path.chmod(0o600)


def state_args(client, collection, anchor, cache='cache', recovery=None):
    args = ['--collection', collection, '--anchor', anchor, '--pin', client / 'pin.json',
            '--cache', client / cache]
    if recovery:
        args += ['--recovery', recovery]
    else:
        args += ['--recipient-identity', client / 'identity.json']
    return args


def capture(home, output):
    tool('create', '--offline', '--data', home / 'data', '--mirror', home / 'mirror',
         '--config', home / 'config', '--release', 'entry-drill-release', '--output', output)


def drill(mode):
    with tempfile.TemporaryDirectory(prefix='petika-entry-recovery-') as temporary:
        root = Path(temporary)
        original = root / 'original'
        (original / 'config').mkdir(parents=True)
        (original / 'mirror').mkdir()
        write(original / 'config/token', secrets.token_hex(32).encode())
        write(original / 'config/password', PASSWORD.encode())
        client = root / 'client'
        overrides = {'PETIKA_EXPERIMENTAL_ENTRIES': '1'}
        server = Server(original, provision=True, overrides=overrides)
        try:
            user = server.login(client)
            cli(client, ['keys', 'enroll'], [IDENTITY, IDENTITY, PASSWORD], identity=True)
            store = client / 'source.petika'
            cli(client, ['init', '--encryption', mode], [PASSPHRASE, PASSPHRASE], store)
            cli(client, ['put', 'literal/recovery-test', '--password-stdin'], [PASSPHRASE, 'synthetic recovery secret'], store)
            cli(client, ['push', '--collection', 'personal', '--revision', '0'], [PASSPHRASE], store)
        finally:
            server.stop()
        # Independent older backup is deliberately retained to test rollback refusal.
        capture(original, root / 'before-migration')
        server = Server(original, overrides=overrides)
        try:
            session = root / 'migration-session'
            server.login(session)
            write(client / 'session.json', (session / 'session.json').read_bytes())
            draft = client / 'migration.json'
            common = ['--authority-identity', client / 'identity.json', '--draft', draft]
            cli(client, ['entries', 'migrate-stage', *common, '--recovery-policy', 'replace'],
                [PASSPHRASE, IDENTITY, PASSPHRASE, PASSPHRASE])
            cli(client, ['entries', 'migrate-submit', *common, '--pin', client / 'pin.json',
                         '--cache', client / 'cache', '--confirm'], [PASSPHRASE, IDENTITY, PASSPHRASE])
            head = json.loads((client / 'pin.json').read_text())['head']
            # cache_object uses the receipt's authenticated head digest.
            digest = json.loads(draft.with_suffix('.accepted.json').read_text())['accepted']['digest']
            anchor = client / 'cache' / (digest + '.json')
            args = state_args(client, user['id'], anchor)
            # Capture a real earlier entry backup before a same-epoch write and rotation.
            server.stop()
            baseline_report = root / 'before-new-writes-report.json'
            write(baseline_report, run([AUDIT, original / 'data']).encode())
            capture(original, root / 'before-new-writes')
            server = Server(original, overrides=overrides)
            later_session = root / 'later-session'
            server.login(later_session)
            write(client / 'session.json', (later_session / 'session.json').read_bytes())
            edit = client / 'post-backup-edit.json'
            cli(client, ['entries', 'put', *args, '--name', 'post-backup-entry',
                         '--password-stdin', '--draft', edit], [IDENTITY, 'synthetic later password'])
            cli(client, ['entries', 'submit', *args, '--draft', edit, '--confirm'], [IDENTITY])
            rotation = client / 'rotation.json'
            rotation_args = [*args, '--authority-identity', client / 'identity.json', '--draft', rotation]
            cli(client, ['entries', 'rotate', *rotation_args, '--recovery-policy', 'replace'],
                [IDENTITY, IDENTITY, PASSPHRASE, PASSPHRASE])
            cli(client, ['entries', 'rotate-submit', *rotation_args, '--confirm'], [IDENTITY, IDENTITY])
            pin = (client / 'pin.json').read_bytes()
            current = json.loads(pin)
            assert current['head']['context']['key_epoch'] == head['context']['key_epoch'] + 1
            cli(client, ['entries', 'verify-backup', *args], [IDENTITY])
            # Current recovery filename is the wrapper ID in the stored envelope.
            recovery_files = []
            for file in (client / 'cache').glob('recovery-*.json'):
                value = json.loads(file.read_text())
                if value['context'] == current['head']['context']:
                    recovery_files.append(file)
            assert len(recovery_files) == 1
            recovery = recovery_files[0]
            cli(client, ['entries', 'verify-backup', *state_args(client, user['id'], anchor, recovery=recovery)], [PASSPHRASE])
            # Do not claim a full backup while a server is still running.
            run([AUDIT, original / 'data'], ok=False)
            run([AUDIT, original / 'data', '--compare', baseline_report], ok=False)
            for _ in range(200):
                status = server.api(f'/v1/collections/{user["id"]}/status')
                if status['replication'].get('local', {}).get('revision') == current['head']['revision']:
                    break
                time.sleep(.1)
            else:
                raise AssertionError('Entry mirror did not catch up')
            repo = original / 'mirror' / user['id'] / 'entries/repository.git'
            epoch = json.loads(backup.git(repo, 'show', 'HEAD:epoch.json'))
            assert epoch['checkpoint'] == current['checkpoint']
            for item in json.loads(rotation.read_text())['transaction']['entries']:
                assert backup.git(repo, 'show', 'HEAD:entries/' + item['id'] + '.json') == item['envelope'].encode()

            # Recover directly from Git and from a scoped API export with no old cache.
            commit = backup.git(repo, 'rev-parse', 'HEAD').decode().strip()
            git_base = ['entries', 'recover-git', '--repository', repo, '--commit', commit,
                        '--pin', client / 'pin.json']
            recovered = root / 'git-recovered'
            cli(client, [*git_base, '--recipient-identity', client / 'identity.json',
                         '--output', recovered], [IDENTITY])
            recovered_anchor = recovered / json.loads((recovered / 'RECOVERY.json').read_text())['anchor']
            cli(client, ['entries', 'verify-backup', '--anchor', recovered_anchor,
                         '--pin', client / 'pin.json', '--cache', recovered,
                         '--handoff', recovered / 'handoff.json',
                         '--recipient-identity', client / 'identity.json'], [IDENTITY])
            cli(client, [*git_base, '--recipient-identity', client / 'identity.json',
                         '--output', recovered], [], ok=False)
            recovery_id = json.loads(recovery.read_text())['wrapper_id']
            cli(client, [*git_base, '--recovery-wrapper-id', recovery_id,
                         '--output', root / 'git-recovery-key'], [PASSPHRASE])
            key_cache = root / 'git-recovery-key'
            key_anchor = key_cache / json.loads((key_cache / 'RECOVERY.json').read_text())['anchor']
            cli(client, ['entries', 'verify-backup', '--anchor', key_anchor,
                         '--pin', client / 'pin.json', '--cache', key_cache,
                         '--recovery', key_cache / ('recovery-' + recovery_id + '.json')], [PASSPHRASE])
            for label, extra, passwords in [
                    ('wrong-key', [], ['wrong identity']),
                    ('symbolic', ['--commit', 'HEAD'], []),
                    ('older', ['--commit', backup.git(repo, 'rev-parse', 'HEAD^').decode().strip()], [])]:
                rejected = root / label
                # Replace commit rather than supply a duplicate clap option.
                command = git_base.copy()
                if extra:
                    command[command.index('--commit') + 1] = extra[1]
                cli(client, [*command, '--recipient-identity', client / 'identity.json',
                             '--output', rejected], passwords, ok=False)
                assert not rejected.exists()
            key = server.api('/v1/backup-settings/keys',
                             {'name': 'recovery drill', 'expires_in_days': 1, 'current_password': PASSWORD})
            keyfile = root / 'backup-key'
            write(keyfile, key['token'].encode())
            bundle = root / 'user-backup'
            user_backup.fetch(user_backup.API(server.origin, keyfile), bundle)
            saved_path = bundle / 'collections' / (user['id'] + '.json')
            saved = json.loads(saved_path.read_text())
            assert saved['backup_version'] == 2
            user_output = root / 'user-recovered'
            run(['python3', ROOT / 'scripts/user_backup.py', '--recover-from', bundle,
                 '--collection', user['id'], '--pin', client / 'pin.json',
                 '--recipient-identity', client / 'identity.json', '--output', user_output,
                 '--passphrase-stdin'], [IDENTITY])
            user_anchor = user_output / json.loads((user_output / 'RECOVERY.json').read_text())['anchor']
            cli(client, ['entries', 'verify-backup', '--anchor', user_anchor,
                         '--pin', client / 'pin.json', '--cache', user_output,
                         '--handoff', user_output / 'handoff.json',
                         '--recipient-identity', client / 'identity.json'], [IDENTITY])
            for label in ['missing', 'tampered', 'owner']:
                altered = json.loads(saved_path.read_text())
                if label == 'missing':
                    altered['entries'].clear()
                elif label == 'tampered':
                    entry_id = next(iter(altered['entries']))
                    altered['entries'][entry_id] = '{}'
                else:
                    altered['owner_id'] = '0' * 64
                bad = root / (label + '.json')
                write(bad, json.dumps(altered).encode())
                output = root / (label + '-output')
                cli(client, ['entries', 'recover-backup', '--backup', bad,
                             '--pin', client / 'pin.json', '--recipient-identity', client / 'identity.json',
                             '--output', output], [IDENTITY], ok=False)
                assert not output.exists()
            assert (client / 'pin.json').read_bytes() == pin

            assert backup.git(repo, 'show', 'HEAD:index.json') == json.loads((client / 'cache' / (status['accepted']['digest'] + '.json')).read_text())['envelope'].encode()
        finally:
            server.stop()
        report = root / 'retained-entry-report.json'
        write(report, run([AUDIT, original / 'data']).encode())
        before_compare = backup.inventory(original / 'data')
        exact = json.loads(run([AUDIT, original / 'data', '--compare', report]))
        assert exact['exact_match'] and not exact['requires_reconciliation']
        newer = json.loads(run([AUDIT, original / 'data', '--compare', baseline_report], ok=False))
        assert newer['collections'][0]['status'] == 'retained-head-in-local-history'
        conflicting = json.loads(baseline_report.read_text())
        conflicting['collections'][0]['accepted']['digest'] = '0' * 64
        conflict_report = root / 'conflict-report.json'
        write(conflict_report, json.dumps(conflicting).encode())
        conflict = json.loads(run([AUDIT, original / 'data', '--compare', conflict_report], ok=False))
        assert conflict['collections'][0]['status'] == 'conflicting-history'
        assert backup.inventory(original / 'data') == before_compare
        old_entry_server = root / 'old-entry-server'
        tool('restore', root / 'before-new-writes', '--release', 'entry-drill-release', '--output', old_entry_server)
        older = json.loads(run([AUDIT, old_entry_server / 'data', '--compare', report], ok=False))
        assert older['collections'][0]['status'] == 'newer-retained-head'
        assert older['requires_reconciliation'] and not older['exact_match']
        capture(original, root / 'full')
        backup.private_copy(client, root / 'client-kit')
        # Old client caches/identity are gone; only separately retained kit survives.
        shutil.rmtree(client)
        shutil.rmtree(original)
        restored = root / 'restored'
        tool('restore', root / 'full', '--release', 'entry-drill-release', '--output', restored)
        run([AUDIT, restored / 'data', '--expect', report])
        backup.private_copy(root / 'client-kit', client)
        args = state_args(client, user['id'], anchor)
        cli(client, ['entries', 'verify-backup', *args], [IDENTITY])
        cli(client, ['entries', 'verify-backup', *args], ['wrong identity'], ok=False)
        assert (client / 'pin.json').read_bytes() == pin
        # A missing current ciphertext cannot be hidden by a valid index/wrapper.
        receipt = json.loads((client / 'rotation.accepted.json').read_text())
        rotated = json.loads((client / 'rotation.json').read_text())['transaction']['entries'][0]['envelope'].encode()
        entry_file = client / 'cache' / ('entry-' + hashlib.sha256(rotated).hexdigest() + '.json')
        entry_bytes = entry_file.read_bytes()
        entry_file.unlink()
        cli(client, ['entries', 'verify-backup', *args], [IDENTITY], ok=False)
        write(entry_file, entry_bytes)
        # Offline audit detects missing roots against independent capture evidence.
        journal = restored / 'data/collections' / user['id'] / 'entries'
        pointer = journal / 'committed-root'
        pointer_bytes = pointer.read_bytes()
        pointer.unlink()
        missing = json.loads(run([AUDIT, restored / 'data', '--compare', report], ok=False))
        assert missing['collections'][0]['status'] == 'missing-collection'
        run([AUDIT, restored / 'data', '--expect', report], ok=False)
        write(pointer, pointer_bytes)
        record = journal / (json.loads(pointer_bytes)['record'] + '.json')
        record_bytes = record.read_bytes()
        write(record, b'{}')
        run([AUDIT, restored / 'data', '--expect', report], ok=False)
        write(record, record_bytes)
        run([AUDIT, restored / 'data', '--expect', report])
        source_file = restored / 'data/collections' / user['id'] / 'snapshot.json'
        source_bytes = source_file.read_bytes()
        altered = json.loads(source_bytes)
        altered['revision'] += 1
        write(source_file, json.dumps(altered).encode())
        run([AUDIT, restored / 'data', '--expect', report], ok=False)
        write(source_file, source_bytes)
        accounts_file = restored / 'data/accounts.json'
        accounts_bytes = accounts_file.read_bytes()
        altered = json.loads(accounts_bytes)
        altered['deployment_id'] = '0' * 64
        write(accounts_file, json.dumps(altered).encode())
        run([AUDIT, restored / 'data', '--expect', report], ok=False)
        write(accounts_file, accounts_bytes)
        run([AUDIT, restored / 'data', '--expect', report])
        server = Server(restored, overrides=overrides)
        try:
            restored_session = root / 'restored-session'
            recovered_user = server.login(restored_session)
            assert recovered_user['id'] == user['id']
            write(client / 'session.json', (restored_session / 'session.json').read_bytes())
            cli(client, ['entries', 'sync', *args], [IDENTITY])
            assert 'literal/recovery-test' in cli(client, ['entries', 'list', *args], [IDENTITY])
            lookup = server.api(f'/v1/collections/{user["id"]}/entry-receipt',
                                {'context': current['head']['context'], 'operation': receipt['operation']})
            assert lookup['receipt'] == receipt
            server.api(f'/v1/collections/{user["id"]}/snapshot', expected=426)
        finally:
            server.stop()
        older = root / 'older'
        tool('restore', root / 'before-migration', '--release', 'entry-drill-release', '--output', older)
        run([AUDIT, older / 'data', '--expect', report], ok=False)
        server = Server(older, overrides=overrides)
        try:
            older_session = root / 'older-session'
            server.login(older_session)
            write(client / 'session.json', (older_session / 'session.json').read_bytes())
            cli(client, ['entries', 'sync', *args], [IDENTITY], ok=False)
            assert (client / 'pin.json').read_bytes() == pin
        finally:
            server.stop()
    print(f'Entry recovery drill passed: {mode}, migration, rotation, full restore, Git/user exports, identity/recovery unlock, retained client kit, receipts, corruption and rollback refusal.')


if __name__ == '__main__':
    for mode in ['standard', 'hybrid-post-quantum']:
        drill(mode)
