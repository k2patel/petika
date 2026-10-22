#!/usr/bin/env python3
"""Real shared-vault recovery, retained identity copies and membership revocation.

Synthetic device directories reuse an enrolled identity; this does not test hardware
keys, biometrics, independently enrolled device keys or production key custody.
"""
import json
from pathlib import Path
import secrets
import shutil
import tempfile

from test_backup_recovery import Server, PASSWORD, PASSPHRASE, IDENTITY
from test_entry_recovery import cli, write, state_args
import user_backup


def save(path, value):
    write(path, json.dumps(value).encode())


def reader(server, root, name):
    key = server.api('/v1/backup-settings/keys',
                     {'name': name, 'expires_in_days': 1, 'current_password': PASSWORD})
    path = root / (name + '-key')
    write(path, key['token'].encode())
    return user_backup.API(server.origin, path)


def export(api, collection, path, owner):
    saved = api.get('/v1/backup/collections/' + collection)
    assert saved['backup_version'] == 2 and saved['owner_id'] == owner
    assert json.loads(saved['handoff']['package'])['recipient_user_id'] == owner
    assert set(saved['handoff']) == {'handoff_version', 'checkpoint', 'package', 'wrappers'}
    assert 'snapshot' not in saved and 'recovery' not in saved
    save(path, saved)
    return saved


def recover(device, saved, output, ok=True):
    before = (device / 'pin.json').read_bytes()
    result = cli(device, ['entries', 'recover-backup', '--backup', saved,
                         '--pin', device / 'pin.json', '--recipient-identity', device / 'identity.json',
                         '--output', output], [IDENTITY], ok=ok)
    assert (device / 'pin.json').read_bytes() == before
    if not ok:
        assert not output.exists()
        return
    for secret in ('shared/secret', 'synthetic shared password', 'JBSWY3DPEHPK3PXP'):
        assert secret not in result
    anchor = output / json.loads((output / 'RECOVERY.json').read_text())['anchor']
    cli(device, ['entries', 'verify-backup', '--anchor', anchor,
                 '--pin', device / 'pin.json', '--cache', output,
                 '--handoff', output / 'handoff.json', '--recipient-identity', device / 'identity.json'],
        [IDENTITY])


def retained_device(source, destination):
    destination.mkdir(mode=0o700)
    # No session, authority identity, recovery passphrase wrapper, or old cache.
    for name in ('identity.json', 'pin.json'):
        write(destination / name, (source / name).read_bytes())


def drill(mode):
    with tempfile.TemporaryDirectory(prefix='petika-shared-recovery-') as temporary:
        root = Path(temporary)
        home = root / 'server'
        (home / 'config').mkdir(parents=True)
        write(home / 'config/token', secrets.token_hex(32).encode())
        write(home / 'config/password', PASSWORD.encode())
        server = Server(home, provision=True, mirror=False,
                        overrides={'PETIKA_EXPERIMENTAL_ENTRIES': '1'})
        try:
            owner, recipient = root / 'owner', root / 'recipient'
            alice = server.login(owner)
            bob = server.api('/v1/admin/users', {'username': 'bob', 'name': 'Reader', 'password': PASSWORD})
            group = server.api('/v1/admin/groups', {'name': 'Shared recovery', 'members': [
                {'user_id': alice['id'], 'edit': True}, {'user_id': bob['id'], 'edit': False}]})
            collection = group['id']
            cli(owner, ['keys', 'enroll'], [IDENTITY, IDENTITY, PASSWORD], identity=True)
            owner_api = reader(server, root, 'owner-backup')
            server.login(recipient, 'bob')
            cli(recipient, ['keys', 'enroll'], [IDENTITY, IDENTITY, PASSWORD], identity=True)
            recipient_api = reader(server, root, 'recipient-backup')
            for local, other in [(owner, recipient), (recipient, owner)]:
                public = json.loads((other / 'identity.json').read_text())['public_identity']
                cli(local, ['keys', 'verify', '--user', public['user_id'],
                            '--fingerprint', public['fingerprint']], [IDENTITY], identity=True)
            store = owner / 'source.petika'
            cli(owner, ['init', '--encryption', mode], [PASSPHRASE, PASSPHRASE], store)
            cli(owner, ['put', 'shared/secret', '--password-stdin'],
                [PASSPHRASE, 'synthetic shared password'], store)
            cli(owner, ['otp', 'set', 'shared/secret', '--secret-stdin'],
                [PASSPHRASE, 'JBSWY3DPEHPK3PXP'], store)
            cli(owner, ['push', '--collection', collection, '--revision', '0'], [PASSPHRASE], store)
            draft = owner / 'migration.json'
            common = ['--collection', collection, '--authority-identity', owner / 'identity.json', '--draft', draft]
            cli(owner, ['entries', 'migrate-stage', *common, '--recovery-policy', 'replace'],
                [PASSPHRASE, IDENTITY, PASSPHRASE, PASSPHRASE])
            cli(owner, ['entries', 'migrate-submit', *common, '--pin', owner / 'pin.json',
                        '--cache', owner / 'cache', '--confirm'], [PASSPHRASE, IDENTITY, PASSPHRASE])
            digest = json.loads(draft.with_suffix('.accepted.json').read_text())['accepted']['digest']
            anchor = owner / 'cache' / (digest + '.json')
            args = state_args(owner, collection, anchor)
            old_export = root / 'recipient-old.json'
            saved = export(recipient_api, collection, old_export, bob['id'])
            # Simulate independent authority confirmation, never trust a digest supplied by the export.
            checkpoint_file = next((owner / 'cache').glob('epoch-*.json'))
            confirmed_digest = checkpoint_file.stem.removeprefix('epoch-')
            confirmed_authority = json.loads((owner / 'identity.json').read_text())['public_identity']['fingerprint']
            save(recipient / 'checkpoint.json', saved['handoff']['checkpoint'])
            save(recipient / 'handoff.json', saved['handoff'])
            save(recipient / 'anchor.json', saved['object'])
            trust = ['entries', 'trust', '--checkpoint', recipient / 'checkpoint.json',
                     '--checkpoint-digest', confirmed_digest, '--authority-fingerprint', confirmed_authority,
                     '--index', recipient / 'anchor.json', '--handoff', recipient / 'handoff.json',
                     '--recipient-identity', recipient / 'identity.json', '--pin', recipient / 'pin.json',
                     '--cache', recipient / 'cache']
            cli(recipient, trust, [], ok=False)
            assert not (recipient / 'pin.json').exists()
            cli(recipient, [*trust, '--confirm'], [IDENTITY])
            historical = root / 'historical-device'
            retained_device(recipient, historical)
            recover(historical, old_export, root / 'historical-before-revocation')
            reader_args = [*state_args(recipient, collection, recipient / 'anchor.json'),
                           '--handoff', recipient / 'handoff.json']

            # Rotate with both recipients, then have the read-only recipient independently accept it.
            rotation = owner / 'rotation.json'
            rotate_args = [*args, '--authority-identity', owner / 'identity.json', '--draft', rotation]
            cli(owner, ['entries', 'rotate', *rotate_args, '--recovery-policy', 'replace'],
                [IDENTITY, IDENTITY, PASSPHRASE, PASSPHRASE])
            cli(owner, ['entries', 'rotate-submit', *rotate_args, '--confirm'], [IDENTITY, IDENTITY])
            before = (recipient / 'pin.json').read_bytes()
            advance = ['entries', 'advance-epoch', *reader_args, '--next-identity', recipient / 'identity.json']
            cli(recipient, advance, [IDENTITY, IDENTITY])
            assert (recipient / 'pin.json').read_bytes() == before
            cli(recipient, [*advance, '--confirm'], [IDENTITY, IDENTITY])
            assert (recipient / 'pin.json').read_bytes() != before
            current_export = root / 'recipient-current.json'
            current = export(recipient_api, collection, current_export, bob['id'])
            owner_export = root / 'owner-current.json'
            export(owner_api, collection, owner_export, alice['id'])
            owner_device, second_device = root / 'owner-restored', root / 'recipient-second-device'
            retained_device(owner, owner_device)
            retained_device(recipient, second_device)
            # Destroy the reader cache. Recovery has only the exported ciphertext and retained trust/key.
            shutil.rmtree(recipient / 'cache')
            recover(owner_device, owner_export, root / 'owner-recovered')
            recover(second_device, current_export, root / 'recipient-recovered')
            recover(second_device, owner_export, root / 'cross-user-rejected', ok=False)
            recover(second_device, old_export, root / 'rollback-rejected', ok=False)

            # Revoke API access and rotate to a new root that has no package for Bob.
            server.api('/v1/auth/login', {'username': 'alice', 'password': PASSWORD})
            server.api('/v1/admin/groups', {'id': collection, 'name': 'Shared recovery',
                                          'members': [{'user_id': alice['id'], 'edit': True}]})
            assert collection not in {c['id'] for c in recipient_api.get('/v1/backup/index')['collections']}
            try:
                recipient_api.get('/v1/backup/collections/' + collection)
            except ValueError as error:
                assert 'HTTP 403' in str(error)
            else:
                raise AssertionError('Revoked recipient could still export')
            revoked = owner / 'revoked-rotation.json'
            revoke_args = [*args, '--authority-identity', owner / 'identity.json', '--draft', revoked]
            cli(owner, ['entries', 'rotate', *revoke_args, '--recovery-policy', 'replace'],
                [IDENTITY, IDENTITY, PASSPHRASE, PASSPHRASE])
            cli(owner, ['entries', 'rotate-submit', *revoke_args, '--confirm'], [IDENTITY, IDENTITY])
            transaction = json.loads(revoked.read_text())['transaction']
            packages = [json.loads(w['envelope']) for w in transaction['wrappers'] if w['kind'] == 'recipient']
            assert [p['recipient_user_id'] for p in packages] == [alice['id']]
            new_export = root / 'owner-after-revocation.json'
            newest = export(owner_api, collection, new_export, alice['id'])
            assert newest['object']['head']['context']['key_epoch'] > current['object']['head']['context']['key_epoch']
            recover(second_device, new_export, root / 'revoked-new-epoch-rejected', ok=False)
            # Even explicitly confirming the new authority checkpoint cannot let Bob
            # decrypt Alice's recipient package. This is a new test pin, never a reset.
            latest_digest = next(p.stem.removeprefix('epoch-') for p in (owner / 'cache').glob('epoch-*.json')
                                 if json.loads(p.read_text())['checkpoint'] == newest['handoff']['checkpoint'])
            save(second_device / 'new-checkpoint.json', newest['handoff']['checkpoint'])
            save(second_device / 'new-handoff.json', newest['handoff'])
            save(second_device / 'new-anchor.json', newest['object'])
            cli(second_device, ['entries', 'trust', '--checkpoint', second_device / 'new-checkpoint.json',
                                '--checkpoint-digest', latest_digest, '--authority-fingerprint', confirmed_authority,
                                '--index', second_device / 'new-anchor.json', '--handoff', second_device / 'new-handoff.json',
                                '--recipient-identity', second_device / 'identity.json',
                                '--pin', second_device / 'rejected-pin.json', '--cache', second_device / 'rejected-cache',
                                '--confirm'], [IDENTITY], ok=False)
            assert not (second_device / 'rejected-pin.json').exists()
            retained_device(owner, root / 'owner-latest')
            server.stop()
            shutil.rmtree(owner)
            shutil.rmtree(recipient)
            recover(root / 'owner-latest', new_export, root / 'owner-latest-recovered')
            # Revocation cannot erase an already retained key and ciphertext from an older epoch.
            recover(historical, old_export, root / 'historical-after-revocation')
            recover(second_device, current_export, root / 'retained-after-revocation')
        finally:
            server.stop()
    print(f'Shared recovery passed: {mode}; scoped exports, independent trust, restored identities, rotation and revocation.', flush=True)


if __name__ == '__main__':
    for mode in ['standard', 'hybrid-post-quantum']:
        drill(mode)
