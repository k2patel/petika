#!/usr/bin/env python3
"""Real shared-vault recovery, retained identity copies and membership revocation.

Synthetic device directories use software identities; this does not test hardware
keys, biometrics, independently enrolled device keys or production key custody.
"""
import argparse
import json
import hashlib
from pathlib import Path
import secrets
import shutil
import tempfile

from test_backup_recovery import Server, PASSWORD, PASSPHRASE, IDENTITY, run, tool
from test_entry_recovery import cli, write, state_args, capture, AUDIT
import user_backup
import backup_recovery


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


def drill(mode, downgrade=False, replace_identity=False):
    with tempfile.TemporaryDirectory(prefix='petika-shared-recovery-') as temporary:
        root = Path(temporary)
        home = root / 'server'
        (home / 'config').mkdir(parents=True)
        (home / 'mirror').mkdir()
        write(home / 'config/token', secrets.token_hex(32).encode())
        write(home / 'config/password', PASSWORD.encode())
        server = Server(home, provision=True, mirror=False,
                        overrides={'PETIKA_EXPERIMENTAL_ENTRIES': '1'})
        try:
            owner, recipient = root / 'owner', root / 'recipient'
            alice = server.login(owner)
            bob = server.api('/v1/admin/users', {'username': 'bob', 'name': 'Reader', 'password': PASSWORD})
            group = server.api('/v1/admin/groups', {'name': 'Shared recovery', 'members': [
                {'user_id': alice['id'], 'edit': True}, {'user_id': bob['id'], 'edit': downgrade}]})
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
            recipient_pin = (second_device / 'pin.json').read_bytes()
            if downgrade:
                pending = recipient / 'pending-edit.json'
                cli(recipient, ['entries', 'put', *state_args(recipient, collection, recipient / 'anchor.json'),
                                '--name', 'pending-editor-change', '--password-stdin', '--draft', pending],
                    [IDENTITY, 'synthetic pending password'])
                pending_bytes = pending.read_bytes()
                pending_transaction = json.loads(pending_bytes)['transaction']
                write(second_device / 'pending-edit.json', pending_bytes)
            # Destroy the reader cache. Recovery has only the exported ciphertext and retained trust/key.
            shutil.rmtree(recipient / 'cache')
            recover(owner_device, owner_export, root / 'owner-recovered')
            recover(second_device, current_export, root / 'recipient-recovered')
            recover(second_device, owner_export, root / 'cross-user-rejected', ok=False)
            recover(second_device, old_export, root / 'rollback-rejected', ok=False)

            # Retain a complete pre-revocation baseline with Bob still in the group.
            server.stop()
            baseline_report = root / 'pre-revocation-report.json'
            write(baseline_report, run([AUDIT, home / 'data']).encode())
            baseline_cursor = json.loads(baseline_report.read_text())['collections'][0]['accepted']
            capture(home, root / 'pre-revocation-backup')
            # Managed identity commands retain the original origin pin across this restart.
            server = Server(home, mirror=False, overrides={'PETIKA_EXPERIMENTAL_ENTRIES': '1'},
                            port=int(server.origin.rsplit(':', 1)[1]) if replace_identity else None)
            owner_session = root / 'owner-restarted'
            server.login(owner_session)
            write(owner / 'session.json', (owner_session / 'session.json').read_bytes())
            owner_api = user_backup.API(server.origin, root / 'owner-backup-key')
            recipient_api = user_backup.API(server.origin, root / 'recipient-backup-key')
            # Remove membership or edit permission, then rotate for the current roster.
            server.api('/v1/auth/login', {'username': 'alice', 'password': PASSWORD})
            members = [{'user_id': alice['id'], 'edit': True}]
            if downgrade or replace_identity:
                members.append({'user_id': bob['id'], 'edit': False})
            server.api('/v1/admin/groups', {'id': collection, 'name': 'Shared recovery', 'members': members})
            if replace_identity:
                replacement = root / 'replacement-device'
                server.login(replacement, 'bob')
                old_identity = server.api('/v1/keys/identity')
                run([AUDIT.parent / 'examples/recovery_identity_fixture',
                     old_identity['public_identity']['deployment_id'], bob['id'], root / 'replacement-fixture.json'])
                replacement_backup = json.loads((root / 'replacement-fixture.json').read_text())
                replacement_public = replacement_backup['public_identity']
                request = {'expected_bundle_revision': old_identity['bundle_revision'],
                           'expected_identity_version': old_identity['public_identity']['identity_version'],
                           'current_password': PASSWORD, 'public_identity': replacement_public,
                           'encrypted_bundle': replacement_backup['encrypted_bundle']}
                replacement_state = server.api('/v1/keys/identity/replace', request)
                assert replacement_state['public_identity'] == replacement_public
                server.api('/v1/keys/identity/replace', request, expected=409)
                assert server.api('/v1/keys/identity') == replacement_state
                cli(replacement, ['keys', 'restore', '--fingerprint', replacement_public['fingerprint']],
                    [IDENTITY], identity=True)
                # New keys do not silently inherit the old identity's verified contacts.
                cli(replacement, ['keys', 'verify', '--user', alice['id'],
                                  '--fingerprint', confirmed_authority], [IDENTITY], identity=True)
                replacement_state = server.api('/v1/keys/identity')
                # Existing packages target the retired identity until an authority rotates.
                try:
                    recipient_api.get('/v1/backup/collections/' + collection)
                except ValueError as error:
                    assert 'HTTP 503' in str(error)
                else:
                    raise AssertionError('Replacement identity received an obsolete package')
                write(replacement / 'pin.json', recipient_pin)
                server.api('/v1/auth/login', {'username': 'alice', 'password': PASSWORD})
                # An explicit independently confirmed replacement fingerprint updates the contact pin.
                cli(owner, ['keys', 'verify', '--user', bob['id'],
                            '--fingerprint', replacement_public['fingerprint']], [IDENTITY], identity=True)
            if downgrade:
                probe = root / 'downgraded-session'
                server.login(probe, 'bob')
                probe_headers = {'Authorization': 'Bearer ' + json.loads((probe / 'session.json').read_text())['token']}
                visible = next(c for c in server.api('/v1/collections', headers=probe_headers) if c['id'] == collection)
                assert visible['edit'] is False
                # The staged transaction still targets the current head: denial is not due to rotation/staleness.
                status = server.api(f'/v1/collections/{collection}/status', headers=probe_headers)
                assert status['accepted'] == pending_transaction['expected']
                server.api(f'/v1/collections/{collection}/entry-transactions', pending_transaction,
                           headers=probe_headers, expected=403)
                assert server.api(f'/v1/collections/{collection}/status', headers=probe_headers)['accepted'] == status['accepted']
                server.api('/v1/auth/login', {'username': 'alice', 'password': PASSWORD})
            if downgrade:
                assert collection in {c['id'] for c in recipient_api.get('/v1/backup/index')['collections']}
                export(recipient_api, collection, root / 'downgraded-pre-rotation.json', bob['id'])
            elif not replace_identity:
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
            assert {p['recipient_user_id'] for p in packages} == ({alice['id'], bob['id']} if downgrade or replace_identity else {alice['id']})
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
            accepted = json.loads((owner / 'revoked-rotation.accepted.json').read_text())
            # Retain the exact post-revocation access state for comparison after restore.
            live_group = next(g for g in server.api('/v1/admin/groups') if g['id'] == collection)
            capture_session = root / 'bob-before-capture'
            assert server.login(capture_session, 'bob')['id'] == bob['id']
            old_bob_token = json.loads((capture_session / 'session.json').read_text())['token']
            assert server.api('/v1/auth/status', headers={'Authorization': 'Bearer ' + old_bob_token})['user']['id'] == bob['id']
            server.stop()
            expected_report = root / 'post-revocation-report.json'
            write(expected_report, run([AUDIT, home / 'data']).encode())
            full = root / 'post-revocation-backup'
            capture(home, full)
            manifest_hash = hashlib.sha256((full / 'manifest.json').read_bytes()).hexdigest()
            source_inventory = backup_recovery.inventory(full)
            restored = root / 'reconciled-server'
            tool('reconcile', full, '--release', 'entry-drill-release',
                 '--baseline-report', baseline_report, '--expected-report', expected_report,
                 '--expected-manifest-sha256', manifest_hash, '--recovery-tool', AUDIT,
                 '--output', restored)
            assert (restored / 'RECONCILIATION.json').is_file()
            assert (restored / 'data/accounts.json').read_bytes() == (full / 'data/accounts.json').read_bytes()
            assert backup_recovery.inventory(full) == source_inventory
            # Destruction here affects only disposable fixtures. All subsequent access uses the restore.
            shutil.rmtree(home)
            shutil.rmtree(owner)
            shutil.rmtree(recipient)
            recover(root / 'owner-latest', new_export, root / 'owner-latest-recovered')
            # Revocation cannot erase an already retained key and ciphertext from an older epoch.
            recover(historical, old_export, root / 'historical-after-revocation')
            recover(second_device, current_export, root / 'retained-after-revocation')
            server = Server(restored, mirror=False, overrides={'PETIKA_EXPERIMENTAL_ENTRIES': '1'})
            restored_owner = root / 'restored-owner-session'
            assert server.login(restored_owner)['id'] == alice['id']
            restored_group = next(g for g in server.api('/v1/admin/groups') if g['id'] == collection)
            assert restored_group == live_group
            assert {m['user_id']: m['edit'] for m in restored_group['members']} == {m['user_id']: m['edit'] for m in members}
            owner_api = user_backup.API(server.origin, root / 'owner-backup-key')
            after = export(owner_api, collection, root / 'restored-owner-export.json', alice['id'])
            assert after == newest
            lookup = server.api(f'/v1/collections/{collection}/entry-receipt',
                                {'context': newest['object']['head']['context'], 'operation': accepted['operation']})
            assert lookup['receipt'] == accepted
            recover(root / 'owner-latest', root / 'restored-owner-export.json', root / 'restored-owner-verified')
            # Sessions are memory-only: a restored server must not resurrect an old CLI grant.
            old_headers = {'Authorization': 'Bearer ' + old_bob_token}
            assert server.api('/v1/auth/status', headers=old_headers)['user'] is None
            server.api('/v1/collections', headers=old_headers, expected=401)
            # Fresh, valid CLI/browser credentials must still enforce the removed membership.
            restored_bob = root / 'restored-bob-session'
            assert server.login(restored_bob, 'bob')['id'] == bob['id']
            new_bob_token = json.loads((restored_bob / 'session.json').read_text())['token']
            headers = {'Authorization': 'Bearer ' + new_bob_token}
            assert server.api('/v1/auth/status', headers=headers)['user']['id'] == bob['id']
            if replace_identity:
                assert server.api('/v1/keys/identity', headers=headers) == replacement_state
                recipient_api = user_backup.API(server.origin, root / 'recipient-backup-key')
                read_export = root / 'replacement-reader-export.json'
                read_saved = export(recipient_api, collection, read_export, bob['id'])
                package = json.loads(read_saved['handoff']['package'])
                assert package['recipient_identity_version'] == replacement_public['identity_version']
                cache = root / 'recipient-recovered'
                reader_anchor = cache / json.loads((cache / 'RECOVERY.json').read_text())['anchor']
                reader_state = ['--collection', collection, '--anchor', reader_anchor,
                                '--pin', replacement / 'pin.json', '--cache', cache,
                                '--recipient-identity', second_device / 'identity.json',
                                '--handoff', cache / 'handoff.json']
                write(replacement / 'session.json', (restored_bob / 'session.json').read_bytes())
                cli(replacement, ['entries', 'advance-epoch', *reader_state,
                                  '--next-identity', second_device / 'identity.json', '--confirm'],
                    [IDENTITY, IDENTITY], ok=False)
                assert (replacement / 'pin.json').read_bytes() == recipient_pin
                cli(replacement, ['entries', 'advance-epoch', *reader_state,
                                  '--next-identity', replacement / 'identity.json', '--confirm'], [IDENTITY, IDENTITY])
                assert json.loads((replacement / 'pin.json').read_text())['head'] == read_saved['object']['head']
                recover(replacement, read_export, root / 'replacement-restored-verified')
                # At the exact same new pin, the retired key still cannot decrypt the new package.
                retired = root / 'retired-at-new-head'
                retained_device(replacement, retired)
                write(retired / 'identity.json', (second_device / 'identity.json').read_bytes())
                recover(retired, read_export, root / 'retired-key-rejected', ok=False)
                assert (second_device / 'pin.json').read_bytes() == recipient_pin
            elif downgrade:
                visible = next(c for c in server.api('/v1/collections', headers=headers) if c['id'] == collection)
                assert visible['edit'] is False
                browser_visible = next(c for c in server.api('/v1/collections') if c['id'] == collection)
                assert browser_visible['edit'] is False
                recipient_api = user_backup.API(server.origin, root / 'recipient-backup-key')
                read_export = root / 'restored-reader-export.json'
                read_saved = export(recipient_api, collection, read_export, bob['id'])
                status = server.api(f'/v1/collections/{collection}/status', headers=headers)
                for auth in (headers, None):
                    server.api(f'/v1/collections/{collection}/entry-transactions', pending_transaction,
                               headers=auth, expected=403)
                assert server.api(f'/v1/collections/{collection}/status', headers=headers)['accepted'] == status['accepted']
                assert (second_device / 'pending-edit.json').read_bytes() == pending_bytes
                assert (second_device / 'pin.json').read_bytes() == recipient_pin
                write(second_device / 'session.json', (restored_bob / 'session.json').read_bytes())
                cache = root / 'recipient-recovered'
                reader_anchor = cache / json.loads((cache / 'RECOVERY.json').read_text())['anchor']
                reader_state = ['--collection', collection, '--anchor', reader_anchor,
                                '--pin', second_device / 'pin.json', '--cache', cache,
                                '--recipient-identity', second_device / 'identity.json']
                cli(second_device, ['entries', 'advance-epoch', *reader_state, '--handoff', cache / 'handoff.json',
                                    '--next-identity', second_device / 'identity.json', '--confirm'], [IDENTITY, IDENTITY])
                assert json.loads((second_device / 'pin.json').read_text())['head'] == read_saved['object']['head']
                recover(second_device, read_export, root / 'restored-reader-verified')
                accepted_pin = (second_device / 'pin.json').read_bytes()
                denied_draft = second_device / 'forbidden-new-write.json'
                cli(second_device, ['entries', 'put', *reader_state, '--name', 'forbidden',
                                    '--password-stdin', '--draft', denied_draft], [IDENTITY, 'unused'], ok=False)
                assert not denied_draft.exists()
                assert (second_device / 'pin.json').read_bytes() == accepted_pin
                assert (second_device / 'pending-edit.json').read_bytes() == pending_bytes
                assert server.api(f'/v1/collections/{collection}/status', headers=headers)['accepted'] == status['accepted']
            else:
                assert collection not in {c['id'] for c in server.api('/v1/collections', headers=headers)}
                for action, body in [
                        ('entry-roster', {}),
                        ('entry-epoch', {'context': current['object']['head']['context'],
                                         'after': baseline_cursor}),
                        ('entry-receipt', {'context': newest['object']['head']['context'], 'operation': accepted['operation']})]:
                    server.api(f'/v1/collections/{collection}/{action}', body, headers=headers, expected=403)
                recipient_api = user_backup.API(server.origin, root / 'recipient-backup-key')
                assert recipient_api.get('/v1/backup/index')['user']['id'] == bob['id']
                assert collection not in {c['id'] for c in recipient_api.get('/v1/backup/index')['collections']}
                try:
                    recipient_api.get('/v1/backup/collections/' + collection)
                except ValueError as error:
                    assert 'HTTP 403' in str(error)
                else:
                    raise AssertionError('Restored backup resurrected revoked group access')
                # Browser cookies from the fresh login enforce the same membership as the CLI.
                assert collection not in {c['id'] for c in server.api('/v1/collections')}
                server.api(f'/v1/collections/{collection}/entry-roster', {}, expected=403)
                assert (second_device / 'pin.json').read_bytes() == recipient_pin

        finally:
            server.stop()
    print(f'Shared recovery passed: {mode}, downgrade={downgrade}, replacement={replace_identity}; scoped exports, independent trust, restored identities, rotation, revocation and complete-server reconciliation.', flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    scenario = parser.add_mutually_exclusive_group()
    scenario.add_argument('--role-downgrade', action='store_true',
                        help='Keep the former editor as a reader instead of removing membership')
    scenario.add_argument('--identity-replacement', action='store_true',
                          help='Replace the retained reader identity before rotation and recovery')
    args = parser.parse_args()
    for mode in ['standard', 'hybrid-post-quantum']:
        drill(mode, args.role_downgrade, args.identity_replacement)
