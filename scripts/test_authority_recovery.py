#!/usr/bin/env python3
"""Synthetic same-account authority replacement and complete-server recovery.

Requires opt-in native binaries and the recovery_identity_fixture example. Both
signing identities survive replacement; this is not lost-authority recovery or
hardware-backed device enrollment.
"""
import json
from pathlib import Path
import secrets
import shutil
import tempfile

import user_backup

from test_backup_recovery import Server, PASSWORD, PASSPHRASE, IDENTITY, run, tool
from test_entry_recovery import cli, write, state_args, capture, AUDIT
from test_entry_shared_recovery import save, reader, export, recover, retained_device


def drill(mode):
    with tempfile.TemporaryDirectory(prefix='petika-authority-recovery-') as temporary:
        root = Path(temporary)
        home = root / 'server'
        (home / 'config').mkdir(parents=True)
        (home / 'mirror').mkdir()
        write(home / 'config/token', secrets.token_hex(32).encode())
        write(home / 'config/password', PASSWORD.encode())
        overrides = {'PETIKA_EXPERIMENTAL_ENTRIES': '1'}
        server = Server(home, provision=True, mirror=False, overrides=overrides)
        try:
            owner = root / 'owner'
            user = server.login(owner)
            cli(owner, ['keys', 'enroll'], [IDENTITY, IDENTITY, PASSWORD], identity=True)
            backup_api = reader(server, root, 'authority-backup')
            store = owner / 'source.petika'
            cli(owner, ['init', '--encryption', mode], [PASSPHRASE, PASSPHRASE], store)
            cli(owner, ['put', 'authority/private-entry', '--password-stdin'],
                [PASSPHRASE, 'synthetic authority secret'], store)
            cli(owner, ['otp', 'set', 'authority/private-entry', '--secret-stdin'],
                [PASSPHRASE, 'JBSWY3DPEHPK3PXP'], store)
            cli(owner, ['push', '--collection', 'personal', '--revision', '0'], [PASSPHRASE], store)
            migration = owner / 'migration.json'
            common = ['--authority-identity', owner / 'identity.json', '--draft', migration]
            cli(owner, ['entries', 'migrate-stage', *common, '--recovery-policy', 'replace'],
                [PASSPHRASE, IDENTITY, PASSPHRASE, PASSPHRASE])
            cli(owner, ['entries', 'migrate-submit', *common, '--pin', owner / 'pin.json',
                        '--cache', owner / 'cache', '--confirm'], [PASSPHRASE, IDENTITY, PASSPHRASE])
            digest = json.loads(migration.with_suffix('.accepted.json').read_text())['accepted']['digest']
            anchor = owner / 'cache' / (digest + '.json')
            before = root / 'old-export.json'
            old_export = export(backup_api, user['id'], before, user['id'])
            historical = root / 'old-device'
            retained_device(owner, historical)
            old_pin = (owner / 'pin.json').read_bytes()
            old_public = old_export['handoff']['checkpoint']['authority']

            # Replacement enrollment is an existing reauthenticated CAS API. The
            # fixture only generates a synthetic version-2 identity for this drill.
            enrolled = server.api('/v1/keys/identity')
            fixture = root / 'replacement-fixture.json'
            run([AUDIT.parent / 'examples/recovery_identity_fixture', old_public['deployment_id'], user['id'], fixture])
            bundle = json.loads(fixture.read_text())
            new_public = bundle['public_identity']
            server.api('/v1/keys/identity/replace', {
                'expected_bundle_revision': enrolled['bundle_revision'],
                'expected_identity_version': old_public['identity_version'],
                'current_password': PASSWORD, 'public_identity': new_public,
                'encrypted_bundle': bundle['encrypted_bundle'],
            })
            replacement = root / 'new-device'
            server.login(replacement)
            cli(replacement, ['keys', 'restore', '--fingerprint', new_public['fingerprint']],
                [IDENTITY], identity=True)
            args = state_args(owner, user['id'], anchor)
            draft = owner / 'replacement.json'
            base = ['entries', 'rotate', *args, '--authority-identity', owner / 'identity.json',
                    '--draft', draft, '--recovery-policy', 'replace']
            cli(owner, base, [IDENTITY], ok=False)
            extra = ['--replacement-identity', replacement / 'identity.json',
                     '--replacement-fingerprint', new_public['fingerprint']]
            wrong = extra.copy(); wrong[-1] = '0' * 64
            cli(owner, [*base, *wrong], [IDENTITY], ok=False)
            assert not draft.exists() and (owner / 'pin.json').read_bytes() == old_pin
            # Unlock old content, unlock new identity, verify new recovery, then
            # authorize the candidate using the retained old signing identity.
            cli(owner, [*base, *extra], [IDENTITY, IDENTITY, PASSPHRASE, PASSPHRASE, IDENTITY])
            draft_bytes = draft.read_bytes()
            for secret in (IDENTITY, PASSPHRASE, 'authority/private-entry', 'synthetic authority secret', 'JBSWY3DPEHPK3PXP'):
                assert secret.encode() not in draft_bytes
            tx = json.loads(draft_bytes)['transaction']
            forged = json.loads(draft_bytes)['transaction']
            forged['transition']['signature'] = 'A' * 88
            server.api(f'/v1/collections/{user["id"]}/entry-rotations', forged, expected=409)
            submit = [*args, '--authority-identity', replacement / 'identity.json', '--draft', draft]
            cli(owner, ['entries', 'rotate-review', *submit], [IDENTITY, IDENTITY])
            cli(owner, ['entries', 'rotate-submit', *submit], [], ok=False)
            assert (owner / 'pin.json').read_bytes() == old_pin
            cli(owner, ['entries', 'rotate-submit', *submit, '--confirm'], [IDENTITY, IDENTITY])
            cli(owner, ['entries', 'rotate-submit', *submit, '--confirm'], [IDENTITY])
            assert draft.read_bytes() == draft_bytes
            assert (owner / 'pin.json').read_bytes() != old_pin
            # Old material cannot unlock the new epoch even with the new exact pin.
            cli(owner, ['entries', 'verify-backup', *args], [IDENTITY], ok=False)
            new_args = args.copy(); new_args[-1] = replacement / 'identity.json'
            cli(owner, ['entries', 'verify-backup', *new_args], [IDENTITY])
            current = root / 'new-export.json'
            saved = export(backup_api, user['id'], current, user['id'])
            assert saved['handoff']['checkpoint']['authority'] == new_public
            assert saved['object']['head']['context']['key_epoch'] == 2
            assert saved['handoff']['checkpoint']['delivery_profile'] == old_export['handoff']['checkpoint']['delivery_profile']
            write(replacement / 'pin.json', (owner / 'pin.json').read_bytes())
            kit = root / 'recovery-device'
            retained_device(replacement, kit)
            recover(kit, current, root / 'new-key-recovered')
            recover(kit, before, root / 'old-export-rejected', ok=False)
            recover(historical, before, root / 'historical-recovered')
            write(historical / 'pin.json', (kit / 'pin.json').read_bytes())
            recover(historical, current, root / 'old-key-rejected', ok=False)
            assert tx['transition']['next']['authority'] == new_public

            # Recover the whole server with only separately retained current keys,
            # pins and exports. No reset of the client's checkpoint is permitted.
            server.stop()
            capture(home, root / 'full')
            shutil.rmtree(home)
            shutil.rmtree(owner)
            shutil.rmtree(replacement)
            restored = root / 'restored'
            tool('restore', root / 'full', '--output', restored, '--release', 'entry-drill-release')
            server = Server(restored, mirror=False, overrides=overrides)
            session = root / 'restored-session'
            assert server.login(session)['id'] == user['id']
            assert server.api('/v1/keys/identity')['public_identity'] == new_public
            restored_api = user_backup.API(server.origin, root / 'authority-backup-key')
            after_export = root / 'restored-export.json'
            restored_export = export(restored_api, user['id'], after_export, user['id'])
            assert restored_export['handoff']['checkpoint']['authority'] == new_public
            recover(kit, after_export, root / 'restored-key-recovered')
            recover(historical, after_export, root / 'restored-old-key-rejected', ok=False)
        finally:
            server.stop()
    print(f'Authority replacement recovery passed: {mode}; two signatures, current enrollment, exact-pin recovery and retired-key rejection.', flush=True)


if __name__ == '__main__':
    for mode in ['standard', 'hybrid-post-quantum']:
        drill(mode)
