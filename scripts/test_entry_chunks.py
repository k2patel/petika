#!/usr/bin/env python3
"""Real API chunk capture and native recovery above 16 MiB; synthetic data only."""
import argparse
import hashlib
import json
from pathlib import Path
import secrets
import shutil
import tempfile

from test_backup_recovery import Server, PASSWORD, PASSPHRASE, IDENTITY
from test_entry_recovery import cli, write, state_args
import backup_recovery
import user_backup


def drill(mode, retain=None):
    with tempfile.TemporaryDirectory(prefix='petika-chunks-') as temporary:
        root = Path(temporary)
        home = root / 'server'
        (home / 'config').mkdir(parents=True)
        write(home / 'config/token', secrets.token_hex(32).encode())
        write(home / 'config/password', PASSWORD.encode())
        server = Server(home, provision=True, mirror=False, overrides={'PETIKA_EXPERIMENTAL_ENTRIES': '1'})
        try:
            client = root / 'client'
            user = server.login(client)
            cli(client, ['keys', 'enroll'], [IDENTITY, IDENTITY, PASSWORD], identity=True)
            store = client / 'source.petika'
            cli(client, ['init', '--encryption', mode], [PASSPHRASE, PASSPHRASE], store)
            cli(client, ['put', 'first', '--password-stdin'], [PASSPHRASE, 'synthetic password'], store)
            cli(client, ['push', '--collection', 'personal', '--revision', '0'], [PASSPHRASE], store)
            migration = client / 'migration.json'
            common = ['--authority-identity', client / 'identity.json', '--draft', migration]
            cli(client, ['entries', 'migrate-stage', *common, '--recovery-policy', 'replace'],
                [PASSPHRASE, IDENTITY, PASSPHRASE, PASSPHRASE])
            cli(client, ['entries', 'migrate-submit', *common, '--pin', client / 'pin.json',
                         '--cache', client / 'cache', '--confirm'], [PASSPHRASE, IDENTITY, PASSPHRASE])
            anchor = client / 'cache' / (json.loads(migration.with_suffix('.accepted.json').read_text())['accepted']['digest'] + '.json')
            state = state_args(client, user['id'], anchor)
            # Two bounded arguments also work on platforms with a 128 KiB per-argument limit.
            for number in range(64):
                draft = client / f'large-{number}.json'
                cli(client, ['entries', 'put', *state, '--name', f'large-{number}',
                             '--username', 'u' * 100000, '--url', 'x' * 100000,
                             '--password-stdin', '--draft', draft], [IDENTITY, 'synthetic large password'])
                cli(client, ['entries', 'submit', *state, '--draft', draft, '--confirm'], [IDENTITY])
                if number % 16 == 15:
                    print(f'{mode}: {number + 1}/64 large entries accepted', flush=True)
            key = server.api('/v1/backup-settings/keys', {'name': 'chunk drill', 'expires_in_days': 1, 'current_password': PASSWORD})
            keyfile = root / 'backup-key'
            write(keyfile, key['token'].encode())
            api = user_backup.API(server.origin, keyfile)
            bundle = root / 'bundle'
            user_backup.fetch(api, bundle, chunked=True)
            manifest = bundle / 'collections' / (user['id'] + '.json')
            saved = json.loads(manifest.read_text())
            chunks = manifest.with_suffix('.entries')
            size = sum(p.stat().st_size for p in chunks.iterdir())
            assert size > 16 * 1024 * 1024 and saved['backup_version'] == 3
            pin = (client / 'pin.json').read_bytes()
            kit = root / 'kit'
            kit.mkdir(mode=0o700)
            for name in ['identity.json', 'pin.json']:
                write(kit / name, (client / name).read_bytes())
            # Native recovery must work after deleting the old client and all its cached entries.
            shutil.rmtree(client)
            base = ['entries', 'recover-backup', '--backup', manifest, '--pin', kit / 'pin.json',
                    '--recipient-identity', kit / 'identity.json']
            output = root / 'recovered'
            cli(kit, [*base, '--output', output], [IDENTITY])
            assert (kit / 'pin.json').read_bytes() == pin
            user_backup.verify_user_bundle(bundle)  # native import must not modify the source bundle
            marker = json.loads((output / 'RECOVERY.json').read_text())
            assert marker['entries'] == 65
            cli(kit, ['entries', 'verify-backup', '--anchor', output / marker['anchor'],
                      '--pin', kit / 'pin.json', '--cache', output, '--handoff', output / 'handoff.json',
                      '--recipient-identity', kit / 'identity.json'], [IDENTITY])
            for label in ['missing', 'tampered']:
                entry = next(chunks.iterdir())
                original = entry.read_bytes()
                if label == 'missing':
                    entry.unlink()
                else:
                    write(entry, b'{}')
                rejected = root / label
                cli(kit, [*base, '--output', rejected], [IDENTITY], ok=False)
                assert not rejected.exists() and (kit / 'pin.json').read_bytes() == pin
                write(entry, original)
            cli(kit, [*base, '--output', output], [IDENTITY], ok=False)
            class Interrupted:
                def get(self, path):
                    if '/entries/' in path:
                        raise ValueError('synthetic network interruption')
                    return api.get(path)
            try:
                user_backup.fetch(Interrupted(), root / 'interrupted', chunked=True)
            except ValueError:
                pass
            else:
                raise AssertionError('Interrupted capture unexpectedly succeeded')
            assert not (root / 'interrupted').exists()
            entry, reference = next(iter(saved['entries'].items()))
            chunk_url = f'/v1/backup/collections/{user["id"]}/entries/{saved["head_digest"]}/{entry}/{reference["digest"]}'
            try:
                api.get(chunk_url.replace(saved['head_digest'], '0' * 64))
            except ValueError:
                pass
            else:
                raise AssertionError('Mismatched head accepted')
            if retain:
                destination = retain / mode
                destination.mkdir(mode=0o700)
                backup_recovery.private_copy(bundle, destination / 'bundle')
                backup_recovery.private_copy(kit, destination / 'kit')
                write(destination / 'evidence.json', json.dumps({'mode': mode, 'collection': user['id'],
                      'entries': 65, 'ciphertext_bytes': size, 'pin_sha256': hashlib.sha256(pin).hexdigest()}).encode())
            print(f'Chunked export/recovery passed: {mode}, {size} ciphertext bytes, exact pin and 65 decrypted entries.', flush=True)
        finally:
            server.stop()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--retain-kit', type=Path, help='New directory for synthetic cross-platform recovery kits')
    args = parser.parse_args()
    if args.retain_kit:
        args.retain_kit.mkdir(mode=0o700)
    for mode in ['standard', 'hybrid-post-quantum']:
        drill(mode, args.retain_kit)
