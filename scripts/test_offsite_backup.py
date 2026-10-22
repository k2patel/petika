#!/usr/bin/env python3
"""Synthetic off-site runner safety and real encrypted repository round trips."""
import argparse
import json
import os
from pathlib import Path
import tempfile
import unittest

import backup_recovery as backup
import offsite_backup as offsite
import user_backup as user


class OffsiteTests(unittest.TestCase):
    def test_transport_and_origin_guards(self):
        for value in ('s3:http://host/bucket', 's3:https://key:secret@host/bucket',
                      'sftp://user:secret@host//backup', 'sftp://user@-oProxyCommand=evil//backup', 'sftp://-option@host//backup', '/local'):
            with self.assertRaises(ValueError):
                offsite.transport(value)
        self.assertEqual(offsite.transport('s3:https://host/bucket/path'), 's3')
        self.assertEqual(offsite.transport('sftp://user@host//backup'), 'sftp')
        for value in ('http://example.com', 'https://host/path', 'https://user:secret@host'):
            with self.assertRaises(ValueError):
                user.origin(value)

    def test_entry_export_scope_validation(self):
        index = {'deployment_id': 'a' * 64, 'user': {'id': 'b' * 64}}
        saved = {'backup_version': 2, 'format': 'entry-v1',
                 'deployment_id': index['deployment_id'], 'owner_id': index['user']['id'],
                 'collection_id': 'c' * 64,
                 'object': {'head': {'context': {'deployment_id': 'a' * 64,
                                               'collection_id': 'c' * 64}}, 'envelope': '{}'},
                 'handoff': {'handoff_version': 1, 'checkpoint': {}, 'wrappers': [],
                             'package': json.dumps({'recipient_user_id': 'b' * 64})},
                 'entries': {'d' * 64: '{}'}}
        user.validate_collection(saved, index, 'c' * 64)
        for field, value in [('owner_id', 'e' * 64), ('deployment_id', 'e' * 64),
                             ('entries', {'invalid': '{}'}), ('format', 'unknown')]:
            changed = {**saved, field: value}
            with self.assertRaises(ValueError):
                user.validate_collection(changed, index, 'c' * 64)
        saved['handoff']['package'] = json.dumps({'recipient_user_id': 'e' * 64})
        with self.assertRaises(ValueError):
            user.validate_collection(saved, index, 'c' * 64)

    @unittest.skipUnless(os.environ.get('PETIKA_TEST_RESTIC'), 'Set PETIKA_TEST_RESTIC for real repository tests')
    def test_encrypted_roundtrip_and_repository_pin(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            password = root / 'password'
            password.write_text('synthetic repository passphrase')
            password.chmod(0o600)
            client = offsite.Restic(os.environ['PETIKA_TEST_RESTIC'], str(root/'repository'), password, allow_local=True)
            client.run('init', '--repository-version', '2')
            identity = client.identity(required=False)
            client.repository_id = '0'*64
            with self.assertRaises(ValueError):
                client.identity()
            client.repository_id = identity
            for name in backup.ROOTS:
                (root/name).mkdir()
                (root/name/'synthetic').write_text('synthetic sensitive server configuration')
            args = argparse.Namespace(**{n:root/n for n in backup.ROOTS}, output=root/'bundle', release='test', offline=True)
            backup.create(args)
            offsite.publish(client, args.output, 'synthetic', root/'receipt.json')
            receipt = json.loads((root/'receipt.json').read_text())
            saved = client.snapshot(receipt['snapshot_id'])
            client.download(saved, root/'restored')
            self.assertEqual(backup.verify(args.output), backup.verify(root/'restored'))
            with self.assertRaises(ValueError):
                offsite.publish(client, args.output, 'synthetic', root/'receipt.json')
            client.run('check', '--read-data')
            before = client.run('--json','snapshots')
            client.run('forget','--dry-run','--keep-last','1')
            self.assertEqual(before, client.run('--json','snapshots'))
            password.write_text('wrong password')
            with self.assertRaises(ValueError):
                client.identity()

    @unittest.skipUnless(os.environ.get('PETIKA_TEST_API'), 'Set PETIKA_TEST_API for native HTTP integration')
    def test_real_api_and_recovery(self):
        import secrets
        from test_backup_recovery import Server, cli, run, CLI, PASSWORD, PASSPHRASE, IDENTITY
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            home = root/'server'
            (home/'config').mkdir(parents=True)
            (home/'config/token').write_text(secrets.token_hex(32))
            (home/'config/password').write_text(PASSWORD)
            # This test exercises API-exported backups, not Git history. A mirror
            # pass holds the backup gate and can deliberately return HTTP 503 to
            # concurrent API requests. Git recovery has its own drill coverage.
            server = Server(home, provision=True, mirror=False)
            try:
                client = root/'client'
                account = server.login(client)
                cli(client, ['keys','enroll'], [IDENTITY,IDENTITY,PASSWORD], identity=True)
                groups=[]
                for mode in ('standard','hybrid-post-quantum'):
                    group=server.api('/v1/admin/groups', {'name':mode,'members':[{'user_id':account['id'],'edit':True}]})
                    store=client/(mode+'.petika')
                    cli(client,['init','--encryption',mode],[PASSPHRASE,PASSPHRASE],store)
                    cli(client,['put','offsite-test','--password-stdin'],[PASSPHRASE,'synthetic secret'],store)
                    cli(client,['push','--collection',group['id'],'--revision','0'],[PASSPHRASE],store)
                    cli(client,['keys','migrate','--collection',group['id']],[IDENTITY,PASSPHRASE,PASSPHRASE,PASSPHRASE],identity=True)
                    cli(client,['keys','rotate','--collection',group['id']],[IDENTITY,PASSPHRASE,PASSPHRASE],identity=True)
                    groups.append(group)
                key=server.api('/v1/backup-settings/keys',{'name':'runner','expires_in_days':1,'current_password':PASSWORD})
                keyfile=root/'key'; keyfile.write_text(key['token']); keyfile.chmod(0o600)
                reader=user.API(server.origin,keyfile)
                for forbidden in ('/v1/admin/users','/v1/backup-settings/keys','/v1/backup-settings/operator/destinations'):
                    with self.assertRaises(ValueError):
                        reader.get(forbidden)
                bundle=root/'user-backup'
                user.fetch(reader,bundle)
                if os.environ.get('PETIKA_TEST_RESTIC'):
                    password=root/'repository-password'; password.write_text('synthetic password'); password.chmod(0o600)
                    remote=offsite.Restic(os.environ['PETIKA_TEST_RESTIC'],str(root/'repository'),password,allow_local=True)
                    remote.run('init','--repository-version','2')
                    remote.repository_id=remote.identity(required=False)
                    offsite.publish(remote,bundle,'user-test',root/'receipt.json')
                for group in groups:
                    saved=json.loads((bundle/'collections'/(group['id']+'.json')).read_text())
                    self.assertTrue(saved['packages'])
                    self.assertTrue(all(p['recipient_user_id']==account['id'] for p in saved['packages']))
                    output=root/(group['id']+'.petika')
                    run(['python3',Path(user.__file__),'--recover-from',bundle,'--collection',group['id'],'--output',output,'--cli',CLI,'--passphrase-stdin'],[PASSPHRASE])
                    self.assertIn('offsite-test',run([CLI,'--store',output,'--passphrase-stdin','list'],[PASSPHRASE]))
                server.api('/v1/backup-settings/keys/'+key['key']['id'],method='DELETE')
                with self.assertRaises(ValueError):
                    reader.get('/v1/backup/index')
            finally:
                server.stop()

    def test_user_capture_and_tampering(self):
        class API:
            def get(self, path):
                if path.endswith('index'):
                    return {'backup_version':1,'kind':'user','deployment_id':'a'*64,
                            'user':{'id':'b'*64},'identity':None,'collections':[{'id':'c'*64}]}
                return {'backup_version':1,'collection_id':'c'*64,'snapshot':None}
        with tempfile.TemporaryDirectory() as temporary:
            target=Path(temporary)/'bundle'
            user.fetch(API(), target)
            user.verify_user_bundle(target)
            with self.assertRaises(ValueError):
                user.fetch(API(), target)
            (target/'collections'/('c'*64+'.json')).write_text('{}')
            with self.assertRaises(ValueError):
                user.verify_user_bundle(target)


if __name__ == '__main__':
    unittest.main()
