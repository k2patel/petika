#!/usr/bin/env python3
"""Chunk transport/bundle checks; cryptographic and real API checks use test_entry_chunks."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest

import backup_recovery
import user_backup


class API:
    def __init__(self, fault=None):
        self.fault = fault
        self.manifests = 0
        self.owner, self.collection, self.deployment = 'a' * 64, 'b' * 64, 'c' * 64
        self.index = {'backup_version': 1, 'kind': 'user', 'deployment_id': self.deployment,
                      'user': {'id': self.owner}, 'collections': [{'id': self.collection}]}
        self.envelopes = {f'{n:064x}': f'synthetic encrypted object {n}' for n in range(2)}
        self.saved = {'backup_version': 3, 'format': 'entry-chunks-v1', 'deployment_id': self.deployment,
                      'owner_id': self.owner, 'collection_id': self.collection, 'head_digest': 'd' * 64,
                      'object': {'head': {'revision': 1, 'context': {'deployment_id': self.deployment,
                                                                  'collection_id': self.collection}}, 'envelope': 'index'},
                      'handoff': {'handoff_version': 1, 'checkpoint': {}, 'wrappers': [],
                                  'package': json.dumps({'recipient_user_id': self.owner})},
                      'entries': {entry: {'revision': 1, 'digest': hashlib.sha256(value.encode()).hexdigest()}
                                  for entry, value in self.envelopes.items()}}

    def get(self, path):
        if path.endswith('/index'):
            return copy.deepcopy(self.index)
        if path.endswith('/manifest'):
            self.manifests += 1
            saved = copy.deepcopy(self.saved)
            if self.fault == 'changed-head' and self.manifests > 1:
                saved['head_digest'] = 'e' * 64
            if self.fault == 'unsafe-id':
                saved['entries']['../outside'] = next(iter(saved['entries'].values()))
            return saved
        if '/entries/' in path:
            if self.fault == 'revoked':
                raise ValueError('Backup API returned HTTP 401')
            entry, digest = path.split('/')[-2:]
            return {'backup_version': 3, 'collection_id': self.collection,
                    'head': {'revision': 1, 'digest': self.saved['head_digest']},
                    'entry_id': entry, 'digest': digest,
                    'envelope': 'wrong' if self.fault == 'corrupt' else self.envelopes[entry]}
        raise AssertionError(path)


class ChunkBackup(unittest.TestCase):
    def test_chunk_response_is_bounded_before_json_parsing(self):
        class Response:
            status = 200
            headers = SimpleNamespace(get_content_type=lambda: 'application/json')
            def __enter__(self):
                return self
            def __exit__(self, *args):
                pass
            def read(self, count):
                self.limit = count
                return b' ' * count
        response = Response()
        api = object.__new__(user_backup.API)
        api.server, api.key = 'https://example.invalid', 'synthetic'
        api.opener = SimpleNamespace(open=lambda *args, **kwargs: response)
        with self.assertRaises(ValueError):
            api.get('/v1/backup/collections/id/entries/head/id/digest')
        self.assertEqual(response.limit, 512 * 1024 + 1)

    def test_complete_bundle_and_modified_chunk(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / 'bundle'
            api = API()
            user_backup.fetch(api, output, chunked=True)
            user_backup.verify_user_bundle(output)
            with self.assertRaises(ValueError):
                user_backup.fetch(api, output, chunked=True)
            chunk = next((output / 'collections' / (api.collection + '.entries')).iterdir())
            chunk.write_text('altered')
            # Rewriting the unsigned inventory does not bypass the entry reference digest check.
            manifest = json.loads((output / 'manifest.json').read_text())
            inventory = backup_recovery.inventory(output)
            inventory.pop('manifest.json')
            manifest['files'] = inventory
            (output / 'manifest.json').write_text(json.dumps(manifest))
            with self.assertRaises(ValueError):
                user_backup.verify_user_bundle(output)

    def test_failed_capture_does_not_publish(self):
        for fault in ['revoked', 'corrupt', 'changed-head', 'unsafe-id']:
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as temporary:
                output = Path(temporary) / 'bundle'
                with self.assertRaises(ValueError):
                    user_backup.fetch(API(fault), output, chunked=True)
                self.assertFalse(output.exists())


if __name__ == '__main__':
    unittest.main()
