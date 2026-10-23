#!/usr/bin/env python3
"""Filesystem failure tests; native history/access validation uses the real entry drill."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

import backup_delta as delta
import backup_recovery as backup


class DeltaSafety(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.sources = {name: self.root / name for name in backup.ROOTS}
        for path in self.sources.values():
            path.mkdir()
            (path / 'unchanged').write_bytes(b'unchanged baseline')
            (path / 'removed').write_bytes(b'remove me')
        (self.root / 'data/accounts.json').write_text('{"state":"old"}')
        self.base = self.root / 'base'
        backup.create(argparse.Namespace(**self.sources, offline=True, release='test', output=self.base))
        (self.root / 'data/accounts.json').write_text('{"state":"new"}')
        (self.root / 'data/new-record').write_bytes(b'new journal record and receipt')
        (self.root / 'config/removed').unlink()
        (self.root / 'mirror/removed').unlink()
        (self.root / 'mirror/removed').mkdir()
        (self.root / 'mirror/removed/child').write_bytes(b'type change')
        self.capture = argparse.Namespace(**self.sources, offline=True, release='test',
                                          baseline=self.base, output=self.root / 'delta')
        delta.create(self.capture)
        self.manifest = json.loads((self.capture.output / 'delta.json').read_text())
        self.old, self.new = self.root / 'old.json', self.root / 'new.json'
        self.old.write_text('{}')
        self.new.write_text('{}')
        self.args = argparse.Namespace(baseline=self.base, delta=self.capture.output,
                                       output=self.root / 'restored', release='test',
                                       baseline_report=self.old, expected_report=self.new,
                                       expected_delta_sha256=delta.digest((self.capture.output / 'delta.json').read_bytes()),
                                       recovery_tool=Path('unused-native-tool'))

    def native(self):
        exact = {'version': 1, 'exact_match': True, 'collections': [{'status': 'matches'}]}
        newer = {'version': 1, 'exact_match': False,
                 'collections': [{'status': 'retained-head-in-local-history'}]}
        return mock.patch.object(backup.subprocess, 'run', side_effect=[
            subprocess.CompletedProcess([], code, json.dumps(value).encode())
            for code, value in [(0, {}), (0, exact), (2, newer)]])

    def test_reconstruct_changes_deletions_types_and_no_clobber(self):
        unchanged = hashlib.sha256(b'unchanged baseline').hexdigest()
        self.assertFalse((self.args.delta / 'blobs' / unchanged).exists())
        before = {name: backup.inventory(path) for name, path in [('base', self.base), ('delta', self.args.delta)]}
        with self.native():
            delta.replay(self.args)
        for name, source in self.sources.items():
            self.assertEqual(backup.inventory(source), backup.inventory(self.args.output / name))
        marker = json.loads((self.args.output / 'RECONCILIATION.json').read_text())
        self.assertEqual(marker['mode'], 'offline-recovery-delta')
        self.assertEqual(marker['delta_sha256'], self.args.expected_delta_sha256)
        self.assertFalse((self.args.output / 'RESTORE.json').exists())
        self.assertEqual(before, {name: backup.inventory(path) for name, path in [('base', self.base), ('delta', self.args.delta)]})
        with self.assertRaises(ValueError):
            delta.replay(self.args)

    def test_missing_accounts_and_journal_rejected_before_native_audit(self):
        for name in ['accounts.json', 'new-record']:
            blob = self.args.delta / 'blobs' / self.manifest['files']['data'][name]['sha256']
            original = blob.read_bytes()
            blob.unlink()
            with mock.patch.object(backup.subprocess, 'run') as native:
                with self.assertRaises(ValueError):
                    delta.replay(self.args)
                native.assert_not_called()
            self.assertFalse(self.args.output.exists())
            blob.write_bytes(original)

    def test_changed_blob_and_wrong_hash(self):
        self.args.expected_delta_sha256 = '0' * 64
        with self.assertRaises(ValueError):
            delta.replay(self.args)
        self.args.expected_delta_sha256 = delta.digest((self.args.delta / 'delta.json').read_bytes())
        blob = self.args.delta / 'blobs' / self.manifest['files']['data']['new-record']['sha256']
        blob.write_bytes(b'corrupt')
        with self.assertRaises(ValueError):
            delta.replay(self.args)
        self.assertFalse(self.args.output.exists())

    def test_unsafe_paths_and_missing_account_inventory(self):
        for name in ['../outside', '/absolute', 'a/../../outside', 'a\\outside', 'x:y']:
            files = json.loads(json.dumps(self.manifest['files']))
            files['data'][name] = {'directory': True}
            with self.assertRaises(ValueError):
                delta.validate_files(files)
        files = json.loads(json.dumps(self.manifest['files']))
        del files['data']['accounts.json']
        with self.assertRaises(ValueError):
            delta.validate_files(files)

    def test_publication_failure_has_no_completion_marker(self):
        copy = backup.private_copy
        def fail(source, target):
            if target == self.args.output:
                target.mkdir()
                (target / 'partial').write_bytes(b'partial')
                raise OSError('injected failure')
            copy(source, target)
        with self.native(), mock.patch.object(backup, 'private_copy', side_effect=fail):
            with self.assertRaises(OSError):
                delta.replay(self.args)
        self.assertFalse((self.args.output / 'RECONCILIATION.json').exists())
        self.assertFalse((self.args.output / 'RESTORE.json').exists())

    def test_native_rejection_and_incomplete_capture(self):
        with mock.patch.object(backup.subprocess, 'run', return_value=subprocess.CompletedProcess([], 1, b'')):
            with self.assertRaises(ValueError):
                delta.replay(self.args)
        self.assertFalse(self.args.output.exists())
        self.capture.output = self.root / 'failed-capture'
        with mock.patch.object(delta, 'copy_file', side_effect=OSError('injected copy failure')):
            with self.assertRaises(OSError):
                delta.create(self.capture)
        self.assertFalse((self.capture.output / 'delta.json').exists())

    def test_capture_detects_source_mutation(self):
        self.capture.output = self.root / 'mutating-capture'
        copy = delta.copy_file
        def mutate(source, target):
            copy(source, target)
            (self.root / 'data/accounts.json').write_text('{"state":"changed during capture"}')
        with mock.patch.object(delta, 'copy_file', side_effect=mutate):
            with self.assertRaises(ValueError):
                delta.create(self.capture)
        self.assertFalse((self.capture.output / 'delta.json').exists())

    def test_missing_baseline_binding_and_symlink(self):
        changed = dict(self.manifest, baseline_manifest_sha256='0' * 64)
        marker = self.args.delta / 'delta.json'
        marker.write_text(json.dumps(changed))
        self.args.expected_delta_sha256 = delta.digest(marker.read_bytes())
        with self.assertRaises(ValueError):
            delta.replay(self.args)
        self.assertFalse(self.args.output.exists())
        (self.args.delta / 'link').symlink_to(self.root / 'data')
        with self.assertRaises(ValueError):
            delta.replay(self.args)


if __name__ == '__main__':
    unittest.main()
