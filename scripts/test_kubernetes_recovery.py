#!/usr/bin/env python3
"""Exercise destructive cleanup boundaries without contacting Kubernetes."""
import json
import unittest
from unittest.mock import patch

from drill_kubernetes_recovery import Cluster


class VolumeOwnership(unittest.TestCase):
    def cluster(self, pv='pvc-test-uid', namespace='petika-recovery-test', name='original', uid='test-uid'):
        cluster = Cluster('synthetic-context', 'petika-recovery-test')
        pvc = {'metadata': {'uid': 'test-uid'}, 'spec': {'volumeName': pv}, 'status': {'phase': 'Bound'}}
        volume = {'spec': {'claimRef': {'namespace': namespace, 'name': name, 'uid': uid}}}
        def respond(*arguments, **kwargs):
            if arguments[:2] == ('get', 'pvc'):
                return json.dumps(pvc)
            if arguments[:2] == ('get', 'pv'):
                return json.dumps(volume)
            if arguments[:2] == ('patch', 'pv'):
                return '{}'
            raise AssertionError(arguments)
        cluster.create = lambda document: None
        return cluster, respond

    def test_only_new_matching_volume_gets_delete_policy(self):
        cluster, response = self.cluster()
        with patch.object(cluster, 'kubectl', side_effect=response) as command:
            self.assertEqual(cluster.disposable_volume('original', 'test-storage'), 'pvc-test-uid')
        changes = [call for call in command.call_args_list if call.args[0] == 'patch']
        self.assertEqual(len(changes), 1)
        self.assertEqual(json.loads(changes[0].args[-1]), {'spec': {'persistentVolumeReclaimPolicy': 'Delete'}})

    def test_foreign_or_preexisting_volumes_are_never_modified(self):
        for values in [{'pv': 'existing-static-volume'}, {'namespace': 'petika'},
                       {'name': 'production'}, {'uid': 'other-uid'}]:
            with self.subTest(values=values):
                cluster, response = self.cluster(**values)
                with patch.object(cluster, 'kubectl', side_effect=response) as command:
                    with self.assertRaises(RuntimeError):
                        cluster.disposable_volume('original', 'test-storage')
                self.assertFalse(any(call.args[0] == 'patch' for call in command.call_args_list))
                self.assertFalse(cluster.cleanup_safe)


class PodPermissions(unittest.TestCase):
    def test_remount_preserves_owner_only_restored_files(self):
        cluster = Cluster('test', 'petika-recovery-test')
        documents = []
        cluster.create = documents.append
        cluster.wait = lambda pod: None
        cluster.app('restored', 'new-volume', 'test-image', 'node-b', restored=True)
        cluster.maintenance('worker', {'backup': 'new-backup'}, 'test-python', 'node-b')
        for document in documents:
            security = document['spec']['securityContext']
            self.assertEqual(security['fsGroupChangePolicy'], 'OnRootMismatch')
            self.assertEqual(security['runAsUser'], 65532)


if __name__ == '__main__':
    unittest.main()
