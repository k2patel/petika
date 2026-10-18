#!/usr/bin/env python3
"""Run a synthetic, cross-node restore drill in a newly created Kubernetes namespace."""
import argparse
from datetime import datetime, timezone
import http.cookiejar
import json
from pathlib import Path
import secrets
import re
import shutil
import socket
import subprocess
import tempfile
import time
from urllib.request import build_opener, HTTPCookieProcessor

from test_backup_recovery import CLI, IDENTITY, PASSPHRASE, PASSWORD, ROOT, Server, cli


class Cluster:
    def __init__(self, context, namespace):
        self.context = context
        self.namespace = namespace
        self.volumes = []
        self.cleanup_safe = True

    def kubectl(self, *args, payload=None):
        result = subprocess.run(['kubectl', '--context', self.context, '-n', self.namespace, *args],
                                input=payload, text=True, capture_output=True, timeout=180)
        if result.returncode:
            # Never include stdin: Secret documents can be passed here.
            raise RuntimeError(result.stderr.strip())
        return result.stdout

    def create(self, document):
        return self.kubectl('create', '-f', '-', payload=json.dumps(document))

    def wait(self, pod):
        for _ in range(75):
            saved = json.loads(self.kubectl('get', 'pod', pod, '-o', 'json'))
            status = saved.get('status', {})
            if status.get('phase') in ('Failed', 'Succeeded'):
                raise RuntimeError('Drill pod exited before readiness: ' + pod)
            if any(c.get('type') == 'Ready' and c.get('status') == 'True'
                   for c in status.get('conditions', [])):
                return
            time.sleep(2)
        raise RuntimeError('Drill pod did not become ready: ' + pod)

    def delete_pod(self, pod):
        self.kubectl('delete', 'pod', pod, '--wait=true', '--timeout=90s')

    def maintenance(self, name, claims, helper_image, node):
        self.create({'apiVersion': 'v1', 'kind': 'Pod', 'metadata': {'name': name}, 'spec': {
            'restartPolicy': 'Never', 'automountServiceAccountToken': False,
            'nodeSelector': {'kubernetes.io/hostname': node},
            'securityContext': {'runAsUser': 65532, 'runAsGroup': 65532, 'fsGroup': 65532,
                                'fsGroupChangePolicy': 'OnRootMismatch'},
            'containers': [{'name': 'tools', 'image': helper_image,
                            'command': ['python3', '-c', 'import time; time.sleep(3600)'],
                            'securityContext': {'allowPrivilegeEscalation': False, 'capabilities': {'drop': ['ALL']}},
                            'resources': {'requests': {'cpu': '50m', 'memory': '64Mi'},
                                          'limits': {'cpu': '1', 'memory': '512Mi'}},
                            'volumeMounts': [{'name': key, 'mountPath': '/' + key} for key in claims] +
                                            [{'name': 'tools', 'mountPath': '/tools', 'readOnly': True},
                                             {'name': 'fixture', 'mountPath': '/fixture', 'readOnly': True}]}],
            'volumes': [{'name': key, 'persistentVolumeClaim': {'claimName': value}} for key, value in claims.items()] +
                       [{'name': 'tools', 'configMap': {'name': 'recovery-tools'}},
                        {'name': 'fixture', 'secret': {'secretName': 'synthetic-config'}}]}})
        self.wait(name)

    def python(self, pod, source):
        return self.kubectl('exec', '-i', pod, '--', 'python3', '-', payload=source)

    def app(self, name, claim, image, node, restored=False):
        base = '/state/restored' if restored else '/state'
        env = {'PETIKA_LISTEN': '0.0.0.0:8080', 'PETIKA_DATA_DIR': base + '/data',
               'PETIKA_GIT_MIRROR': base + '/mirror',
               'PETIKA_TOKEN_FILE': base + '/config/token' if restored else '/fixture/token',
               'PETIKA_COOKIE_SECURE': 'false', 'PETIKA_ENDPOINT': '',
               'PETIKA_SETUP_MODE': 'disabled' if restored else 'auto'}
        if not restored:
            env.update(PETIKA_ADMIN_USERNAME='alice', PETIKA_ADMIN_PASSWORD_FILE='/fixture/password')
        self.create({'apiVersion': 'v1', 'kind': 'Pod', 'metadata': {'name': name}, 'spec': {
            'restartPolicy': 'Never', 'automountServiceAccountToken': False,
            'nodeSelector': {'kubernetes.io/hostname': node},
            'securityContext': {'runAsUser': 65532, 'runAsGroup': 65532, 'fsGroup': 65532,
                                'fsGroupChangePolicy': 'OnRootMismatch'},
            'imagePullSecrets': [{'name': 'registry'}],
            'containers': [{'name': 'petika', 'image': image,
                            'env': [{'name': key, 'value': value} for key, value in env.items()],
                            'securityContext': {'readOnlyRootFilesystem': True, 'allowPrivilegeEscalation': False,
                                                'capabilities': {'drop': ['ALL']}},
                            'resources': {'requests': {'cpu': '100m', 'memory': '128Mi'},
                                          'limits': {'cpu': '2', 'memory': '512Mi'}},
                            'readinessProbe': {'httpGet': {'path': '/readyz', 'port': 8080},
                                               'periodSeconds': 2, 'failureThreshold': 30},
                            'volumeMounts': [{'name': 'state', 'mountPath': '/state'},
                                             {'name': 'fixture', 'mountPath': '/fixture', 'readOnly': True},
                                             {'name': 'tmp', 'mountPath': '/tmp'}]}],
            'volumes': [{'name': 'state', 'persistentVolumeClaim': {'claimName': claim}},
                        {'name': 'fixture', 'secret': {'secretName': 'synthetic-config'}},
                        {'name': 'tmp', 'emptyDir': {}}]}})
        self.wait(name)

    def disposable_volume(self, name, storage_class):
        self.create({'apiVersion': 'v1', 'kind': 'PersistentVolumeClaim', 'metadata': {'name': name},
                     'spec': {'storageClassName': storage_class, 'accessModes': ['ReadWriteOnce'],
                              'resources': {'requests': {'storage': '1Gi'}}}})
        for _ in range(100):
            pvc = json.loads(self.kubectl('get', 'pvc', name, '-o', 'json'))
            if pvc.get('status', {}).get('phase') == 'Bound':
                pv = pvc['spec']['volumeName']
                if pv != 'pvc-' + pvc['metadata']['uid']:
                    self.cleanup_safe = False
                    raise RuntimeError('Refusing cleanup changes to a pre-existing/static volume')
                volume = json.loads(self.kubectl('get', 'pv', pv, '-o', 'json'))
                claim = volume['spec']['claimRef']
                if (claim['namespace'], claim['name'], claim['uid']) != (self.namespace, name, pvc['metadata']['uid']):
                    self.cleanup_safe = False
                    raise RuntimeError('Refusing to modify an unrelated persistent volume')
                self.volumes.append(pv)
                # Only this newly provisioned synthetic PVC: ensure cleanup also releases its NFS directory.
                self.kubectl('patch', 'pv', pv, '--type=merge', '-p',
                             json.dumps({'spec': {'persistentVolumeReclaimPolicy': 'Delete'}}))
                return pv
            time.sleep(1)
        raise RuntimeError('Synthetic PVC did not bind')


class ForwardedServer(Server):
    def __init__(self, cluster, pod):
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            port = sock.getsockname()[1]
        self.origin = f'http://127.0.0.1:{port}'
        self.opener = build_opener(HTTPCookieProcessor(http.cookiejar.CookieJar()))
        self.process = subprocess.Popen(['kubectl', '--context', cluster.context, '-n', cluster.namespace,
                                         'port-forward', 'pod/' + pod, f'{port}:8080', '--address=127.0.0.1'],
                                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            for _ in range(100):
                if self.process.poll() is not None:
                    raise RuntimeError('Port-forward failed')
                try:
                    self.api('/healthz')
                    return
                except OSError:
                    time.sleep(.1)
            raise RuntimeError('Port-forward did not become ready')
        except BaseException:
            self.stop()
            raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--context', required=True)
    parser.add_argument('--image', required=True, help='Petika image pinned by sha256 digest')
    parser.add_argument('--source-node', required=True, help='kubernetes.io/hostname label')
    parser.add_argument('--restore-node', required=True)
    parser.add_argument('--storage-class', default='nfs-csi')
    parser.add_argument('--registry-secret-namespace', default='petika')
    parser.add_argument('--registry-secret', default='gitea-registry')
    parser.add_argument('--helper-image', default='python:3.12-slim-bookworm')
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    if not re.fullmatch(r'[^\s]+@sha256:[0-9a-f]{64}', args.image) or args.source_node == args.restore_node:
        parser.error('Use a digest-pinned image and distinct source/restore nodes')
    if not CLI.exists():
        parser.error('Build the native CLI first')
    if args.report.exists():
        parser.error('Report already exists; choose a new path')
    namespace = 'petika-recovery-' + secrets.token_hex(4)
    cluster = Cluster(args.context, namespace)
    storage = json.loads(cluster.kubectl('get', 'storageclass', args.storage_class, '-o', 'json'))
    if storage.get('volumeBindingMode', 'Immediate') != 'Immediate':
        parser.error('This drill requires an Immediate-binding dynamic storage class')
    started = time.monotonic()
    report = {'namespace': namespace, 'context': args.context, 'image': args.image,
              'source_node': args.source_node, 'restore_node': args.restore_node,
              'storage_class': args.storage_class,
              'started_utc': datetime.now(timezone.utc).isoformat(), 'synthetic_only': True,
              'status': 'failed', 'volumes': cluster.volumes}
    created = False
    forward = None
    try:
        cluster.create({'apiVersion': 'v1', 'kind': 'Namespace', 'metadata': {
            'name': namespace, 'labels': {'app.kubernetes.io/part-of': 'petika-recovery-drill'}}})
        created = True
        print(f'Created isolated namespace {namespace}.', flush=True)
        # Copy only the registry pull credential in memory; never print or persist its contents locally.
        source = json.loads(cluster.kubectl('-n', args.registry_secret_namespace, 'get', 'secret',
                                            args.registry_secret, '-o', 'json'))
        cluster.create({'apiVersion': 'v1', 'kind': 'Secret', 'metadata': {'name': 'registry'},
                        'type': source['type'], 'data': source['data']})
        del source
        cluster.create({'apiVersion': 'v1', 'kind': 'Secret', 'metadata': {'name': 'synthetic-config'},
                        'stringData': {'token': secrets.token_hex(32), 'password': PASSWORD,
                                       'runtime.json': json.dumps({'image': args.image})}})
        cluster.create({'apiVersion': 'v1', 'kind': 'ConfigMap', 'metadata': {'name': 'recovery-tools'},
                        'data': {'backup_recovery.py': (ROOT / 'scripts/backup_recovery.py').read_text()}})
        for claim in ['original', 'backup', 'restored']:
            cluster.disposable_volume(claim, args.storage_class)
        with tempfile.TemporaryDirectory(prefix='petika-k8s-client-') as temporary:
            work = Path(temporary)
            original_client = work / 'original'
            cluster.app('original', 'original', args.image, args.source_node)
            report['source_pod_node'] = json.loads(cluster.kubectl('get', 'pod', 'original', '-o', 'json'))['spec']['nodeName']
            forward = ForwardedServer(cluster, 'original')
            user = forward.login(original_client)
            cli(original_client, ['keys', 'enroll'], [IDENTITY, IDENTITY, PASSWORD], identity=True)
            fingerprint = forward.api('/v1/keys/identity')['public_identity']['fingerprint']
            groups = []
            for mode in ['standard', 'hybrid-post-quantum']:
                group = forward.api('/v1/admin/groups', {'name': mode, 'members': [{'user_id': user['id'], 'edit': True}]})
                store = original_client / (mode + '.petika')
                cli(original_client, ['init', '--encryption', mode], [PASSPHRASE, PASSPHRASE], store)
                cli(original_client, ['put', 'kubernetes-recovery', '--password-stdin'],
                    [PASSPHRASE, 'synthetic Kubernetes secret'], store)
                cli(original_client, ['push', '--collection', group['id'], '--revision', '0'], [PASSPHRASE], store)
                cli(original_client, ['keys', 'migrate', '--collection', group['id']],
                    [IDENTITY, PASSPHRASE, PASSPHRASE, PASSPHRASE], identity=True)
                cli(original_client, ['keys', 'rotate', '--collection', group['id']],
                    [IDENTITY, PASSPHRASE, PASSPHRASE], identity=True)
                for _ in range(30):
                    status = forward.api('/v1/collections/' + group['id'] + '/status')
                    if status['mirror_revision'] == status['revision'] == 3:
                        break
                    time.sleep(1)
                else:
                    raise RuntimeError('Synthetic collection mirror did not catch up')
                groups.append(group)
            forward.stop()
            forward = None
            cluster.delete_pod('original')
            print('Original server stopped after both encryption modes migrated and rotated.', flush=True)
            cluster.maintenance('backup-worker', {'source': 'original', 'backup': 'backup'},
                                args.helper_image, args.source_node)
            helper = json.loads(cluster.kubectl('get', 'pod', 'backup-worker', '-o', 'json'))
            report['helper_image_id'] = helper['status']['containerStatuses'][0]['imageID']
            source_code = """from pathlib import Path
import os, subprocess, sys
os.umask(0o077)
config = Path('/tmp/config')
config.mkdir()
for name in ['token', 'password', 'runtime.json']:
    (config/name).write_bytes((Path('/fixture')/name).read_bytes())
subprocess.run([sys.executable, '/tools/backup_recovery.py', 'create', '--offline',
    '--data', '/source/data', '--mirror', '/source/mirror', '--config', str(config),
    '--release', RELEASE, '--output', '/backup/full'], check=True)
""".replace('RELEASE', repr(args.image))
            print(cluster.python('backup-worker', source_code).strip(), flush=True)
            cluster.delete_pod('backup-worker')
            cluster.kubectl('delete', 'pvc', 'original', '--wait=true', '--timeout=90s')
            cluster.kubectl('wait', '--for=delete', 'pv/' + report['volumes'][0], '--timeout=90s')
            shutil.rmtree(original_client)
            report['original_removed_before_restore'] = True
            print('Original synthetic PVC and client removed; restoring on the other node.', flush=True)
            recovery_started = time.monotonic()
            cluster.maintenance('restore-worker', {'backup': 'backup', 'restore': 'restored'},
                                args.helper_image, args.restore_node)
            source_code = """import subprocess, sys
subprocess.run([sys.executable, '/tools/backup_recovery.py', 'verify', '/backup/full'], check=True)
subprocess.run([sys.executable, '/tools/backup_recovery.py', 'restore', '/backup/full',
    '--release', RELEASE, '--output', '/restore/restored'], check=True)
""".replace('RELEASE', repr(args.image))
            print(cluster.python('restore-worker', source_code).strip(), flush=True)
            cluster.delete_pod('restore-worker')
            cluster.app('restored', 'restored', args.image, args.restore_node, restored=True)
            report['restore_pod_node'] = json.loads(cluster.kubectl('get', 'pod', 'restored', '-o', 'json'))['spec']['nodeName']
            assert report['source_pod_node'] != report['restore_pod_node']
            forward = ForwardedServer(cluster, 'restored')
            fresh = work / 'fresh'
            assert forward.login(fresh)['id'] == user['id']
            cli(fresh, ['keys', 'restore', '--fingerprint', fingerprint], [IDENTITY], identity=True)
            for group in groups:
                local = fresh / (group['name'] + '.petika')
                cli(fresh, ['keys', 'pull', '--collection', group['id']], [IDENTITY], local, identity=True)
                assert 'synthetic Kubernetes secret' in cli(fresh, ['get', 'kubernetes-recovery', '--reveal'],
                                                          [IDENTITY], local, identity=True)
                status = forward.api('/v1/collections/' + group['id'] + '/status')
                assert status['revision'] == 3
            report['restore_and_validation_seconds'] = round(time.monotonic() - recovery_started, 2)
            report['checks'] = ['offline backup inventory and hashes', 'original PVC/client removed',
                                'cross-node fresh PVC restore', 'setup disabled on restored server',
                                'account ID preserved', 'fingerprint-verified identity bundle restore',
                                'Standard and Hybrid rotated recipient access and secret decryption',
                                'snapshot revision 3 preserved']
            report['status'] = 'passed'
            print('Cross-node Kubernetes restore and fresh-client decryption passed.', flush=True)
    finally:
        if forward:
            forward.stop()
        if created:
            print('Removing only the temporary drill namespace and its synthetic volumes.', flush=True)
            try:
                if not cluster.cleanup_safe:
                    raise RuntimeError('Namespace retained: unexpected volume ownership requires manual inspection')
                cluster.kubectl('delete', 'namespace', namespace, '--wait=true', '--timeout=150s')
                for pv in report['volumes']:
                    cluster.kubectl('wait', '--for=delete', 'pv/' + pv, '--timeout=90s')
                report['cleanup'] = 'namespace and synthetic PVs deleted'
            except Exception as error:
                report['cleanup'] = str(error)
                report['status'] = 'cleanup-failed'
                raise
            finally:
                report['elapsed_seconds'] = round(time.monotonic() - started, 2)
                args.report.parent.mkdir(parents=True, exist_ok=True)
                with args.report.open('x') as stream:
                    json.dump(report, stream, indent=2)
                    stream.write('\n')
    print('Report:', args.report, flush=True)


if __name__ == '__main__':
    main()
