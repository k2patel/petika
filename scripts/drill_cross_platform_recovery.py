#!/usr/bin/env python3
"""Restore synthetic Mac/native recovery kits on a separate Linux Kubernetes host.

Creates a disposable namespace with no production data volumes. Copies only the named
registry pull secret, never application credentials. Requires an opt-in QA CLI image.
"""
import argparse
from datetime import datetime, timezone
import json
import platform
from pathlib import Path
import secrets
import subprocess
import tarfile
import tempfile

import user_backup


def run(*args, data=None):
    result = subprocess.run(args, input=data, capture_output=True, timeout=90)
    if result.returncode:
        raise RuntimeError('Cross-platform command failed: ' + ' '.join(args[:5]) + '\n' + result.stderr.decode()[-2000:])
    return result.stdout


def drill(args):
    if args.output.exists():
        raise ValueError('Evidence output exists')
    for mode in ['standard', 'hybrid-post-quantum']:
        user_backup.verify_user_bundle(args.kits / mode / 'bundle')
        evidence = json.loads((args.kits / mode / 'evidence.json').read_text())
        if evidence['mode'] != mode or evidence['entries'] != 65 or evidence['ciphertext_bytes'] <= 16 * 1024 * 1024:
            raise ValueError('Expected synthetic large-vault recovery kit')
    namespace = 'petika-recovery-qa-' + secrets.token_hex(4)
    run('kubectl', 'create', 'namespace', namespace)
    try:
        credential = json.loads(run('kubectl', '-n', args.registry_namespace, 'get', 'secret', args.registry_secret, '-o', 'json'))
        secret = {'apiVersion': 'v1', 'kind': 'Secret', 'metadata': {'name': 'registry', 'namespace': namespace},
                  'type': credential['type'], 'data': credential['data']}
        run('kubectl', 'create', '-f', '-', data=json.dumps(secret).encode())
        del credential, secret
        pod = {'apiVersion': 'v1', 'kind': 'Pod', 'metadata': {'name': 'restore', 'namespace': namespace},
               'spec': {'restartPolicy': 'Never', 'imagePullSecrets': [{'name': 'registry'}],
                        'securityContext': {'runAsNonRoot': True, 'runAsUser': 65532, 'runAsGroup': 65532, 'fsGroup': 65532},
                        'containers': [{'name': 'restore', 'image': args.image,
                                        'command': ['python3', '-c', 'import time; time.sleep(3600)'],
                                        'resources': {'requests': {'memory': '128Mi', 'cpu': '100m'},
                                                      'limits': {'memory': '768Mi', 'cpu': '2'}},
                                        'securityContext': {'allowPrivilegeEscalation': False,
                                                            'capabilities': {'drop': ['ALL']}},
                                        'volumeMounts': [{'name': 'work', 'mountPath': '/work'}]}],
                        'volumes': [{'name': 'work', 'emptyDir': {'sizeLimit': '1Gi'}}]}}
        run('kubectl', 'create', '-f', '-', data=json.dumps(pod).encode())
        print('Disposable Linux recovery pod created; waiting for image readiness.', flush=True)
        for attempt in range(10):
            result = subprocess.run(['kubectl', '-n', namespace, 'wait', '--for=condition=Ready', 'pod/restore', '--timeout=30s'],
                                    capture_output=True, timeout=40)
            if result.returncode == 0:
                break
            if attempt == 9:
                raise RuntimeError('Linux recovery pod did not become ready')
        pod = json.loads(run('kubectl', '-n', namespace, 'get', 'pod', 'restore', '-o', 'json'))
        image_id = pod['status']['containerStatuses'][0]['imageID']
        remote = ['kubectl', '-n', namespace, 'exec', '-i', 'restore', '--']
        with tempfile.TemporaryFile() as archive:
            with tarfile.open(fileobj=archive, mode='w') as stream:
                stream.add(args.kits, arcname='kits')
            archive.seek(0)
            extract = subprocess.run([*remote, 'python3', '-c',
                "import sys,tarfile; tarfile.open(fileobj=sys.stdin.buffer,mode='r|').extractall('/work',filter='data')"],
                stdin=archive, capture_output=True, timeout=120)
            if extract.returncode:
                raise RuntimeError('Synthetic kit transfer failed')
        print('Synthetic encrypted kits transferred; verifying both profiles without an API session.', flush=True)
        program = r'''
import hashlib,json,os,platform,subprocess,sys
from pathlib import Path
sys.path.insert(0, '/usr/share/petika/scripts')
import user_backup
results = []
for mode in ['standard', 'hybrid-post-quantum']:
    root = Path('/work/kits') / mode
    evidence = json.loads((root / 'evidence.json').read_text())
    pin, identity = root / 'kit/pin.json', root / 'kit/identity.json'
    before = pin.read_bytes()
    assert hashlib.sha256(before).hexdigest() == evidence['pin_sha256']
    saved = root / 'bundle/collections' / (evidence['collection'] + '.json')
    output = Path('/work/recovered-' + mode)
    base = ['petika', '--no-config', '--passphrase-stdin', 'entries', 'recover-backup',
            '--backup', str(saved), '--pin', str(pin), '--recipient-identity', str(identity)]
    wrong = subprocess.run(base + ['--output', str(output)], input='wrong synthetic passphrase\n', text=True, capture_output=True)
    assert wrong.returncode and not output.exists() and pin.read_bytes() == before
    result = subprocess.run(base + ['--output', str(output)], input='synthetic identity passphrase\n', text=True, capture_output=True)
    if result.returncode: raise RuntimeError(result.stderr)
    marker = json.loads((output / 'RECOVERY.json').read_text())
    assert marker['entries'] == evidence['entries'] and pin.read_bytes() == before
    verified = subprocess.run(['petika','--no-config','--passphrase-stdin','entries','verify-backup',
        '--anchor',str(output / marker['anchor']), '--pin',str(pin),'--cache',str(output),
        '--handoff',str(output / 'handoff.json'),'--recipient-identity',str(identity)],
        input='synthetic identity passphrase\n',text=True,capture_output=True)
    if verified.returncode: raise RuntimeError(verified.stderr)
    user_backup.verify_user_bundle(root / 'bundle')
    results.append({**evidence, 'recovered_entries':marker['entries'], 'pin_unchanged':True,
                    'wrong_key_rejected':True,'source_bundle_verified':True})
print(json.dumps({'system':platform.system(),'architecture':platform.machine(),
                  'release':os.environ.get('PETIKA_BACKUP_RELEASE'),'results':results}))
'''
        # The remote program is sent as an argument; passphrases are synthetic fixture constants.
        verification = json.loads(run(*remote, 'python3', '-c', program))
        if verification['system'] != 'Linux':
            raise ValueError('Expected a separate Linux recovery host')
        user_backup.write_json(args.output, {'version': 1, 'created_utc': datetime.now(timezone.utc).isoformat(),
            'source_system': platform.system(), 'source_architecture': platform.machine(),
            'target_image_digest': image_id.rsplit('@', 1)[-1], 'verification': verification,
            'scope': 'synthetic independently retained software identity/pin kits; no hardware/biometric enrollment or production-data restore'})
        print('Cross-platform restore passed for both profiles; evidence recorded.', flush=True)
    finally:
        run('kubectl', 'delete', 'namespace', namespace, '--wait=false')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kits', type=Path, required=True)
    parser.add_argument('--image', required=True)
    parser.add_argument('--registry-namespace', default='petika')
    parser.add_argument('--registry-secret', default='gitea-registry')
    parser.add_argument('--output', type=Path, required=True)
    drill(parser.parse_args())
