#!/usr/bin/env python3
"""Server scheduler/capture/credential isolation using real restic and a local transport adapter."""
import json
import os
from pathlib import Path
import secrets
import sys
import tempfile
import time
from urllib.error import HTTPError
from urllib.request import Request
from test_backup_recovery import Server, PASSWORD, ROOT

RESTIC=os.environ['PETIKA_TEST_RESTIC']
with tempfile.TemporaryDirectory(prefix='petika-server-push-') as temporary:
    root=Path(temporary)
    home=root/'server'; (home/'config').mkdir(parents=True)
    (home/'config/token').write_text(secrets.token_hex(32))
    (home/'config/password').write_text(PASSWORD)
    adapter=root/'restic-adapter'
    # Production accepts only S3/SFTP. This test-only executable substitutes local
    # repositories after checking the exact credentials given to the child process.
    adapter.write_text('#!'+sys.executable+'\n'+f'''
import os, sys, subprocess
from pathlib import Path
from urllib.parse import urlsplit
args=sys.argv[1:]
repository=os.environ['RESTIC_REPOSITORY']
if repository.startswith('s3:'):
    assert os.environ['AWS_ACCESS_KEY_ID']=='synthetic-access'
    assert os.environ['AWS_SECRET_ACCESS_KEY']=='synthetic-secret'
    name=urlsplit(repository[3:]).path.strip('/')
else:
    assert repository.startswith('sftp:')
    assert 'AWS_ACCESS_KEY_ID' not in os.environ
    option=args[args.index('-o')+1]
    assert 'StrictHostKeyChecking=yes' in option and 'IdentitiesOnly=yes' in option
    assert '-F /dev/null' in option
    offset=args.index('-o'); del args[offset:offset+2]
    name=urlsplit(repository).path.strip('/')
assert name in ('user-s3','operator-ssh')
failure=Path({str(root)!r})/'fail-once'
if 'backup' in args and failure.exists():
    failure.unlink()
    sys.exit(1)
os.environ['RESTIC_REPOSITORY']=str(Path({str(root)!r})/name)
assert Path(os.environ['RESTIC_PASSWORD_FILE']).stat().st_mode & 0o077 == 0
sys.exit(subprocess.call([{RESTIC!r}]+args))
''')
    adapter.chmod(0o700)
    worker=root/'worker.py'
    worker.write_text("import sys, time, runpy\nsys.path.insert(0, "+repr(str(ROOT/'scripts'))+")\nif sys.argv[1].startswith('capture'): time.sleep(2)\nrunpy.run_path("+repr(str(ROOT/'scripts/server_backup.py'))+",run_name='__main__')\n")
    server=Server(home,provision=True,overrides={
        'PETIKA_BACKUP_SCRIPT':str(worker),
        'PETIKA_BACKUP_PYTHON':sys.executable,
        'PETIKA_BACKUP_RESTIC':str(adapter),
        'PETIKA_BACKUP_RELEASE':'synthetic-release',
        'AWS_ACCESS_KEY_ID':'ambient-credential-must-not-leak'})
    try:
        account=server.login(root/'client')
        (root/'fail-once').write_text('synthetic upload failure')
        capture_busy=[]
        def status(base, destination_id):
            try:
                with server.opener.open(Request(server.origin+base+'destinations')) as response:
                    entries=json.load(response)['destinations']
                return next(d for d in entries if d['id']==destination_id)
            except HTTPError as error:
                if error.code!=503: raise
                capture_busy.append(True)
                assert server.api('/healthz')['status']=='ok'
                return {'status':'capturing'}
        def destination(operator, kind, repository, credentials):
            base='/v1/backup-settings/'+('operator/' if operator else '')
            value=server.api(base+'destinations',{'name':kind,'kind':kind,'repository':repository,
                'enabled':True,'interval_hours':24,'initialize_repository':True,'credentials':credentials})
            assert value['credentials_configured'] and 'credentials' not in value
            server.api(base+'destinations/'+value['id']+'/run',{})
            deadline=time.monotonic()+120
            while time.monotonic()<deadline:
                saved=status(base,value['id'])
                if saved['status'] in ('verified','failed'): break
                time.sleep(.5)
            if kind=='s3':
                assert saved['status']=='failed' and saved['last_success']==0, saved
                assert len(saved['repository_id'])==64 and not saved['initialize_repository']
                server.api(base+'destinations/'+value['id']+'/run',{})
                deadline=time.monotonic()+120
                while time.monotonic()<deadline:
                    saved=status(base,value['id'])
                    if saved['status'] in ('verified','failed'): break
                    time.sleep(.5)
            assert saved['status']=='verified', saved
            assert len(saved['repository_id'])==64 and len(saved['snapshot_id'])==64
            assert saved['last_success']>0 and not saved['initialize_repository']
            return saved
        user=destination(False,'s3','s3:https://offsite.example/user-s3',{
            'repository_password':'synthetic repository password','access_key':'synthetic-access','secret_key':'synthetic-secret'})
        operator=destination(True,'sftp','sftp://backup@offsite.example//operator-ssh',{
            'repository_password':'synthetic repository password','ssh_private_key':'-----BEGIN OPENSSH PRIVATE KEY-----\nsynthetic\n-----END OPENSSH PRIVATE KEY-----',
            'ssh_known_hosts':'offsite.example ssh-ed25519 synthetic'})
        assert capture_busy, 'Capture should reject API work while health remains available'
        disk=(home/'data/backups.json').read_text()
        assert 'synthetic-secret' not in disk and 'synthetic repository password' not in disk
        # Download independently and verify both kinds, including the full-server key/config.
        import offsite_backup as offsite
        password=root/'password'; password.write_text('synthetic repository password'); password.chmod(0o600)
        for value,name,kind in [(user,'user-s3','user'),(operator,'operator-ssh','server')]:
            remote=offsite.Restic(RESTIC,str(root/name),password,value['repository_id'],allow_local=True)
            output=root/(name+'-restore')
            manifest=remote.download(remote.snapshot(value['snapshot_id']),output)
            assert manifest.get('kind','server')==kind
            if kind=='server':
                assert (output/'config/backup-master.key').read_bytes()==(home/'data/backup-master.key').read_bytes()
                assert (output/'config/token').read_bytes()==(home/'config/token').read_bytes()
            else:
                assert set(p.name for p in output.iterdir())=={'index.json','collections','manifest.json'}
                index=json.loads((output/'index.json').read_text())
                assert index['user']['id']==account['id']
                assert 'push' not in index['destinations'][0]
    finally:
        server.stop()
print('Server-owned S3/SSH jobs and independent user/full-server restore checks passed (local transport adapter).')
