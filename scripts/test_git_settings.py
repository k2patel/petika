#!/usr/bin/env python3
"""Real API, encrypted settings and fast-forward Git tests using a local transport adapter.
The adapter validates HTTPS/SSH credential isolation, then uses real local bare repositories.
It does not claim a live hosted-provider TLS/SSH integration test.
"""
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
from urllib.request import Request
from urllib.error import HTTPError
from test_backup_recovery import Server, PASSWORD, ROOT
import git_sync


def git(*args, data=None):
    return subprocess.check_output(['git', *map(str,args)], input=data, stderr=subprocess.DEVNULL).decode().strip()


def commit(repo, parent=None):
    blob=git('--git-dir='+str(repo),'hash-object','-w','--stdin',data=b'synthetic encrypted fixture')
    tree=git('--git-dir='+str(repo),'mktree',data=('100644 blob '+blob+'\tsnapshot.json\n').encode())
    oid=git('--git-dir='+str(repo),'-c','user.name=Test','-c','user.email=test@example.com','commit-tree',tree,*(['-p',parent] if parent else []),data=b'Encrypted revision fixture\n')
    git('--git-dir='+str(repo),'update-ref','HEAD',oid)
    return oid


def wait(server, expected):
    deadline=time.monotonic()+40
    while time.monotonic()<deadline:
        value=server.api('/v1/admin/git')
        if value['status'] not in ('queued','running'):
            assert value['status']==expected,value
            return value
        time.sleep(.2)
    raise AssertionError('Git worker did not complete')


with tempfile.TemporaryDirectory(prefix='petika-git-test-') as temporary:
    root=Path(temporary); home=root/'server'; (home/'config').mkdir(parents=True)
    (home/'config/token').write_text(secrets.token_hex(32)); (home/'config/password').write_text(PASSWORD)
    mirror=home/'mirror/repository.git'; mirror.parent.mkdir()
    remote=root/'remote.git'; ssh_remote=root/'ssh.git'
    for path in (mirror,remote,ssh_remote): git('init','--bare',path)
    first=commit(mirror)
    adapter_dir=root/'bin'; adapter_dir.mkdir(); adapter=adapter_dir/'git'
    real_git=shutil.which('git')
    adapter.write_text('#!'+sys.executable+'\n'+f'''
import os,sys,subprocess
from pathlib import Path
args=sys.argv[1:]
assert 'AMBIENT_GIT_SECRET' not in os.environ
assert 'synthetic-git-token' not in ' '.join(args)
assert 'http.sslVerify=true' in args and 'http.followRedirects=false' in args
for i,arg in enumerate(args):
    if arg.startswith(('https://','ssh://')):
        if arg.startswith('https://'):
            helper=os.environ['GIT_ASKPASS']
            assert subprocess.check_output([helper,'Username']).strip()==b'backup-user'
            assert subprocess.check_output([helper,'Password']).strip()==b'synthetic-git-token'
            assert Path(helper).parent.joinpath('token').stat().st_mode & 0o077 == 0
            args[i]={str(remote)!r}
        else:
            command=os.environ['GIT_SSH_COMMAND']
            assert 'StrictHostKeyChecking=yes' in command and 'IdentityAgent=none' in command and 'IdentitiesOnly=yes' in command
            assert 'GIT_ASKPASS' not in os.environ
            args[i]={str(ssh_remote)!r}
        break
else:
    pass
args=[a.replace('protocol.allow=never','protocol.allow=always') for a in args]
sys.exit(subprocess.call([{real_git!r}]+args))
''')
    adapter.chmod(0o700)
    env={'PETIKA_GIT_SYNC_SCRIPT':str(ROOT/'scripts/git_sync.py'),'PETIKA_BACKUP_PYTHON':sys.executable,
         'PATH':str(adapter_dir)+os.pathsep+os.environ['PATH'],'AMBIENT_GIT_SECRET':'must-not-leak'}
    server=Server(home,provision=True,overrides=env)
    try:
        server.api('/v1/admin/git',expected=403)
        server.api('/v1/auth/login',{'username':'alice','password':PASSWORD})
        initial=server.api('/v1/admin/git'); assert initial['status']=='not_configured' and initial['available']
        body={'remote':'https://example.com/owner/backup.git','username':'backup-user','enabled':False,
              'schedule':'manual','interval_minutes':60,'credentials':{'token':'synthetic-git-token'},'current_password':PASSWORD}
        server.api('/v1/admin/git',{**body,'current_password':'wrong'},expected=400)
        for invalid in ['file:///tmp/repo','ext::bad','http://example.com/repo','https://user:token@example.com/repo','ssh://backup-user@-bad/repo']:
            server.api('/v1/admin/git',{**body,'remote':invalid},expected=400)
        saved=server.api('/v1/admin/git',body)
        assert saved['credentials_configured'] and 'synthetic-git-token' not in json.dumps(saved)
        assert b'synthetic-git-token' not in (home/'data/git-sync.json').read_bytes()
        assert (home/'mirror/ui-managed').exists()
        server.api('/v1/admin/git/test',{}); tested=wait(server,'tested'); assert tested['last_test'] and not tested['last_success']
        server.api('/v1/admin/git/sync',{}); synced=wait(server,'synced'); assert synced['last_success'] and synced['repositories']==1
        assert git('--git-dir='+str(remote),'rev-parse','refs/heads/legacy')==first
        # A local successor reaches the remote, preserving ancestry.
        successor=commit(mirror,first)
        server.api('/v1/admin/git/sync',{}); wait(server,'synced')
        assert git('--git-dir='+str(remote),'rev-parse','refs/heads/legacy')==successor
        # A remote descendant cannot be overwritten by a rolled-back source.
        remote_new=git('--git-dir='+str(remote),'-c','user.name=Other','-c','user.email=other@example.com','commit-tree',git('--git-dir='+str(remote),'rev-parse',successor+'^{tree}'),'-p',successor,data=b'Remote-only revision\n')
        git('--git-dir='+str(remote),'update-ref','refs/heads/legacy',remote_new)
        server.api('/v1/admin/git/sync',{}); wait(server,'push_rejected')
        assert git('--git-dir='+str(remote),'rev-parse','refs/heads/legacy')==remote_new
        kept={k:v for k,v in body.items() if k!='credentials'}
        server.api('/v1/admin/git',{**kept,'remote':'https://other.example.com/repo'},expected=400)
        ssh={**body,'remote':'ssh://git@example.com/owner/backup.git','username':'git','credentials':{'ssh_private_key':'-----BEGIN OPENSSH PRIVATE KEY-----\nsynthetic fixture\n-----END OPENSSH PRIVATE KEY-----','ssh_known_hosts':'example.com ssh-ed25519 synthetic-fixture'}}
        server.api('/v1/admin/git',ssh); server.api('/v1/admin/git/sync',{}); wait(server,'synced')
        assert git('--git-dir='+str(ssh_remote),'rev-parse','refs/heads/legacy')==successor
        server.api('/v1/admin/users',{'username':'reader','name':'Reader','password':PASSWORD,'admin':False})
        server.api('/v1/auth/login',{'username':'reader','password':PASSWORD})
        server.api('/v1/admin/git',expected=403); server.api('/v1/admin/git/sync',{},expected=403)
        server.stop(); server=Server(home,provision=False,overrides=env)
        server.api('/v1/auth/login',{'username':'alice','password':PASSWORD})
        assert server.api('/v1/admin/git')['credentials_configured']
        server.api('/v1/admin/git/test',{}); wait(server,'tested')
        # Sealed credential corruption fails closed and never changes remote history.
        config=home/'data/git-sync.json'; original=config.read_bytes(); corrupted=json.loads(original)
        corrupted['sealed'][0] ^= 1; config.write_text(json.dumps(corrupted))
        server.api('/v1/admin/git/sync',{}); wait(server,'failed')
        assert git('--git-dir='+str(ssh_remote),'rev-parse','refs/heads/legacy')==successor
        config.write_bytes(original)
        # Automatic after-change scheduling performs a push without the run endpoint.
        next_commit=commit(mirror,successor)
        auto={k:v for k,v in ssh.items() if k!='credentials'}
        server.api('/v1/admin/git',{**auto,'enabled':True,'schedule':'change'})
        deadline=time.monotonic()+30
        while time.monotonic()<deadline:
            status=server.api('/v1/admin/git')
            if status['status']=='synced' and git('--git-dir='+str(ssh_remote),'rev-parse','refs/heads/legacy')==next_commit: break
            time.sleep(.3)
        else: raise AssertionError('After-change scheduler did not push')
        print('Git settings: admin authorization, encrypted persistence, HTTPS/SSH credential isolation, verified push, divergence rejection and restart passed.')
    finally:
        server.stop()
