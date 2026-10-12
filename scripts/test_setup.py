#!/usr/bin/env python3
"""Exercise unattended setup, restart idempotency, and closed setup modes."""
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import tempfile
import time
import urllib.request

root=Path(__file__).resolve().parent.parent
with tempfile.TemporaryDirectory(prefix='petika-setup-') as temporary:
    work=Path(temporary)
    (work/'token').write_text(secrets.token_hex(32))
    (work/'password').write_text('synthetic setup password\n')
    encrypted=work/'initial.petika'
    subprocess.run([str(root/'target/debug/petika'),'--store',str(encrypted),'--passphrase-stdin','init'],input='synthetic collection passphrase\nsynthetic collection passphrase\n',text=True,check=True,capture_output=True)
    with socket.socket() as sock:
        sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
    base={**os.environ,'PETIKA_TOKEN_FILE':str(work/'token'),'PETIKA_DATA_DIR':str(work/'data'),'PETIKA_LISTEN':f'127.0.0.1:{port}','PETIKA_SETUP_MODE':'auto','PETIKA_ADMIN_USERNAME':'owner','PETIKA_ADMIN_NAME':'Test Owner','PETIKA_ADMIN_PASSWORD_FILE':str(work/'password'),'PETIKA_INITIAL_SNAPSHOT_FILE':str(encrypted)}
    def boot(env):
        proc=subprocess.Popen([str(root/'target/debug/petika-server')],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
        for _ in range(100):
            if proc.poll() is not None:raise AssertionError(proc.stderr.read().decode())
            try:
                with urllib.request.urlopen(f'http://127.0.0.1:{port}/v1/auth/status',timeout=1) as r: status=json.load(r)
                return proc,status
            except OSError:time.sleep(.1)
        proc.terminate();raise AssertionError('Server did not start')
    proc,status=boot(base)
    try:assert status['initialized']
    finally:proc.terminate();proc.wait(timeout=5)
    db=json.loads((work/'data/accounts.json').read_text())
    assert db['schema_version']==1
    assert db['users'][0]['username']=='owner'
    snapshot=json.loads((work/'data/collections'/db['users'][0]['id']/'snapshot.json').read_text())
    assert snapshot['encrypted']==encrypted.read_text()
    original=(work/'data/accounts.json').read_bytes()
    proc,status=boot({**base,'PETIKA_ADMIN_USERNAME':'changed','PETIKA_ADMIN_PASSWORD_FILE':'/missing/must-not-be-read','PETIKA_SETUP_MODE':'disabled'})
    try:assert status['initialized']
    finally:proc.terminate();proc.wait(timeout=5)
    assert (work/'data/accounts.json').read_bytes()==original
    for extra in [{'PETIKA_SETUP_MODE':'disabled'}, {'PETIKA_SETUP_MODE':'auto','PETIKA_ADMIN_PASSWORD_FILE':'/missing'}]:
        failed=subprocess.run([str(root/'target/debug/petika-server')],env={**base,'PETIKA_DATA_DIR':str(work/'empty'),**extra},capture_output=True,timeout=10)
        assert failed.returncode!=0
    print('Unattended bootstrap, encrypted initial snapshot, restart idempotency, disabled setup and invalid configuration passed.')
