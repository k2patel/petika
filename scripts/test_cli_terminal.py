#!/usr/bin/env python3
"""Exercise real hidden prompting and TOTP expiry in a disposable Unix terminal."""
import os
from pathlib import Path
import re
import select
import subprocess
import tempfile
import time

if os.name != 'posix':
    raise SystemExit('This terminal test requires a Unix PTY.')
import pty
import fcntl
import termios
ROOT=Path(__file__).resolve().parents[1]
BINARY=ROOT/'target/debug/petika'
with tempfile.TemporaryDirectory(prefix='petika-cli-terminal-') as temp:
    store=Path(temp)/'vault.petika'
    base=[str(BINARY),'--no-config','--store',str(store)]
    password='synthetic terminal passphrase'
    def setup(args, lines):
        result=subprocess.run(base+['--passphrase-stdin']+args,input='\n'.join(lines)+'\n',text=True,capture_output=True)
        assert result.returncode==0,result.stderr
    setup(['init'],[password,password])
    setup(['insert','Email/test','--password-stdin'],[password,'synthetic-entry-password'])
    setup(['otp','set','Email/test','--secret-stdin'],[password,'JBSWY3DPEHPK3PXP'])
    fd,slave=pty.openpty()
    def terminal_session():
        os.setsid()
        fcntl.ioctl(0,termios.TIOCSCTTY,0)
    child=subprocess.Popen(base+['show','Email/test'],stdin=slave,stdout=slave,stderr=slave,preexec_fn=terminal_session)
    os.close(slave)
    output=b''
    def read_until(needle, timeout=10):
        global output
        deadline=time.monotonic()+timeout
        while needle not in output:
            assert time.monotonic()<deadline,'CLI terminal step timed out'
            if select.select([fd],[],[],.2)[0]:
                chunk=os.read(fd,4096)
                assert chunk,'CLI exited unexpectedly: '+output.decode(errors='replace')
                output+=chunk
    try:
        read_until(b'Passphrase: ')
        assert b'synthetic-entry-password' not in output
        echo_deadline=time.monotonic()+3
        while termios.tcgetattr(fd)[3] & termios.ECHO:
            assert time.monotonic()<echo_deadline,'Hidden prompt did not disable terminal echo'
            time.sleep(.01)
        os.write(fd,(password+'\n').encode())
        read_until(b'Press Enter for a verification code')
        assert b'Password: synthetic-entry-password' in output
        assert password.encode() not in output  # Terminal echo must remain disabled for unlock.
        assert b'TOTP:' not in output
        output=b'';os.write(fd,b'\n')
        read_until(b'Ctrl+C to exit')
        assert re.search(rb'TOTP: \d{6} .*expires in\s+\d+s',output)
        read_until(b'Verification code expired.',timeout=35)
        read_until(b'Press Enter for a verification code')
        os.write(fd,b'q\n')
        deadline=time.monotonic()+5
        while child.poll() is None and time.monotonic()<deadline:
            if select.select([fd],[],[],.1)[0]:
                try:
                    chunk=os.read(fd,4096)
                    if chunk:output+=chunk
                except OSError:break
        assert child.wait(timeout=5)==0
        print('CLI hidden unlock, Enter-to-TOTP, countdown, expiry and exit passed.')
    finally:
        os.close(fd)
        if child.poll() is None:
            child.kill()
            child.wait(timeout=5)
