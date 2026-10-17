#!/usr/bin/env python3
"""Native CLI -> browser/WASM -> native CLI delivery and rotation, both modes."""
import argparse
import http.cookiejar
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import tempfile
import time
import urllib.request
from playwright.sync_api import sync_playwright, expect

ROOT = Path(__file__).resolve().parents[1]
PASSWORD = 'synthetic account password'
IDENTITY = 'synthetic identity passphrase'
RECOVERY = 'synthetic recovery passphrase'
parser = argparse.ArgumentParser()
parser.add_argument('--chrome')
args = parser.parse_args()
with tempfile.TemporaryDirectory(prefix='petika-delivery-') as temporary:
    work = Path(temporary)
    (work/'token').write_text(secrets.token_hex(32))
    (work/'password').write_text(PASSWORD)
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0)); port = sock.getsockname()[1]
    origin = f'http://127.0.0.1:{port}'
    env = {**os.environ, 'PETIKA_DATA_DIR':str(work/'data'), 'PETIKA_TOKEN_FILE':str(work/'token'), 'PETIKA_LISTEN':f'127.0.0.1:{port}', 'PETIKA_COOKIE_SECURE':'false', 'PETIKA_WEB_DIR':str(ROOT/'clients/web'), 'PETIKA_SETUP_MODE':'auto', 'PETIKA_ADMIN_USERNAME':'alice', 'PETIKA_ADMIN_NAME':'Alice', 'PETIKA_ADMIN_PASSWORD_FILE':str(work/'password')}
    server = subprocess.Popen([str(ROOT/'target/debug/petika-server')], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    def api(path, body=None):
        request = urllib.request.Request(origin+path, data=None if body is None else json.dumps(body).encode(), headers={'Content-Type':'application/json','X-Petika-Request':'1'})
        with opener.open(request, timeout=30) as response: return json.load(response)
    def cli(arguments, lines, identity=True, store=None):
        command = [str(ROOT/'target/debug/petika'), '--session-file', str(work/'session.json'), '--passphrase-stdin']
        if identity: command += ['--identity-file', str(identity if isinstance(identity, Path) else work/'identity.json')]
        if store: command += ['--store', str(store)]
        result = subprocess.run(command+arguments, input='\n'.join(lines)+'\n', text=True, capture_output=True, timeout=60)
        if result.returncode: raise AssertionError(f'{arguments}: {result.stderr}')
        return result.stdout
    try:
        for _ in range(100):
            try: api('/v1/auth/status'); break
            except OSError: time.sleep(.1)
        alice = api('/v1/auth/login', {'username':'alice','password':PASSWORD})
        bob = api('/v1/admin/users', {'username':'bob','name':'Bob','password':PASSWORD,'admin':False})
        grant = api('/v1/auth/device/start', {})
        api('/v1/auth/device/approve', {'user_code':grant['user_code'],'password':PASSWORD,'approve':True})
        approved = api('/v1/auth/device/poll', {'device_code':grant['device_code']})
        (work/'session.json').write_text(json.dumps({'version':1,'server':origin,'token':approved['token']})); (work/'session.json').chmod(0o600)
        cli(['keys','enroll'], [IDENTITY,IDENTITY,PASSWORD])
        alice_identity = api('/v1/keys/identity')['public_identity']
        groups = []
        for mode in ['standard','hybrid-post-quantum']:
            group = api('/v1/admin/groups', {'name':mode,'members':[{'user_id':alice['id'],'edit':True},{'user_id':bob['id'],'edit':True}]})
            path = work/(mode+'.petika')
            cli(['init','--encryption',mode], [RECOVERY,RECOVERY], identity=False, store=path)
            cli(['put','shared-login','--password-stdin'], [RECOVERY,'synthetic shared secret'], identity=False, store=path)
            cli(['push','--collection',group['id'],'--revision','0'], [RECOVERY], identity=False, store=path)
            groups.append(group)
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True, **({'executable_path':args.chrome} if args.chrome else {}))
            page = browser.new_page(viewport={'width':1440,'height':1100})
            errors = []; page.on('pageerror', lambda e: errors.append(str(e)))
            page.goto(origin)
            page.get_by_label('Username', exact=True).fill('bob')
            page.get_by_label('Account password', exact=True).fill(PASSWORD)
            page.get_by_role('button', name='Sign in', exact=True).click()
            expect(page.get_by_role('heading', name='Set up Personal')).to_be_visible()
            page.get_by_role('button', name='Settings', exact=True).click()
            page.get_by_role('button', name='Recipient identity', exact=True).click()
            page.get_by_label('Action', exact=True).select_option('enroll')
            page.get_by_label('Identity passphrase (local only)', exact=True).fill(IDENTITY)
            page.get_by_label('Confirm passphrase for first enrollment', exact=True).fill(IDENTITY)
            page.get_by_label('Account password for first enrollment', exact=True).fill(PASSWORD)
            page.get_by_role('button', name='Continue', exact=True).click()
            expect(page.get_by_role('heading', name='Identity unlocked', exact=True)).to_be_visible(timeout=30000)
            bob_identity = api('/v1/keys/users/'+bob['id'])
            cli(['keys','verify','--user',bob['id'],'--fingerprint',bob_identity['fingerprint']], [IDENTITY])
            page.get_by_role('button', name='Close dialog', exact=True).click()
            for group in groups:
                print('Testing', group['name'], flush=True)
                page.get_by_role('button', name='All items', exact=False).click()
                page.get_by_role('button', name=group['name'], exact=True).click()
                # Switching collections clears all worker secrets; unlock the identity again.
                page.get_by_role('button', name='Settings', exact=True).click()
                page.get_by_role('button', name='Recipient identity', exact=True).click()
                page.get_by_label('Identity passphrase (local only)', exact=True).fill(IDENTITY)
                page.get_by_role('button', name='Continue', exact=True).click()
                expect(page.get_by_role('heading', name='Identity unlocked', exact=True)).to_be_visible(timeout=30000)
                page.get_by_role('dialog').get_by_role('button', name='Group access', exact=True).click()
                page.get_by_label('Contact user ID (verification)', exact=True).fill(alice['id'])
                page.get_by_label('Independently confirmed fingerprint (verification)', exact=True).fill(alice_identity['fingerprint'])
                page.get_by_label('Identity passphrase (save trust changes)', exact=True).fill(IDENTITY)
                page.get_by_role('button', name='Apply', exact=True).click()
                expect(page.get_by_role('dialog')).not_to_be_visible(timeout=30000)
                cli(['keys','migrate','--collection',group['id']], [IDENTITY,RECOVERY,RECOVERY,RECOVERY])
                # Reload gets the newly migrated snapshot; identity reopens from encrypted storage.
                page.reload()
                page.get_by_role('button', name=group['name'], exact=True).click()
                page.get_by_role('button', name='Unlock with identity', exact=True).click()
                page.get_by_label('Identity passphrase (local only)', exact=True).fill(IDENTITY)
                page.get_by_role('button', name='Continue', exact=True).click()
                expect(page.get_by_role('button', name='shared-login', exact=False)).to_be_visible(timeout=30000)
                page.get_by_role('button', name='Settings', exact=True).click()
                page.get_by_role('button', name='Group access', exact=True).click()
                page.get_by_label('Action', exact=True).select_option('rotate')
                page.get_by_label('Identity passphrase (save trust changes)', exact=True).fill(IDENTITY)
                page.get_by_label('New recovery passphrase (migration or rotation)', exact=True).fill('rotated recovery passphrase')
                page.get_by_label('Confirm recovery passphrase', exact=True).fill('rotated recovery passphrase')
                page.get_by_role('button', name='Apply', exact=True).click()
                expect(page.get_by_role('dialog')).not_to_be_visible(timeout=30000)
                local = work/(group['name']+'-pulled.petika')
                cli(['keys','pull','--collection',group['id']], [IDENTITY], store=local)
                assert 'synthetic shared secret' in cli(['get','shared-login','--reveal'], [IDENTITY], store=local)
                cli(['put','new-from-cli','--password-stdin'], [IDENTITY,'second shared secret'], store=local)
                access = api('/v1/collections/'+group['id']+'/key-access')
                cli(['keys','push','--collection',group['id'],'--revision',str(access['snapshot_revision'])], [IDENTITY], store=local)

                output = ROOT/'output'/'group-delivery'; output.mkdir(parents=True,exist_ok=True)
                page.get_by_role('button', name='Group access', exact=True).click()
                expect(page.get_by_role('heading', name='Group access', exact=True)).to_be_visible()
                page.screenshot(path=str(output/(group['name']+'.png')), full_page=True)
                page.get_by_role('button', name='Close dialog', exact=True).click()
            recovered = work/'restored-identity.json'
            cli(['keys','restore','--fingerprint',alice_identity['fingerprint']], [IDENTITY], identity=recovered)
            restored_store = work/'restored-group.petika'
            cli(['keys','pull','--collection',groups[-1]['id']], [IDENTITY], identity=recovered, store=restored_store)
            assert 'synthetic shared secret' in cli(['get','shared-login','--reveal'], [IDENTITY], identity=recovered, store=restored_store)
            fresh = browser.new_page()
            fresh.goto(origin)
            fresh.get_by_label('Username', exact=True).fill('bob')
            fresh.get_by_label('Account password', exact=True).fill(PASSWORD)
            fresh.get_by_role('button', name='Sign in', exact=True).click()
            fresh.get_by_role('button', name='Settings', exact=True).click()
            fresh.get_by_role('button', name='Recipient identity', exact=True).click()
            fresh.get_by_label('Identity passphrase (local only)', exact=True).fill(IDENTITY)
            fresh.get_by_label('Trusted fingerprint for restore', exact=True).fill(bob_identity['fingerprint'])
            fresh.get_by_role('button', name='Continue', exact=True).click()
            expect(fresh.get_by_role('heading', name='Identity unlocked', exact=True)).to_be_visible(timeout=30000)
            fresh.close()
            assert not errors, errors
            browser.close()
        print('PASS: CLI enrollment, browser enrollment, mutual verification, native-to-WASM unlock, WASM rotation, WASM-to-native unlock, both modes.')
    finally:
        server.terminate(); server.wait(timeout=10)
