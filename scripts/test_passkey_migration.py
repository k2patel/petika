#!/usr/bin/env python3
"""Explicit legacy-to-passkey UI migration with generated data and virtual UV only."""
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import tempfile
import time
from urllib.request import urlopen
from playwright.sync_api import sync_playwright, expect

root=Path(__file__).resolve().parents[1]
for mode in ['standard','hybrid-post-quantum']:
    with tempfile.TemporaryDirectory(prefix='petika-passkey-migration-') as temporary:
        work=Path(temporary);(work/'token').write_text(secrets.token_hex(32))
        old_pass='synthetic old vault passphrase';password='synthetic account password'
        cli=[str(root/'target/debug/petika'),'--no-config','--store',str(work/'original.petika'),'--passphrase-stdin']
        subprocess.run(cli+['init','--encryption',mode],input=old_pass+'\n'+old_pass+'\n',text=True,capture_output=True,check=True)
        subprocess.run(cli+['generate','Example'],input=old_pass+'\n',text=True,capture_output=True,check=True)
        original_ciphertext=(work/'original.petika').read_text()
        with socket.socket() as sock:
            sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
        origin=f'http://localhost:{port}'
        env={**os.environ,'PETIKA_DATA_DIR':str(work/'data'),'PETIKA_TOKEN_FILE':str(work/'token'),
             'PETIKA_WEB_DIR':str(root/'clients/web'),'PETIKA_GIT_MIRROR':str(work/'mirror'),
             'PETIKA_LISTEN':f'127.0.0.1:{port}','PETIKA_ENDPOINT':origin,'PETIKA_COOKIE_SECURE':'false',
             'PETIKA_SETUP_MODE':'auto','PETIKA_ADMIN_USERNAME':'owner','PETIKA_ADMIN_PASSWORD':password,
             'PETIKA_INITIAL_SNAPSHOT_FILE':str(work/'original.petika')}
        for key in ['PETIKA_ADMIN_PASSWORD_FILE','PETIKA_FRESH_VAULT_POLICY']:env.pop(key,None)
        server=subprocess.Popen([str(root/'target/debug/petika-server')],env=env,stdout=subprocess.DEVNULL)
        try:
            for _ in range(100):
                try:urlopen(origin+'/healthz',timeout=1).close();break
                except OSError:time.sleep(.1)
            else:raise AssertionError('Server failed to start')
            db=json.loads((work/'data/accounts.json').read_text());user=db['users'][0]['id']
            folder=work/'data/collections'/user;source=(folder/'snapshot.json').read_bytes()
            with sync_playwright() as p:
                browser=p.chromium.launch();context=browser.new_context(viewport={'width':1440,'height':1100})
                page=context.new_page();errors=[];wire=[]
                page.on('pageerror',lambda e:errors.append(str(e)))
                page.on('request',lambda request:wire.append(request.post_data or '') if '/v1/passkey' in request.url else None)
                cdp=context.new_cdp_session(page);cdp.send('WebAuthn.enable')
                cdp.send('WebAuthn.addVirtualAuthenticator',{'options':{'protocol':'ctap2','ctap2Version':'ctap2_1','transport':'internal','hasResidentKey':True,'hasUserVerification':True,'isUserVerified':True,'automaticPresenceSimulation':True,'hasPrf':True}})
                page.goto(origin);page.get_by_label('Username',exact=True).fill('owner');page.get_by_label('Account password',exact=True).fill(password)
                page.get_by_role('button',name='Sign in',exact=True).click()
                expect(page.get_by_role('heading',name='Unlock Personal')).to_be_visible()
                page.get_by_role('button',name='Settings',exact=True).click()
                page.get_by_role('button',name='Move to passkey protection',exact=True).click()
                expect(page.get_by_role('dialog')).to_be_visible()
                output=root/'output/passkey-migration';output.mkdir(parents=True,exist_ok=True)
                page.screenshot(path=str(output/(mode+'.png')),animations='disabled')
                page.get_by_label('Current vault passphrase',exact=True).fill('wrong synthetic passphrase')
                page.get_by_label('Confirm account password',exact=True).fill(password)
                page.get_by_role('checkbox').check()
                page.get_by_role('button',name='Migrate with passkey',exact=True).click()
                expect(page.get_by_role('dialog').get_by_role('alert')).to_contain_text('incorrect passphrase',timeout=30000)
                assert (folder/'snapshot.json').read_bytes()==source
                assert not (folder/'snapshot.passphrase-backup.json').exists()
                page.get_by_role('button',name='Close dialog',exact=True).click()
                page.get_by_role('button',name='Move to passkey protection',exact=True).click()
                page.get_by_label('Passkey',exact=True).select_option(index=1)
                page.get_by_role('checkbox').check()
                page.get_by_label('Current vault passphrase',exact=True).fill(old_pass)
                held=[]
                page.route('**/v1/passkeys/authentication/start',lambda route:held.append(route))
                with page.expect_request('**/v1/passkeys/authentication/start'):
                    page.get_by_role('button',name='Migrate with passkey',exact=True).click()
                page.get_by_role('button',name='Close dialog',exact=True).click()
                with page.expect_response('**/v1/passkeys/authentication/start'):
                    held.pop().continue_()
                page.unroute('**/v1/passkeys/authentication/start')
                assert (folder/'snapshot.json').read_bytes()==source
                assert not (folder/'snapshot.passphrase-backup.json').exists()
                page.get_by_role('button',name='Move to passkey protection',exact=True).click()
                page.get_by_label('Passkey',exact=True).select_option(index=1)
                page.get_by_role('checkbox').check()
                page.get_by_label('Current vault passphrase',exact=True).fill(old_pass)
                # Lost acknowledgement leaves a ciphertext-only, restartable candidate.
                def lose_reply(route):
                    if route.request.method=='PUT':
                        accepted=route.fetch();assert accepted.status==200;route.abort()
                        page.unroute('**/v1/passkey-vaults/*',lose_reply)
                    else:route.continue_()
                page.route('**/v1/passkey-vaults/*',lose_reply)
                page.get_by_role('button',name='Migrate with passkey',exact=True).click()
                expect(page.get_by_role('dialog').get_by_role('alert')).to_contain_text('fetch',ignore_case=True,timeout=30000)
                pending=page.evaluate("JSON.parse(localStorage.getItem(Object.keys(localStorage).find(k=>k.startsWith('petika-encrypted-'))))")
                assert pending['migration'] is True and pending['dirty'] is True
                assert old_pass not in json.dumps(pending)
                page.reload()
                expect(page.get_by_role('heading',name='Unlock Personal')).to_be_visible()
                page.get_by_role('button',name='Verify and resume encrypted changes',exact=True).click()
                expect(page.get_by_role('button',name='Lock',exact=True)).to_be_visible(timeout=30000)
                assert (folder/'snapshot.passphrase-backup.json').read_bytes()==source
                saved=json.loads((folder/'snapshot.json').read_text());outer=json.loads(saved['encrypted'])
                assert saved['revision']==2 and outer['version']==3
                assert json.loads(outer['encrypted_snapshot'])['encryption']==mode
                assert old_pass not in '\n'.join(wire)
                page.get_by_role('button',name='All items 1',exact=True).click()
                page.get_by_role('button',name='E Example Secure note',exact=True).click()
                page.get_by_role('button',name='Reveal password',exact=True).click()
                expect(page.locator('#password-display')).not_to_have_text('••••••••••••••••')
                assert not errors,errors
                browser.close()
            # Historical source remains usable; the current outer format rejects legacy CLI.
            subprocess.run(cli+['get','Example','--reveal'],input=old_pass+'\n',text=True,capture_output=True,check=True)
            (work/'migrated.petika').write_text(saved['encrypted'])
            denied=subprocess.run([str(root/'target/debug/petika'),'--no-config','--store',str(work/'migrated.petika'),'--passphrase-stdin','get','Example','--reveal'],input=old_pass+'\n',text=True,capture_output=True)
            assert denied.returncode!=0
            print(f'PASS {mode}: wrong-passphrase denial, explicit cutover, fresh passkey reads, lost-reply/reload recovery, exact backup and old-client rejection')
        finally:
            server.terminate();server.wait(timeout=10)
