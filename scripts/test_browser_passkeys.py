#!/usr/bin/env python3
"""Generated-data WebAuthn/PRF browser integration. Virtual authenticator, not biometric evidence."""
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

root = Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory(prefix='petika-passkeys-') as temporary:
    work = Path(temporary)
    (work/'token').write_text(secrets.token_hex(32))
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0)); port = sock.getsockname()[1]
    origin = f'http://localhost:{port}'
    password = 'synthetic passkey account password'
    env = {**os.environ, 'PETIKA_TOKEN_FILE': str(work/'token'),
           'PETIKA_DATA_DIR': str(work/'data'), 'PETIKA_GIT_MIRROR':str(work/'mirror'), 'PETIKA_WEB_DIR': str(root/'clients/web'),
           'PETIKA_LISTEN': f'127.0.0.1:{port}', 'PETIKA_ENDPOINT': origin,
           'PETIKA_COOKIE_SECURE': 'false', 'PETIKA_SETUP_MODE': 'auto',
           'PETIKA_ADMIN_USERNAME': 'owner', 'PETIKA_ADMIN_PASSWORD': password}
    for key in ['PETIKA_ADMIN_PASSWORD_FILE', 'PETIKA_FRESH_VAULT_POLICY']:
        env.pop(key, None)
    server = subprocess.Popen([str(root/'target/debug/petika-server')], env=env, stdout=subprocess.DEVNULL)
    try:
        for _ in range(100):
            try:
                urlopen(origin+'/healthz', timeout=1).close(); break
            except OSError: time.sleep(.1)
        else: raise AssertionError('Server did not start')
        with sync_playwright() as p:
            browser = p.chromium.launch()
            context = browser.new_context(viewport={'width':1440,'height':1000})
            page = context.new_page(); errors = []; requests = []
            page.on('pageerror', lambda e: errors.append(str(e)))
            page.on('request', lambda r: requests.append((r.url, r.post_data)) if '/v1/passkey' in r.url else None)
            cdp = context.new_cdp_session(page)
            cdp.send('WebAuthn.enable')
            authenticator = cdp.send('WebAuthn.addVirtualAuthenticator', {'options': {
                'protocol':'ctap2', 'ctap2Version':'ctap2_1', 'transport':'internal', 'hasResidentKey':True,
                'hasUserVerification':True, 'isUserVerified':True,
                'automaticPresenceSimulation':True, 'hasPrf':True}})['authenticatorId']
            page.goto(origin)
            page.get_by_label('Username', exact=True).fill('owner')
            page.get_by_label('Account password', exact=True).fill(password)
            page.get_by_role('button', name='Sign in', exact=True).click()
            expect(page.get_by_role('heading', name='Set up Personal')).to_be_visible()
            page.get_by_role('radio', name='Biometric only').check()
            expect(page.get_by_role('button', name='Set up passkey protection')).to_be_disabled()
            expect(page.locator('#biometric-policy-status')).to_contain_text('No PIN fallback')
            page.get_by_role('radio', name='Browser passkey').check()
            output = root/'output/passkeys'; output.mkdir(parents=True, exist_ok=True)
            page.screenshot(path=str(output/'setup-both-policies.png'))
            page.get_by_label('Confirm account password', exact=True).fill(password)
            page.get_by_role('button', name='Set up passkey protection').click()
            try:
                expect(page.get_by_role('heading', name='Your secrets, in good company.')).to_be_visible(timeout=15000)
            except Exception:
                print('REQUEST PATHS:', [u for u,b in requests], 'ERRORS:', errors, flush=True)
                raise
            assert not errors, errors
            print('PASS: fresh setup with real WebAuthn verifier and PRF-encrypted bound vault')
            page.get_by_role('button',name='New item',exact=True).click()
            page.get_by_label('Name',exact=True).fill('UI example')
            page.get_by_label('Username',exact=True).fill('ui@example.test')
            page.get_by_label('Password',exact=True).fill('synthetic UI secret')
            def lose_write_reply(route):
                if route.request.method=='PUT':
                    accepted=route.fetch()
                    assert accepted.status==200
                    route.abort()
                    page.unroute('**/v1/passkey-vaults/*',lose_write_reply)
                else: route.continue_()
            page.route('**/v1/passkey-vaults/*',lose_write_reply)
            page.get_by_role('button',name='Save item',exact=True).click()
            page.get_by_role('button',name='Review sync',exact=True).click()
            before_retry=len([u for u,b in requests if u.endswith('/authentication/start')])
            page.get_by_role('button',name='Retry sync',exact=True).click()
            expect(page.get_by_text('Sync checked',exact=True)).to_be_visible()
            assert len([u for u,b in requests if u.endswith('/authentication/start')])==before_retry
            page.get_by_role('button',name='All items 1',exact=True).click()
            print('PASS: lost write reply reconciles ciphertext without replaying approval or duplicating edits')
            page.get_by_role('button',name='View selected item',exact=True).click()
            expect(page.get_by_role('heading',name='UI example',exact=True)).to_be_visible()
            page.get_by_role('button',name='Reveal password',exact=True).click()
            expect(page.locator('#password-display')).to_have_text('synthetic UI secret')
            page.get_by_role('button',name='Lock',exact=True).click()
            expect(page.get_by_role('heading',name='Unlock Personal')).to_be_visible()
            page.get_by_role('button',name='Verify passkey',exact=True).click()
            expect(page.get_by_role('button',name='Lock',exact=True)).to_be_visible()
            # Exercise protected methods directly, while retaining UI coverage above.
            result = page.evaluate('''async () => {
              const {PasskeyClient}=await import('/passkeys.mjs');
              const api=async(path,{method='GET',body}={})=>{const r=await fetch(path,{method,headers:{'Content-Type':'application/json','X-Petika-Request':'1'},body:body===undefined?undefined:JSON.stringify(body)});const value=await r.json();if(!r.ok)throw new Error(JSON.stringify(value));return value};
              const info=await api('/v1/passkeys');const id=info.user_id;
              const current=await api('/v1/passkey-vaults/'+id);
              const scope={origin:location.origin,user_id:id,deployment_id:info.deployment_id,collection_id:id,revision:current.revision};
              const client=new PasskeyClient(api),credential=info.credentials[0].id;
              const edited=await client.run(current.vault,scope,credential,'put',['Example',{username:'synthetic@example.test',password:'synthetic vault secret',url:'https://example.test',notes:'generated',otp:'JBSWY3DPEHPK3PXP'},false]);
              const saved=await api('/v1/passkey-vaults/'+id,{method:'PUT',body:edited.pending});
              const replay=await fetch('/v1/passkey-vaults/'+id,{method:'PUT',headers:{'Content-Type':'application/json','X-Petika-Request':'1'},body:JSON.stringify(edited.pending)});
              scope.revision=saved.revision;
              const shown=await client.run(edited.vault,scope,credential,'reveal-password',['Example']);
              const view=await client.run(edited.vault,scope,credential,'view',['Example']);
              const otp=await client.run(edited.vault,scope,credential,'otp',['Example']);
              return {before:current.revision,after:saved.revision,shown:shown.value,view:view.value,otp:otp.value,replay:replay.status};
            }''')
            assert result['after'] == result['before']+1, result
            assert result['replay']==403, result
            assert result['shown'] == 'synthetic vault secret', result
            assert 'password' not in result['view'], result
            assert len(result['otp']['code']) == 6, result
            assert all('prf' not in (body or '').lower() for url,body in requests if '/authentication/' in url or '/registration/' in url)
            # Add a genuinely independent credential; keep its PRF result in the page only.
            second = cdp.send('WebAuthn.addVirtualAuthenticator', {'options': {
                'protocol':'ctap2', 'ctap2Version':'ctap2_1', 'transport':'usb',
                'hasResidentKey':True, 'hasUserVerification':True, 'isUserVerified':True,
                'automaticPresenceSimulation':True, 'hasPrf':True}})['authenticatorId']
            cdp.send('WebAuthn.setAutomaticPresenceSimulation', {'authenticatorId':authenticator,'enabled':False})
            page.evaluate('''async password=>{
              const {PasskeyClient}=await import('/passkeys.mjs');const {encode,random}=await import('/passkey-crypto.mjs');
              const api=async(path,{method='GET',body}={})=>{const r=await fetch(path,{method,headers:{'Content-Type':'application/json','X-Petika-Request':'1'},body:body===undefined?undefined:JSON.stringify(body)});const value=await r.json();if(!r.ok)throw new Error(JSON.stringify(value));return value};
              const info=await api('/v1/passkeys');const current=await api('/v1/passkey-vaults/'+info.user_id);
              const client=new PasskeyClient(api);const key=await client.enroll(password,'Second synthetic key');const input=encode(random(32));
              const proof=await client.verify(info.user_id,key.credential_id,'prepare-key',current.revision,input);
              window.__passkeyTest={api,client,info,current,key,input,proof};
            }''', password)
            cdp.send('WebAuthn.setAutomaticPresenceSimulation', {'authenticatorId':second,'enabled':False})
            cdp.send('WebAuthn.setAutomaticPresenceSimulation', {'authenticatorId':authenticator,'enabled':True})
            page.evaluate('''async()=>{
              const t=window.__passkeyTest;const scope={origin:location.origin,user_id:t.info.user_id,deployment_id:t.info.deployment_id,collection_id:t.info.user_id,revision:t.current.revision};
              const result=await t.client.run(t.current.vault,scope,t.info.credentials[0].id,'add-key',[],{newCredentialId:t.key.credential_id,newPrf:t.proof.prf.buffer,newInput:t.input});
              const saved=await t.api('/v1/passkey-vaults/'+t.info.user_id,{method:'PUT',body:result.pending});
              scope.revision=saved.revision;t.scope=scope;t.vault=result.vault;
              const shown=await t.client.run(t.vault,scope,t.info.credentials[0].id,'reveal-password',['Example']);
              if(shown.value!=='synthetic vault secret')throw new Error('First credential failed');
            }''')
            cdp.send('WebAuthn.setAutomaticPresenceSimulation', {'authenticatorId':authenticator,'enabled':False})
            cdp.send('WebAuthn.setAutomaticPresenceSimulation', {'authenticatorId':second,'enabled':True})
            page.evaluate('''async()=>{
              const t=window.__passkeyTest;const shown=await t.client.run(t.vault,t.scope,t.key.credential_id,'reveal-password',['Example']);
              if(shown.value!=='synthetic vault secret')throw new Error('Second credential failed');
              delete window.__passkeyTest;
            }''')
            print('PASS: two independent credentials open the same encrypted vault; one-use write replay denied')
            server.terminate(); server.wait(timeout=10)
            server = subprocess.Popen([str(root/'target/debug/petika-server')],env=env,stdout=subprocess.DEVNULL)
            for _ in range(100):
                try:
                    urlopen(origin+'/healthz',timeout=1).close();break
                except OSError: time.sleep(.1)
            page.reload()
            page.get_by_label('Username',exact=True).fill('owner')
            page.get_by_label('Account password',exact=True).fill(password)
            page.get_by_role('button',name='Sign in',exact=True).click()
            expect(page.get_by_role('heading',name='Unlock Personal')).to_be_visible()
            page.get_by_label('Authorized passkey',exact=True).select_option(label='Second synthetic key')
            page.get_by_role('button',name='Verify passkey',exact=True).click()
            expect(page.get_by_role('button',name='Lock',exact=True)).to_be_visible()
            assert len(json.loads((work/'data/passkeys.json').read_text())['credentials'])==2
            assert 'synthetic vault secret' not in (work/'data/passkeys.json').read_text()
            user_id=json.loads((work/'data/accounts.json').read_text())['users'][0]['id']
            mirrored=json.loads(subprocess.check_output(['git','--git-dir',str(work/'mirror'/user_id/'repository.git'),'show','HEAD:snapshot.json'],text=True))
            outer=json.loads(mirrored['encrypted'])
            assert outer['version']==3 and len(outer['protection']['wrappers'])==2
            assert 'synthetic vault secret' not in mirrored['encrypted']
            print('PASS: restart preserves credentials; Git mirror retains ciphertext and both encrypted wrappers')
            assert not errors, errors
            browser.close()
        print('PASS: per-action verification for edit, reveal, view and OTP; PRF never sent to server')
    finally:
        server.terminate(); server.wait(timeout=10)
