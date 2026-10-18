#!/usr/bin/env python3
"""Isolated extension QA. Requires Playwright Chromium and built web WASM/server.
Synthetic HTTPS origins are routed to a disposable local API. Test-only host
permission lets automation exercise filling without clicking browser chrome.
"""
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time
import urllib.request
import urllib.error
from playwright.sync_api import sync_playwright, expect

ROOT = Path(__file__).resolve().parents[1]
ORIGIN = 'https://example.test'
API = 'https://petika.fixture.test'
with tempfile.TemporaryDirectory(prefix='petika-extension-') as temp:
    work = Path(temp)
    with socket.socket() as sock:
        sock.bind(('127.0.0.1',0)); port = sock.getsockname()[1]
    base = f'http://127.0.0.1:{port}'
    (work/'token').write_text('syntheticBootstrapTokenForExtensionQA1234567890')
    env = {**os.environ,'PETIKA_DATA_DIR':str(work/'data'),'PETIKA_TOKEN_FILE':str(work/'token'),'PETIKA_LISTEN':f'127.0.0.1:{port}','PETIKA_SETUP_MODE':'manual','PETIKA_COOKIE_SECURE':'false'}
    server = subprocess.Popen([str(ROOT/'target/debug/petika-server')],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
    def api(path, body=None, cookie=None, method=None, extra=None):
        headers={'Content-Type':'application/json','X-Petika-Request':'1',**(extra or {})}
        if cookie: headers['Cookie']=cookie
        req=urllib.request.Request(base+path,data=None if body is None else (body.encode() if isinstance(body,str) else json.dumps(body).encode()),headers=headers,method=method)
        return urllib.request.urlopen(req,timeout=10)
    try:
        for _ in range(100):
            try: api('/healthz').close();break
            except OSError: time.sleep(.1)
        if server.poll() is not None: raise RuntimeError(server.stderr.read().decode())
        api('/v1/auth/bootstrap',{'token':'syntheticBootstrapTokenForExtensionQA1234567890','username':'admin','name':'QA','password':'synthetic account password'}).close()
        response=api('/v1/auth/login',{'username':'admin','password':'synthetic account password'})
        user=json.load(response); cookie=response.headers['Set-Cookie'].split(';')[0]
        api('/v1/auth/websites',{'origin':ORIGIN,'allow':True},cookie).close()
        package=work/'extension'
        subprocess.run(['python3',str(ROOT/'scripts/build_extension.py'),'--endpoint',API,'--output',str(package)],check=True)
        manifest=json.loads((package/'manifest.json').read_text())
        manifest['host_permissions'].append(ORIGIN+'/*')
        (package/'manifest.json').write_text(json.dumps(manifest))
        with sync_playwright() as p:
            context=p.chromium.launch_persistent_context(str(work/'profile'),channel='chromium',headless=True,args=[f'--disable-extensions-except={package}',f'--load-extension={package}'])
            errors=[]
            def route(r):
                if r.request.url.startswith(API):
                    # Preserve extension Fetch Metadata/Origin: this also checks the
                    # existing API's CSRF handling of privileged extension fetches.
                    headers={k:v for k,v in r.request.headers.items() if k.lower() in ['authorization','content-type','x-petika-request','sec-fetch-site','origin']}
                    req=urllib.request.Request(base+r.request.url[len(API):], data=r.request.post_data_buffer,headers=headers,method=r.request.method)
                    try: res=urllib.request.urlopen(req,timeout=10)
                    except urllib.error.HTTPError as e: res=e
                    return r.fulfill(status=res.status,body=res.read(),headers={'Content-Type':res.headers.get('Content-Type','application/json')})
                if r.request.url.startswith(ORIGIN):
                    return r.fulfill(content_type='text/html',body='<html><body><form><input name="username" autocomplete="username"><input name="password" type="password" autocomplete="current-password"><input name="otp" autocomplete="one-time-code"><button type="submit">Sign in</button></form></body></html>')
                r.continue_()
            context.route('**/*',route)
            worker=context.service_workers[0] if context.service_workers else context.wait_for_event('serviceworker')
            extension_id=worker.url.split('/')[2]
            popup=context.new_page();popup.on('pageerror',lambda e:errors.append(str(e)))
            popup.set_viewport_size({'width':400,'height':740})
            popup.goto(f'chrome-extension://{extension_id}/popup.html')
            popup.get_by_role('button',name='Connect to Petika',exact=True).click()
            expect(popup.locator('#code')).not_to_have_text('')
            code=popup.locator('#code').inner_text()
            api('/v1/auth/device/approve',{'user_code':code,'password':'synthetic account password','approve':True},cookie).close()
            popup.get_by_role('button',name='Finish connecting',exact=True).click()
            expect(popup.locator('#unlock')).to_be_visible()
            # Create a synthetic encrypted collection using the packaged WASM.
            snapshot=popup.evaluate('''async () => {
                const w=new Worker('./worker.js',{type:'module'}); let id=0;
                const call=(action,...args)=>new Promise((resolve,reject)=>{w.onmessage=({data})=>data.error?reject(Error(data.error)):resolve(data.value);w.postMessage({id:++id,action,args});});
                await call('create','synthetic collection password',false);
                await call('put','QA login',{username:'qa-user',password:'synthetic vault password',url:'https://example.test',notes:'',otp:'JBSWY3DPEHPK3PXP'},false);
                const value=await call('seal'); w.terminate(); return value;
            }''')
            api(f'/v1/collections/{user["id"]}/snapshot',snapshot,cookie,method='PUT',extra={'If-Match':'"0"'}).close()
            target=context.new_page();target.goto(ORIGIN)
            # Evaluate click without switching the browser's active tab to the test popup tab.
            popup.locator('#passphrase').fill('synthetic collection password')
            target.bring_to_front()
            popup.evaluate("document.querySelector('#unlock').requestSubmit()")
            expect(popup.get_by_role('button',name='Fill login',exact=True)).to_be_visible(timeout=30000)
            (ROOT/'output/extension-qa').mkdir(parents=True,exist_ok=True)
            popup.screenshot(path=str(ROOT/'output/extension-qa/popup.png'))
            popup.evaluate("[...document.querySelectorAll('button')].find(b=>b.textContent==='Fill login').click()")
            expect(target.locator('[name=password]')).to_have_value('synthetic vault password')
            expect(target.locator('[name=username]')).to_have_value('qa-user')
            # Wait out the last five seconds of the TOTP period, then request a fresh code.
            if int(time.time())%30>=24: time.sleep(31-int(time.time())%30)
            popup.evaluate("[...document.querySelectorAll('button')].find(b=>b.textContent==='Fill code').click()")
            expect(target.locator('[name=otp]')).to_have_value(__import__('re').compile(r'^\d{6}$'))
            assert target.url==ORIGIN+'/'
            # Revoked permissions stop later fills even with an already-unlocked vault.
            target.locator('[name=password]').fill('')
            api('/v1/auth/websites',{'origin':ORIGIN,'allow':False},cookie).close()
            popup.evaluate("[...document.querySelectorAll('button')].find(b=>b.textContent==='Fill login').click()")
            expect(popup.locator('#message')).to_contain_text('Allow this exact website')
            expect(target.locator('[name=password]')).to_have_value('')
            api('/v1/auth/websites',{'origin':ORIGIN,'allow':True},cookie).close()
            # A new document on the same origin must still require reopening/unlocking.
            target.reload()
            popup.evaluate("[...document.querySelectorAll('button')].find(b=>b.textContent==='Fill login').click()")
            expect(popup.locator('#message')).to_contain_text('Website changed')
            expect(target.locator('[name=password]')).to_have_value('')
            # Reopen the collection on the new document, then revoke the approved client.
            popup.evaluate("document.querySelector('#lock').click()")
            popup.locator('#passphrase').fill('synthetic collection password')
            target.bring_to_front()
            popup.evaluate("document.querySelector('#unlock').requestSubmit()")
            expect(popup.get_by_role('button',name='Fill login',exact=True)).to_be_visible(timeout=30000)
            clients=json.load(api('/v1/auth/clients',cookie=cookie))['clients']
            client=next(c for c in clients if c['kind']=='CLI')
            api('/v1/auth/clients/revoke',{'id':client['id']},cookie).close()
            popup.evaluate("[...document.querySelectorAll('button')].find(b=>b.textContent==='Fill login').click()")
            expect(popup.locator('#message')).to_contain_text('Account session revoked')
            expect(target.locator('[name=password]')).to_have_value('')
            # Test the actual serialized fill function against hostile DOM layouts.
            fill_source=(ROOT/'clients/extension/fill.mjs').read_text().split('export function fillPage',1)[1]
            fill_js='function fillPage'+fill_source
            def fill_dom(kind='login', expiry=None):
                return target.evaluate("(args) => { try { return {ok:("+fill_js+")(...args)}; } catch(e) { return {error:e.message}; } }",[ORIGIN,kind,{'username':'qa','password':'synthetic','code':'123456'},expiry or int(time.time()*1000)+5000])
            for markup in [
                '<input type="password" style="display:none">',
                '<div style="opacity:0"><input type="password"></div>',
                '<input type="password"><input type="password">',
                '<form action="https://evil.test"><input type="password"></form>',
                '<input type="password" readonly>',
                '<input type="password" autocomplete="new-password">',
                '<input type="password" style="position:absolute;left:-1000px">',
                '<input type="password"><div style="position:fixed;inset:0;background:white"></div>',
            ]:
                target.set_content(markup)
                assert 'error' in fill_dom(),markup
                assert target.locator('input').evaluate_all('(els)=>els.every(el=>el.value.length===0)')
            target.set_content('<input autocomplete="one-time-code" maxlength="1"><input autocomplete="one-time-code" maxlength="1">')
            assert 'error' in fill_dom('otp')  # Split codes are not yet supported.
            target.set_content('<input autocomplete="one-time-code">')
            assert 'error' in fill_dom('otp',1)  # Expired fill request.
            target.set_content('<iframe srcdoc="<input type=password>"></iframe>')
            frame=target.frames[1]
            assert frame.evaluate("() => { try { ("+fill_js+")('https://example.test','login',{username:'qa',password:'synthetic'},Date.now()+5000); return false; } catch { return true; } }")
            # Inspect session storage: never persist passphrases or decrypted vault contents.
            stored=popup.evaluate('chrome.storage.session.get(null)')
            assert set(stored)=={'token','endpoint'}
            assert stored['endpoint']==API
            assert 'synthetic' not in json.dumps(stored)
            assert popup.evaluate('chrome.storage.local.get(null)')=={}
            # A rebuilt package pointed at a different server must not reuse its token.
            popup.evaluate("chrome.storage.session.set({endpoint:'https://different.test'})")
            popup.reload()
            expect(popup.locator('#connect')).to_be_visible()
            assert popup.evaluate('chrome.storage.session.get(null)')=={}
            assert not errors,errors
            context.close()
        print('Extension pairing, packaged WASM unlock, login/TOTP fill, permission revocation, document binding and storage checks passed.')
    finally:
        server.terminate();server.wait(timeout=10)
