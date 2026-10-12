#!/usr/bin/env python3
"""Isolated end-to-end test. Requires Python Playwright; no npm dependencies."""
import argparse
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

parser=argparse.ArgumentParser()
parser.add_argument('--chrome', help='Optional existing Chromium/Chrome executable')
parser.add_argument('--screenshots', default='output/web-ui')
args=parser.parse_args()
root=Path(__file__).resolve().parent.parent
screenshots=root/args.screenshots
screenshots.mkdir(parents=True,exist_ok=True)
with tempfile.TemporaryDirectory(prefix='petika-ui-') as temporary:
    work=Path(temporary)
    token=secrets.token_hex(32)
    (work/'token').write_text(token)
    with socket.socket() as sock:
        sock.bind(('127.0.0.1',0)); port=sock.getsockname()[1]
    url=f'http://127.0.0.1:{port}'
    env={**os.environ,'PETIKA_DATA_DIR':str(work/'data'),'PETIKA_GIT_MIRROR':str(work/'mirror'),'PETIKA_TOKEN_FILE':str(work/'token'),'PETIKA_COOKIE_SECURE':'false','PETIKA_LISTEN':f'127.0.0.1:{port}','PETIKA_WEB_DIR':str(root/'clients/web'),'PETIKA_SETUP_MODE':'manual'}
    server=subprocess.Popen([str(root/'target/debug/petika-server')],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    try:
        for _ in range(100):
            try:
                urllib.request.urlopen(url+'/healthz',timeout=1).close();break
            except OSError:time.sleep(.1)
        with sync_playwright() as p:
            browser=p.chromium.launch(headless=True,**({'executable_path':args.chrome} if args.chrome else {}))
            context=browser.new_context(viewport={'width':1440,'height':1000},color_scheme='light')
            page=context.new_page();errors=[]
            page.on('pageerror',lambda e:errors.append(str(e)))
            page.goto(url)
            expect(page.get_by_role('heading',name='Make Petika yours')).to_be_visible()
            page.screenshot(path=str(screenshots/'setup-light.png'))
            page.get_by_label('Setup token',exact=True).fill(token)
            page.get_by_label('Your name',exact=True).fill('Test Administrator')
            page.get_by_label('Username',exact=True).fill('admin')
            page.get_by_label('Create an account password',exact=True).fill('synthetic account password')
            page.get_by_role('button',name='Create administrator',exact=True).click()
            expect(page.get_by_role('heading',name='Set up Personal')).to_be_visible()
            page.get_by_label('Unlock passphrase',exact=True).fill('synthetic encryption passphrase')
            page.get_by_label('Confirm passphrase',exact=True).fill('synthetic encryption passphrase')
            page.get_by_role('button',name='Create encrypted collection',exact=True).click()
            expect(page.get_by_role('heading',name='Your secrets, in good company.')).to_be_visible(timeout=30000)
            page.get_by_role('button',name='New item',exact=True).click()
            page.get_by_label('Name',exact=True).fill('Private / Example login')
            page.get_by_label('Username',exact=True).fill('synthetic@example.test')
            page.get_by_role('button',name='Generate',exact=True).click()
            expect(page.get_by_label('Password',exact=True)).not_to_have_value('')
            expect(page.get_by_role('dialog')).to_be_visible()
            page.get_by_label('Password',exact=True).fill('synthetic secret password')
            page.get_by_label('Website',exact=True).fill('https://example.test')
            page.get_by_label('Verification-code setup key',exact=True).fill('JBSWY3DPEHPK3PXP')
            page.get_by_role('button',name='Save item',exact=True).click()
            expect(page.get_by_role('heading',name='Example login')).to_be_visible()
            expect(page.locator('#otp-code')).not_to_have_text('••• •••')
            page.get_by_role('button',name='Lock',exact=True).click()
            expect(page.get_by_role('heading',name='Unlock Personal')).to_be_visible()
            assert page.get_by_text('synthetic@example.test',exact=True).count()==0
            page.get_by_label('Unlock passphrase',exact=True).fill('wrong passphrase')
            page.get_by_role('button',name='Unlock collection',exact=True).click()
            expect(page.get_by_role('alert')).to_contain_text('incorrect passphrase')
            page.get_by_label('Unlock passphrase',exact=True).fill('synthetic encryption passphrase')
            page.get_by_role('button',name='Unlock collection',exact=True).click()
            expect(page.get_by_role('heading',name='Your secrets, in good company.')).to_be_visible()
            page.get_by_role('button',name='Users',exact=True).click()
            page.get_by_role('button',name='Add user',exact=True).click()
            page.get_by_label('Display name',exact=True).fill('Test Member')
            page.get_by_label('Username',exact=True).fill('member')
            page.get_by_label('Initial account password',exact=True).fill('synthetic member password')
            page.get_by_role('button',name='Create user',exact=True).click()
            expect(page.get_by_role('cell',name='Test Member member')).to_be_visible()
            page.get_by_role('button',name='Groups',exact=True).click()
            page.get_by_role('button',name='Create group',exact=True).click()
            page.get_by_label('Group name',exact=True).fill('Engineering')
            page.get_by_label('Test Administrator',exact=True).select_option('edit')
            page.get_by_label('Test Member',exact=True).select_option('read')
            page.get_by_role('button',name='Save group',exact=True).click()
            expect(page.get_by_role('heading',name='Engineering',exact=True)).to_be_visible()
            page.get_by_role('button',name='All items 1',exact=True).click()
            page.get_by_role('button',name='Engineering',exact=True).click()
            expect(page.get_by_role('heading',name='Set up Engineering')).to_be_visible()
            page.get_by_label('Unlock passphrase',exact=True).fill('synthetic group passphrase')
            page.get_by_label('Confirm passphrase',exact=True).fill('synthetic group passphrase')
            page.locator('input[name="mode"][value="hybrid"]').check()
            page.get_by_role('button',name='Create encrypted collection',exact=True).click()
            expect(page.get_by_role('heading',name='Your secrets, in good company.')).to_be_visible(timeout=30000)
            page.get_by_role('button',name='New item',exact=True).click()
            page.get_by_label('Name',exact=True).fill('Engineering secret')
            page.get_by_label('Password',exact=True).fill('synthetic shared password')
            page.get_by_role('button',name='Save item',exact=True).click()
            expect(page.get_by_role('heading',name='Engineering secret')).to_be_visible()
            users=context.request.get(url+'/v1/admin/users').json()
            owner=next(u for u in users if u['username']=='admin')
            group=context.request.get(url+'/v1/admin/groups').json()[0]
            snapshot=context.request.get(url+f'/v1/collections/{owner["id"]}/snapshot').text()
            for private in ['Private','Example login','synthetic@example.test','synthetic secret password','JBSWY3DPEHPK3PXP']:
                assert private not in snapshot
            encrypted=work/'from-web.petika';encrypted.write_text(snapshot);encrypted.chmod(0o600)
            cli=subprocess.run([str(root/'target/debug/petika'),'--store',str(encrypted),'--passphrase-stdin','get','Private / Example login','--reveal'],input='synthetic encryption passphrase\n',text=True,capture_output=True,check=True)
            assert cli.stdout.strip()=='synthetic secret password'
            member=browser.new_context()
            headers={'Content-Type':'application/json','X-Petika-Request':'1'}
            login=member.request.post(url+'/v1/auth/login',headers=headers,data=json.dumps({'username':'member','password':'synthetic member password'}));assert login.ok
            shared=member.request.get(url+f'/v1/collections/{group["id"]}/snapshot')
            assert shared.ok
            assert shared.json()['encryption']=='hybrid-post-quantum'
            shared_file=work/'shared.petika';shared_file.write_text(shared.text());shared_file.chmod(0o600)
            recovered=subprocess.run([str(root/'target/debug/petika'),'--store',str(shared_file),'--passphrase-stdin','get','Engineering secret','--reveal'],input='synthetic group passphrase\n',text=True,capture_output=True,check=True)
            assert recovered.stdout.strip()=='synthetic shared password'
            assert member.request.get(url+'/v1/admin/users').status==403
            assert member.request.get(url+f'/v1/collections/{owner["id"]}/snapshot').status==403
            assert member.request.put(url+f'/v1/collections/{group["id"]}/snapshot',headers={**headers,'If-Match':'"0"'},data=snapshot).status==403
            assert context.request.post(url+'/v1/profile',data=json.dumps({'name':'CSRF'})).status==403
            assert context.request.post(url+'/v1/admin/user-status',headers=headers,data=json.dumps({'id':next(u['id'] for u in users if u['username']=='member'),'disabled':True})).ok
            assert member.request.get(url+'/v1/collections').status==401
            page.get_by_role('button',name='Settings',exact=True).click()
            page.get_by_role('button',name='Sign out',exact=True).click()
            expect(page.get_by_role('heading',name='Welcome back')).to_be_visible()
            page.get_by_role('button',name='Explore the demo',exact=True).click()
            expect(page.get_by_role('heading',name='GitHub',exact=True)).to_be_visible(timeout=30000)
            expect(page.locator('#otp-code')).not_to_have_text('••• •••')
            page.screenshot(path=str(screenshots/'collection-light.png'))
            page.get_by_role('button',name='Settings',exact=True).click()
            page.get_by_label('Appearance',exact=True).select_option('system')
            context_color=page.evaluate('getComputedStyle(document.documentElement).getPropertyValue("--bg").trim()')
            page.emulate_media(color_scheme='dark')
            assert page.evaluate('getComputedStyle(document.documentElement).getPropertyValue("--bg").trim()')!=context_color
            page.get_by_label('Appearance',exact=True).select_option('light')
            assert page.evaluate('getComputedStyle(document.documentElement).getPropertyValue("--bg").trim()')==context_color
            page.get_by_label('Appearance',exact=True).select_option('dark')
            page.screenshot(path=str(screenshots/'settings-dark.png'))
            page.get_by_role('button',name='All items 5',exact=True).click()
            expect(page.get_by_role('heading',name='GitHub',exact=True)).to_be_visible()
            expect(page.locator('.brand .mark-dark')).to_be_visible()
            expect(page.locator('.brand .mark-light')).not_to_be_visible()
            page.locator('#toast').wait_for(state='hidden')
            page.screenshot(path=str(screenshots/'collection-dark.png'))
            page.set_viewport_size({'width':390,'height':844})
            assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
            page.screenshot(path=str(screenshots/'collection-mobile.png'))
            page.set_viewport_size({'width':1440,'height':1000})
            page.get_by_role('button',name='Groups',exact=True).click()
            expect(page.get_by_role('heading',name='Engineering',exact=True)).to_be_visible()
            page.screenshot(path=str(screenshots/'groups-dark.png'))
            assert not errors,errors
            browser.close()
            print('Passed setup, sign-in, Rust/WASM encryption, OTP, lock/unlock, CLI interoperability, users/groups, read-only access, revocation, CSRF, themes and mobile layout.')
    finally:
        server.terminate();server.wait(timeout=5)
