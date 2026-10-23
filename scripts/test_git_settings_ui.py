#!/usr/bin/env python3
"""Guided Git setup: real API, synthetic worker, responsive browser interaction."""
import os
from pathlib import Path
import secrets
import sys
import tempfile
from playwright.sync_api import sync_playwright, expect
from test_backup_recovery import Server, PASSWORD, ROOT

with tempfile.TemporaryDirectory(prefix='petika-git-ui-') as temporary:
    home=Path(temporary); (home/'config').mkdir(); (home/'mirror').mkdir()
    (home/'config/token').write_text(secrets.token_hex(32)); (home/'config/password').write_text(PASSWORD)
    script=home/'synthetic_worker.py'
    script.write_text('import sys,json\nfrom pathlib import Path\np=json.load(sys.stdin)\nPath(sys.argv[2],"result.json").write_text(json.dumps({"status":"tested" if p["action"]=="test" else "empty"}))\n')
    server=Server(home,provision=True,overrides={'PETIKA_GIT_SYNC_SCRIPT':str(script),'PETIKA_BACKUP_PYTHON':sys.executable})
    try:
        with sync_playwright() as p:
            browser=p.chromium.launch(headless=True)
            page=browser.new_page(viewport={'width':1280,'height':900}); errors=[]
            page.on('pageerror',lambda e:errors.append(str(e)))
            page.goto(server.origin)
            page.get_by_label('Username',exact=True).fill('alice')
            page.get_by_label('Account password',exact=True).fill(PASSWORD)
            page.get_by_role('button',name='Sign in',exact=True).click()
            page.get_by_role('button',name='Settings',exact=True).click()
            page.get_by_role('button',name='Git repository',exact=True).click()
            expect(page.get_by_role('button',name='Test connection',exact=True)).to_be_disabled()
            page.get_by_label('Repository URL',exact=True).fill('https://github.com/example/petika-backup.git')
            page.get_by_label('Git username',exact=True).fill('example')
            page.get_by_label('Git access token',exact=True).fill('synthetic-ui-token')
            page.get_by_label('Current account password',exact=True).fill(PASSWORD)
            page.get_by_role('button',name='Save Git settings',exact=True).click()
            expect(page.get_by_text('Settings saved. Test the connection, then sync.',exact=True)).to_be_visible()
            expect(page.get_by_label('Git access token',exact=True)).to_have_value('')
            assert 'synthetic-ui-token' not in page.evaluate('JSON.stringify(localStorage)')
            page.get_by_role('button',name='Test connection',exact=True).click()
            expect(page.get_by_text('Operation queued. Refresh in a few seconds.',exact=True)).to_be_visible()
            page.wait_for_timeout(5500)
            page.get_by_role('button',name='Refresh status',exact=True).click()
            expect(page.get_by_text('Connection tested: repository is readable. Sync now to verify write access.',exact=True)).to_be_visible()
            page.get_by_label('Connection type',exact=True).select_option('ssh')
            expect(page.get_by_label('SSH private key',exact=True)).to_be_visible()
            expect(page.get_by_label('Git access token',exact=True)).not_to_be_visible()
            expect(page.get_by_role('button',name='Test connection',exact=True)).to_be_disabled()
            page.get_by_label('Repository URL',exact=True).fill('git@example.com:owner/backup.git')
            page.get_by_label('Git username',exact=True).fill('git')
            page.get_by_label('SSH private key',exact=True).fill('-----BEGIN OPENSSH PRIVATE KEY-----\nsynthetic key\n-----END OPENSSH PRIVATE KEY-----')
            page.get_by_label('Verified SSH host keys (known_hosts)',exact=True).fill('example.com ssh-ed25519 synthetic-key')
            page.get_by_label('Current account password',exact=True).fill(PASSWORD)
            page.get_by_label('Sync schedule',exact=True).select_option('periodic')
            page.get_by_label('Interval in minutes',exact=True).fill('30')
            page.get_by_role('button',name='Save Git settings',exact=True).click()
            expect(page.get_by_label('Repository URL',exact=True)).to_have_value('ssh://git@example.com/owner/backup.git')
            expect(page.get_by_label('SSH private key',exact=True)).to_have_value('')
            output=ROOT/'output/git-settings'; output.mkdir(parents=True,exist_ok=True)
            page.screenshot(path=str(output/'desktop-light.png'))
            page.set_viewport_size({'width':390,'height':844});page.emulate_media(color_scheme='dark')
            assert page.evaluate('document.querySelector("#dialog").scrollWidth <= document.querySelector("#dialog").clientWidth')
            page.screenshot(path=str(output/'mobile-dark.png'))
            page.get_by_role('button',name='Close dialog',exact=True).click()
            page.set_viewport_size({'width':1280,'height':900})
            page.get_by_role('button',name='Sync & backup',exact=True).click()
            expect(page.get_by_role('button',name='Git repository',exact=True)).to_be_visible()
            assert not errors, errors
            browser.close()
    finally:
        server.stop()
print('Git settings browser: guided HTTPS/SSH, empty secret fields, test status, dirty form and mobile layout passed.')
