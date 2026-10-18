#!/usr/bin/env python3
"""Exercise backup settings against a disposable server in desktop and mobile layouts."""
import os
from pathlib import Path
import secrets
import tempfile
from playwright.sync_api import sync_playwright, expect
from test_backup_recovery import Server, PASSWORD

with tempfile.TemporaryDirectory() as temporary:
    home=Path(temporary)
    (home/'config').mkdir()
    (home/'config/token').write_text(secrets.token_hex(32))
    (home/'config/password').write_text(PASSWORD)
    server=Server(home, provision=True)
    try:
        with sync_playwright() as p:
            browser=p.chromium.launch(headless=True, **({'executable_path':os.environ['PETIKA_TEST_CHROME']} if os.environ.get('PETIKA_TEST_CHROME') else {}))
            page=browser.new_page(viewport={'width':1280,'height':900})
            errors=[]; page.on('pageerror', lambda e:errors.append(str(e)))
            page.goto(server.origin)
            page.get_by_label('Username',exact=True).fill('alice')
            page.get_by_label('Account password',exact=True).fill(PASSWORD)
            page.get_by_role('button',name='Sign in',exact=True).click()
            page.get_by_role('button',name='Settings',exact=True).click()
            page.get_by_role('button',name='Off-site backups',exact=True).click()
            for name,kind,repository in [('External S3','s3','s3:https://storage.example.com/bucket/petika'),('External SSH','sftp','sftp://backup@backup.example.com//backups/petika')]:
                page.get_by_role('button',name='Add S3 or SSH destination').click()
                page.get_by_label('Name',exact=True).fill(name)
                page.get_by_label('Storage type').select_option(kind)
                if kind=='s3':
                    page.get_by_label('Storage endpoint',exact=True).fill('https://storage.example.com')
                    page.get_by_label('Bucket name',exact=True).fill('bucket')
                else:
                    page.get_by_label('SSH host',exact=True).fill('backup.example.com')
                    page.get_by_label('SSH username',exact=True).fill('backup')
                page.get_by_label('Repository encryption password',exact=True).fill('synthetic repository password')
                page.get_by_label('Initialize a new encrypted repository on first run',exact=True).check()
                page.get_by_label('Enable scheduled server push',exact=True).check()
                if kind=='s3':
                    page.get_by_label('S3 access key',exact=True).fill('synthetic-access')
                    page.get_by_label('S3 secret key',exact=True).fill('synthetic-secret')
                else:
                    page.get_by_label('SSH private key',exact=True).fill('-----BEGIN OPENSSH PRIVATE KEY-----\nsynthetic\n-----END OPENSSH PRIVATE KEY-----')
                    page.get_by_label('Verified SSH known_hosts entry',exact=True).fill('backup.example.com ssh-ed25519 synthetic')
                page.get_by_role('button',name='Save destination').click()
                expect(page.get_by_text(name,exact=True)).to_be_visible()
            page.locator('[data-edit-destination="0"]').click()
            expect(page.get_by_label('Repository URL',exact=True)).to_have_value('s3:https://storage.example.com/bucket/petika')
            expect(page.get_by_label('S3 secret key',exact=True)).to_have_value('')
            expect(page.get_by_label('Repository encryption password',exact=True)).to_have_value('')
            page.get_by_role('button',name='Save destination').click()
            page.get_by_role('button',name='Operator full-server destinations').click()
            expect(page.get_by_text('No destinations configured.')).to_be_visible()
            page.get_by_role('button',name='Your backups',exact=True).click()
            page.get_by_role('button',name='Generate backup key',exact=True).click()
            page.get_by_label('Key name').fill('External runner')
            page.get_by_label('Current account password').fill(PASSWORD)
            page.get_by_role('button',name='Generate key',exact=True).click()
            expect(page.get_by_label('Backup API key',exact=True)).to_have_value(__import__('re').compile('pbk_[0-9a-f]{64}_[0-9a-f]{64}'))
            token=page.get_by_label('Backup API key',exact=True).input_value()
            assert token not in page.evaluate('JSON.stringify(localStorage)')
            page.get_by_role('button',name='Done',exact=True).click()
            page.get_by_role('button',name='Off-site backups',exact=True).click()
            expect(page.get_by_text('External runner',exact=True)).to_be_visible()
            page.get_by_role('button',name='Revoke',exact=True).click()
            expect(page.get_by_text('No backup keys.')).to_be_visible()
            page.set_viewport_size({'width':390,'height':844})
            page.emulate_media(color_scheme='dark')
            expect(page.get_by_role('button',name='Add S3 or SSH destination')).to_be_visible()
            assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
            Path('output/backup-settings').mkdir(parents=True,exist_ok=True)
            page.screenshot(path='output/backup-settings/mobile-dark.png')
            assert not errors, errors
            browser.close()
    finally:
        server.stop()
print('Backup Settings browser workflow passed.')
