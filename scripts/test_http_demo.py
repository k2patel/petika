#!/usr/bin/env python3
"""Exercise the demo on a real insecure HTTP origin, without backend writes."""
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from playwright.sync_api import sync_playwright, expect

root = Path(__file__).resolve().parents[1]
server = ThreadingHTTPServer(('127.0.0.1', 0), partial(SimpleHTTPRequestHandler, directory=str(root / 'clients/web')))
Thread(target=server.serve_forever, daemon=True).start()
try:
    with sync_playwright() as p:
        browser = p.chromium.launch(args=['--host-resolver-rules=MAP petika.test 127.0.0.1', '--no-proxy-server'])
        page = browser.new_page()
        errors, writes = [], []
        page.on('pageerror', lambda error: errors.append(str(error)))
        page.on('request', lambda request: writes.append(request.url) if request.method not in ('GET', 'HEAD') else None)
        page.goto(f'http://petika.test:{server.server_port}/')
        assert page.evaluate('isSecureContext') is False
        assert page.evaluate('typeof crypto.randomUUID') == 'undefined'
        page.get_by_role('button', name='Explore the demo', exact=True).click()
        expect(page.get_by_role('heading', name='Your secrets, in good company.')).to_be_visible(timeout=30000)
        expect(page.locator('#item-count')).to_have_text('5 items')
        expect(page.locator('#otp-time')).to_have_text('Verification codes require HTTPS or localhost.')
        page.get_by_role('button', name='Reveal password', exact=True).click()
        expect(page.locator('#password-display')).not_to_have_text('••••••••••••••••')
        page.get_by_role('button', name='New item', exact=True).click()
        page.get_by_label('Name', exact=True).fill('HTTP demo test')
        page.get_by_label('Password', exact=True).fill('synthetic demo password')
        page.get_by_role('button', name='Save item', exact=True).click()
        expect(page.locator('#item-count')).to_have_text('6 items')
        assert not errors, errors
        assert not writes, writes
        browser.close()
    print('PASS: HTTP demo loads, displays sample items, reveals and saves locally, with no backend writes')
finally:
    server.shutdown()
    server.server_close()
