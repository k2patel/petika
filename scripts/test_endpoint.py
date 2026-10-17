#!/usr/bin/env python3
"""Verify runtime endpoint configuration and canonical-origin browser requests."""
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
with tempfile.TemporaryDirectory(prefix='petika-endpoint-') as temporary:
    work = Path(temporary)
    (work / 'token').write_text(secrets.token_hex(32))
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
    endpoint = f'http://localhost:{port}'
    direct = f'http://127.0.0.1:{port}'
    env = {**os.environ, 'PETIKA_TOKEN_FILE': str(work / 'token'),
           'PETIKA_DATA_DIR': str(work / 'data'), 'PETIKA_WEB_DIR': str(root / 'clients/web'),
           'PETIKA_LISTEN': f'127.0.0.1:{port}', 'PETIKA_ENDPOINT': endpoint,
           'PETIKA_COOKIE_SECURE': 'false', 'PETIKA_SETUP_MODE': 'auto',
           'PETIKA_ADMIN_USERNAME': 'owner', 'PETIKA_ADMIN_PASSWORD': 'synthetic endpoint password'}
    env.pop('PETIKA_GIT_MIRROR', None)
    env.pop('PETIKA_ADMIN_PASSWORD_FILE', None)
    server = subprocess.Popen([str(root / 'target/debug/petika-server')], env=env, stdout=subprocess.DEVNULL)
    try:
        for _ in range(100):
            try:
                with urlopen(direct + '/config.json', timeout=1) as response:
                    assert response.headers['Cache-Control'] == 'no-store'
                    assert json.load(response) == {'endpoint': endpoint}
                break
            except OSError:
                time.sleep(.1)
        else:
            raise AssertionError('Server did not start')
        with sync_playwright() as p:
            browser = p.chromium.launch()
            page = browser.new_page()
            api_requests = []
            page.on('request', lambda request: api_requests.append(request.url) if '/v1/' in request.url else None)
            page.goto(direct)
            expect(page).to_have_url(endpoint + '/')
            page.get_by_label('Username', exact=True).fill('owner')
            page.get_by_label('Account password', exact=True).fill('synthetic endpoint password')
            page.get_by_role('button', name='Sign in', exact=True).click()
            expect(page.get_by_role('heading', name='Set up Personal')).to_be_visible()
            page.reload()
            expect(page.get_by_role('heading', name='Set up Personal')).to_be_visible()
            assert api_requests and all(url.startswith(endpoint + '/v1/') for url in api_requests), api_requests
            browser.close()
        print('PASS: runtime endpoint redirects before API calls; configured origin login and cookies survive reload')
    finally:
        server.terminate()
        server.wait(timeout=10)
