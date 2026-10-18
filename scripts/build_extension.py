#!/usr/bin/env python3
"""Package local Chromium preview assets; no remote JavaScript or npm dependencies."""
import argparse
import json
from pathlib import Path
import shutil
from urllib.parse import urlsplit

root = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--endpoint', default='https://petika.k2patel.in')
parser.add_argument('--output', type=Path, default=root/'output/extension-chromium')
args = parser.parse_args()
url = urlsplit(args.endpoint)
if url.scheme != 'https' or not url.hostname or url.username or url.password or url.path not in ('', '/') or url.query or url.fragment:
    parser.error('Endpoint must be an HTTPS origin')
if '*' in url.hostname or '%' in url.hostname:
    parser.error('Endpoint host must be exact, without wildcards or escapes')
try:
    url.port
except ValueError:
    parser.error('Endpoint port is invalid')
endpoint = args.endpoint.rstrip('/')
permission_host = f'[{url.hostname}]' if ':' in url.hostname else url.hostname
source = root/'clients/web'
if not (source/'wasm/petika_web_bg.wasm').is_file():
    parser.error('Build the WASM client first with scripts/build_web.sh')
args.output.mkdir(parents=True, exist_ok=True)
for name in ['popup.html', 'popup.mjs', 'fill.mjs', 'background.mjs']:
    shutil.copyfile(root/'clients/extension'/name, args.output/name)
for name in ['app.css', 'worker.js', 'otp.js']:
    shutil.copyfile(source/name, args.output/name)
shutil.copytree(source/'wasm', args.output/'wasm', dirs_exist_ok=True)
(args.output/'config.json').write_text(json.dumps({'endpoint':endpoint}))
(args.output/'manifest.json').write_text(json.dumps({
    'manifest_version':3, 'name':'Petika — Chromium preview', 'version':'0.1.0',
    'minimum_chrome_version':'106',
    'description':'Locally decrypt and explicitly fill logins and time-based verification codes.',
    'permissions':['activeTab','scripting','storage'],
    'background':{'service_worker':'background.mjs','type':'module'},
    'host_permissions':[f'https://{permission_host}/*'],
    'action':{'default_title':'Open Petika', 'default_popup':'popup.html'},
    'content_security_policy':{'extension_pages':"default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; object-src 'none'; style-src 'self'; connect-src 'self' "+endpoint+"; worker-src 'self'; frame-src 'none'; base-uri 'none'"}
}, indent=2)+'\n')
print(f'Chromium preview packaged at {args.output}')
