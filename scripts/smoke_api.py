#!/usr/bin/env python3
"""Exercise a disposable running API using a synthetic encrypted CLI store."""
import argparse
import json
import time
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("url")
parser.add_argument("token_file", type=Path)
parser.add_argument("store", type=Path)
args = parser.parse_args()
token = args.token_file.read_text().strip()


def request(path, expected, method="GET", data=None, auth=True, revision=None):
    headers = {"Content-Type": "application/json"}
    if auth:
        headers["Authorization"] = "Bearer " + token
    if revision is not None:
        headers["If-Match"] = f'"{revision}"'
    req = Request(args.url + path, data=data, headers=headers, method=method)
    try:
        response = urlopen(req, timeout=5)
    except HTTPError as error:
        response = error
    with response:
        assert response.status == expected, (path, response.status, expected)
        return response.read(), response.headers


request("/healthz", 200, auth=False)
request("/readyz", 200, auth=False)
request("/v1/snapshot", 401, auth=False)
request("/v1/snapshot", 404)
encrypted = args.store.read_bytes()
request("/v1/snapshot", 428, "PUT", encrypted)
request("/v1/snapshot", 200, "PUT", encrypted, revision=0)
request("/v1/snapshot", 409, "PUT", encrypted, revision=0)
body, headers = request("/v1/snapshot", 200)
assert body == encrypted
assert headers["ETag"] == '"1"'
request("/v1/snapshot", 400, "PUT", b"{}", revision=1)
for _ in range(15):
    status = json.loads(request("/v1/status", 200)[0])
    if status["mirror_revision"] == 1:
        break
    time.sleep(1)
else:
    raise AssertionError("Mirror did not catch up")
print("API health, authentication, revision conflicts, ciphertext roundtrip, and Git mirror passed.")
