#!/usr/bin/env python3
"""Stdlib-only confirmation digests using existing synthetic signed fixtures."""
import argparse
import hashlib
import json
from pathlib import Path


def field(value):
    return len(value).to_bytes(4, 'big') + value


def generate(directory):
    trust = json.loads((directory / 'entry-trust-v1.json').read_text())
    cases = []
    for case in trust['cases']:
        snapshot = case['snapshots'][0]
        handoff = dict(handoff_version=1, checkpoint=snapshot['checkpoint'],
                       package=snapshot['package'], wrappers=snapshot['wrappers'])
        message = field(b'petika:entry-handoff:v1') + (1).to_bytes(4, 'big')
        message += field(snapshot['checkpoint_digest'].encode())
        message += field(hashlib.sha256(snapshot['package'].encode()).digest())
        cases.append(dict(handoff=handoff, confirmation_digest=hashlib.sha256(message).hexdigest()))
    return json.dumps(cases, indent=2) + '\n'


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    directory = Path(__file__).resolve().parents[1] / 'crates/petika-core/tests/fixtures'
    path = directory / 'entry-handoff-v1.json'
    expected = generate(directory)
    if args.check:
        if path.read_text() != expected:
            raise SystemExit('entry handoff vectors differ')
    else:
        path.write_text(expected)
