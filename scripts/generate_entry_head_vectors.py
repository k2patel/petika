#!/usr/bin/env python3
"""Independent stdlib-only synthetic head encoding vectors; no Rust calls."""
import argparse
import base64
import hashlib
import json
from pathlib import Path


def field(value):
    return len(value).to_bytes(4, 'big') + value


def generate():
    cases = []
    for revision in (1, 2, (1 << 53) - 1):
        context = dict(deployment_id='a' * 64, collection_id='b' * 64,
                       key_epoch=7, epoch_salt=base64.b64encode(bytes(range(32))).decode())
        head = dict(version=1, context=context, suite='xchacha20poly1305-hkdf-sha256-v1',
                    revision=revision, parent_digest='' if revision == 1 else 'c' * 64,
                    index_digest='d' * 64, wrapper_set_digest='e' * 64, membership_generation=9)
        message = field(b'petika:entry-head:v1') + (1).to_bytes(4, 'big')
        message += field(context['deployment_id'].encode()) + field(context['collection_id'].encode())
        message += context['key_epoch'].to_bytes(8, 'big') + field(bytes(range(32)))
        for key in ('suite', 'parent_digest', 'index_digest', 'wrapper_set_digest'):
            message += field(head[key].encode())
        message += revision.to_bytes(8, 'big') + (9).to_bytes(8, 'big')
        cases.append(dict(head=head, canonical_hex=message.hex(), digest=hashlib.sha256(message).hexdigest()))
    return json.dumps(cases, indent=2) + '\n'


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    path = Path(__file__).resolve().parents[1] / 'crates/petika-core/tests/fixtures/entry-head-v1.json'
    expected = generate()
    if args.check:
        if path.read_text() != expected:
            raise SystemExit('entry head vectors differ')
    else:
        path.write_text(expected)
