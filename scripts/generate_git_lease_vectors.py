#!/usr/bin/env python3
"""Independent public synthetic Git-lease signatures; no production key material."""
import argparse
import hashlib
import json
from cryptography.hazmat.primitives.asymmetric import ed25519
from generate_device_key_vectors import FIXTURES, field, b64, public, digest, synthetic_seed, generate


def fixture():
    source = generate()
    roster = source['chain'][0]
    device = roster['roster']['devices'][0]
    signer = ed25519.Ed25519PrivateKey.from_private_bytes(synthetic_seed('device-0'))
    ssh = ed25519.Ed25519PrivateKey.from_private_bytes(synthetic_seed('temporary-ssh'))
    challenge = dict(version=1, lease_id='f'*64, operation_id='d'*64, deployment_id='a'*64,
                     user_id='b'*64, session_id='e'*64, device_id=device['device_id'],
                     device_fingerprint=device['fingerprint'], roster_digest=roster['digest'],
                     management_origin='https://git.example/', repository='synthetic/vault',
                     ssh_public_key=b64(public(ssh)), read_only=True, issued_at=100,
                     challenge_expires_at=160, lease_expires_at=400)
    transcript = field('petika:git-ssh-lease:experimental-v1') + (1).to_bytes(4, 'big')
    for name in ['lease_id','operation_id','deployment_id','user_id','session_id','device_id',
                 'device_fingerprint','roster_digest','management_origin','repository']:
        transcript += field(challenge[name])
    transcript += field(public(ssh)) + b'\x01'
    for name in ['issued_at','challenge_expires_at','lease_expires_at']:
        transcript += challenge[name].to_bytes(8, 'big')
    fingerprint = digest(transcript)
    proof = dict(challenge=challenge,
                 device_signature=b64(signer.sign(field('petika:git-ssh-lease-device-proof:experimental-v1')+field(fingerprint))),
                 ssh_signature=b64(ssh.sign(field('petika:git-ssh-lease-key-proof:experimental-v1')+field(fingerprint))))
    wire = field('ssh-ed25519') + field(public(ssh))
    return dict(provenance='Independent Python Ed25519/transcript encoding; public synthetic labels; no private keys emitted',
                proof=proof, canonical=b64(transcript), digest=fingerprint,
                openssh_public_key='ssh-ed25519 '+b64(wire), ssh_fingerprint=digest(wire))


if __name__ == '__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--check',action='store_true')
    args=parser.parse_args()
    path=FIXTURES/'git-lease-v1.json'
    encoded=json.dumps(fixture(),indent=2)+'\n'
    if args.check:
        if path.read_text()!=encoded: raise SystemExit('Git lease vectors differ')
        print('Independent Git lease vectors match')
    else:
        path.write_text(encoded)
        print('Wrote public Git lease fixture')
