#!/usr/bin/env python3
"""Independent fixtures: RFC 9180 base mode + X-Wing draft-06 section 5.6.
Test-only generator; requires Python cryptography. Never used by product code.
"""
import base64
import hashlib
import hmac
import json
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
ROOT = Path(__file__).resolve().parents[1]
def field(b): return len(b).to_bytes(4, 'big') + b
def domain(d, h): return field(d) + field(h)
def extract(salt, ikm): return hmac.new(salt or bytes(32), ikm, hashlib.sha256).digest()
def expand(prk, info, length):
    result = b''; previous = b''
    for index in range(1, (length+31)//32+1):
        previous = hmac.new(prk, previous+info+bytes([index]), hashlib.sha256).digest(); result += previous
    return result[:length]
def lextract(suite, salt, label, ikm): return extract(salt, b'HPKE-v1'+suite+label+ikm)
def lexpand(suite, prk, label, info, length): return expand(prk, length.to_bytes(2,'big')+b'HPKE-v1'+suite+label+info, length)
def public(key): return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
vectors = []
for hybrid in [False, True]:
    mode = 'hybrid-post-quantum' if hybrid else 'standard'
    suite_name = 'hpke-'+('xwing-draft06' if hybrid else 'x25519')+'-sha256-chacha20poly1305-v1'
    p = dict(package_version=1, suite=suite_name, deployment_id='a'*64, collection_id='b'*64, collection_mode=mode, key_epoch=7, membership_generation=9, recipient_user_id='c'*64, recipient_identity_version=2, recipient_fingerprint='d'*64, issuer_user_id='e'*64, issuer_identity_version=3, issuer_fingerprint='f'*64, package_id='0'*64)
    header = field(b'petika:key-package:header:v1') + (1).to_bytes(4,'big')
    for key in ['suite','deployment_id','collection_id','collection_mode']: header += field(p[key].encode())
    for key in ['key_epoch','membership_generation']: header += p[key].to_bytes(8,'big')
    for prefix in ['recipient','issuer']:
        header += field(p[prefix+'_user_id'].encode()) + p[prefix+'_identity_version'].to_bytes(8,'big') + field(p[prefix+'_fingerprint'].encode())
    header += field(p['package_id'].encode())
    if hybrid:
        upstream = json.loads((ROOT/'crates/petika-core/tests/fixtures/xwing-draft06.json').read_text())[0]
        secret, enc, shared = [bytes.fromhex(upstream[k]) for k in ['sk','ct','ss']]
        kem_id = 0x647a
    else:
        secret = bytes(range(32)); recipient = x25519.X25519PrivateKey.from_private_bytes(secret)
        ephemeral = x25519.X25519PrivateKey.from_private_bytes(bytes(range(32,64)))
        enc = public(ephemeral); kem_id = 0x20
        kem_suite = b'KEM'+kem_id.to_bytes(2,'big')
        eae_prk = lextract(kem_suite, b'', b'eae_prk', ephemeral.exchange(recipient.public_key()))
        shared = lexpand(kem_suite, eae_prk, b'shared_secret', enc+public(recipient), 32)
    suite = b'HPKE'+kem_id.to_bytes(2,'big')+b'\x00\x01\x00\x03'
    info = domain(b'petika:key-package:info:v1', header)
    context = b'\x00'+lextract(suite,b'',b'psk_id_hash',b'')+lextract(suite,b'',b'info_hash',info)
    hpke_secret = lextract(suite,shared,b'secret',b'')
    key = lexpand(suite,hpke_secret,b'key',context,32); nonce = lexpand(suite,hpke_secret,b'base_nonce',context,12)
    payload = bytes([2 if hybrid else 1])+bytes(range(64,96))
    ct = ChaCha20Poly1305(key).encrypt(nonce,payload,domain(b'petika:key-package:aad:v1',header))
    message = domain(b'petika:key-package:signature:v1',header)+field(enc)+field(ct)
    signer = ed25519.Ed25519PrivateKey.from_private_bytes(bytes(range(96,128)))
    p.update(enc=base64.b64encode(enc).decode(),ciphertext=base64.b64encode(ct).decode(),signature=base64.b64encode(signer.sign(message)).decode())
    vectors.append(dict(package=p,header_hex=header.hex(),private_key_hex=secret.hex(),payload_hex=payload.hex(),signing_public_hex=public(signer).hex()))
(ROOT/'crates/petika-core/tests/fixtures/key-packages-v1.json').write_text(json.dumps(vectors,indent=2)+'\n')
