#!/usr/bin/env python3
"""Independent, synthetic checkpoint/transition/HPKE fixtures. Not product code.
Uses cryptography and the existing upstream X-Wing draft-06 KAT shared secret.
"""
import argparse
import base64
import hashlib
import hmac
import json
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from generate_entry_vectors import field, b64, context_bytes
ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / 'crates/petika-core/tests/fixtures'
SUITE = 'xchacha20poly1305-hkdf-sha256-v1'
def digest(b): return hashlib.sha256(b).hexdigest()
def domain(d,h): return field(d)+field(h)
def extract(salt,ikm): return hmac.new(salt or bytes(32),ikm,hashlib.sha256).digest()
def expand(prk,info,length):
    result=b''; previous=b''
    for i in range(1,(length+31)//32+1):
        previous=hmac.new(prk,previous+info+bytes([i]),hashlib.sha256).digest(); result+=previous
    return result[:length]
def lextract(suite,salt,label,ikm): return extract(salt,b'HPKE-v1'+suite+label+ikm)
def lexpand(suite,prk,label,info,length): return expand(prk,length.to_bytes(2,'big')+b'HPKE-v1'+suite+label+info,length)
def public(key): return key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
def compact(value): return json.dumps(value,separators=(',',':'))
def profile_name(hybrid): return 'entry-hpke-'+('xwing-draft06' if hybrid else 'x25519')+'-sha256-chacha20poly1305-v1'
def generate():
    identity=json.loads((FIXTURES/'identity-v1.json').read_text()); kat=json.loads((FIXTURES/'xwing-draft06.json').read_text())[0]
    signer=ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(identity['signing_seed_hex']))
    transcript=field(b'petika:recipient-identity:v1')+field(b'a'*64)+field(b'b'*64)+(1).to_bytes(8,'big')
    for name,key in [('x25519','standard_public_hex'),('xwing-draft06','hybrid_public_hex'),('ed25519','signing_public_hex')]: transcript+=field(name.encode())+field(bytes.fromhex(identity[key]))
    fingerprint=digest(transcript); assert fingerprint==identity['fingerprint']
    enrollment=domain(b'petika:recipient-enrollment:v1',transcript)+field(fingerprint.encode())
    authority=dict(deployment_id='a'*64,user_id='b'*64,identity_version=1,fingerprint=fingerprint,
                   standard_public_key=b64(bytes.fromhex(identity['standard_public_hex'])),hybrid_public_key=b64(bytes.fromhex(identity['hybrid_public_hex'])),
                   signing_public_key=b64(public(signer)),signature=b64(signer.sign(enrollment)))
    cases=[]
    for hybrid in [False,True]:
        profile='experimental-xwing-draft06' if hybrid else 'standard'; snapshots=[]
        for epoch in [7,8]:
            root=bytes([epoch+2])*32; salt=bytes([epoch-4])*32
            context=dict(deployment_id='a'*64,collection_id='b'*64,key_epoch=epoch,epoch_salt=b64(salt))
            commitment=digest(field(b'petika:entry-root:commitment:v1')+context_bytes(context)+field(context['epoch_salt'].encode())+root)
            package=dict(package_version=1,profile=profile,context=context,data_suite=SUITE,root_commitment=commitment,membership_generation=9,wrapper_id=str(epoch)*64,
                         recipient_user_id=authority['user_id'],recipient_identity_version=1,recipient_fingerprint=fingerprint,
                         issuer_user_id=authority['user_id'],issuer_identity_version=1,issuer_fingerprint=fingerprint)
            header=field(b'petika:entry-package:header:v1')+(1).to_bytes(4,'big')+field(profile_name(hybrid).encode())+field(SUITE.encode())+context_bytes(context)+field(salt)+field(commitment.encode())+(9).to_bytes(8,'big')+field(package['wrapper_id'].encode())
            for _ in range(2): header+=field(authority['user_id'].encode())+(1).to_bytes(8,'big')+field(fingerprint.encode())
            kem_id=0x647a if hybrid else 0x20
            if hybrid:
                enc=bytes.fromhex(kat['ct']); shared=bytes.fromhex(kat['ss'])
            else:
                ephemeral=x25519.X25519PrivateKey.from_private_bytes(bytes(range(32,64)))
                recipient=x25519.X25519PrivateKey.from_private_bytes(bytes.fromhex(identity['standard_secret_hex']))
                enc=public(ephemeral); kem_suite=b'KEM'+kem_id.to_bytes(2,'big')
                shared=lexpand(kem_suite,lextract(kem_suite,b'',b'eae_prk',ephemeral.exchange(recipient.public_key())),b'shared_secret',enc+public(recipient),32)
            suite=b'HPKE'+kem_id.to_bytes(2,'big')+b'\x00\x01\x00\x03'
            info=domain(b'petika:entry-package:info:v1',header)
            schedule=b'\x00'+lextract(suite,b'',b'psk_id_hash',b'')+lextract(suite,b'',b'info_hash',info)
            secret=lextract(suite,shared,b'secret',b'')
            key=lexpand(suite,secret,b'key',schedule,32); nonce=lexpand(suite,secret,b'base_nonce',schedule,12)
            ct=ChaCha20Poly1305(key).encrypt(nonce,b'petika:entry-root:v1\0'+root,domain(b'petika:entry-package:aad:v1',header))
            package.update(enc=b64(enc),ciphertext=b64(ct),signature=b64(signer.sign(domain(b'petika:entry-package:signature:v1',header)+field(enc)+field(ct))))
            # Exact envelope bytes are retained; no parse/re-encode hashing.
            package_bytes=compact(package)
            ref=dict(wrapper_id=package['wrapper_id'],digest=digest(package_bytes.encode()))
            set_digest=digest(field(b'petika:entry-wrapper-set:v1')+field(ref['wrapper_id'].encode())+field(ref['digest'].encode()))
            cp=dict(checkpoint_version=1,context=context,data_suite=SUITE,delivery_profile=profile,root_commitment=commitment,
                    head_revision=epoch+4,head_digest='d'*64,membership_generation=9,wrapper_set_digest=set_digest,authority=authority)
            message=field(b'petika:entry-checkpoint:v1')+(1).to_bytes(4,'big')+context_bytes(context)+field(salt)
            for value in [SUITE,profile_name(hybrid),commitment,cp['head_digest'],set_digest,fingerprint]: message+=field(value.encode())
            message+=cp['head_revision'].to_bytes(8,'big')+(9).to_bytes(8,'big')
            signature=signer.sign(message); cp['signature']=b64(signature)
            cp_digest=digest(message+field(signature))
            snapshots.append(dict(checkpoint=cp,checkpoint_digest=cp_digest,message=b64(message),package=package_bytes,header=b64(header),wrappers=[ref],root=b64(root)))
        transition_message=field(b'petika:entry-epoch-transition:v1')+(1).to_bytes(4,'big')+field(snapshots[0]['checkpoint_digest'].encode())+field(snapshots[1]['checkpoint_digest'].encode())
        transition=dict(transition_version=1,previous_checkpoint_digest=snapshots[0]['checkpoint_digest'],next=snapshots[1]['checkpoint'],signature=b64(signer.sign(transition_message)))
        cases.append(dict(snapshots=snapshots,transition=transition,transition_message=b64(transition_message)))
    return dict(provenance='Test-only cryptography HPKE reference/Ed25519 plus existing X-Wing draft-06 KAT',cases=cases)
if __name__=='__main__':
    parser=argparse.ArgumentParser(); parser.add_argument('--check',action='store_true'); args=parser.parse_args()
    path=FIXTURES/'entry-trust-v1.json'; encoded=json.dumps(generate(),indent=2)+'\n'
    if args.check:
        if path.read_text()!=encoded: raise SystemExit('Entry trust vectors differ')
        print('Independent entry trust vectors match')
    else: path.write_text(encoded); print('Wrote entry-trust-v1.json')
