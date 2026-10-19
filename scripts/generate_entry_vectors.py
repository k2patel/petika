#!/usr/bin/env python3
"""Test-only entry-format vectors using cryptography HKDF and libsodium AEAD/Argon2.
Never imported by product code. Install scripts/requirements-entry-vectors.txt.
Run --check in CI; no argument explicitly regenerates the synthetic fixture.
"""
import argparse
import base64
import json
from pathlib import Path
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from nacl.bindings import crypto_aead_xchacha20poly1305_ietf_encrypt
from nacl.bindings.crypto_pwhash import crypto_pwhash_alg, crypto_pwhash_ALG_ARGON2ID13


def field(value):
    return len(value).to_bytes(4, "big") + value


def b64(value):
    return base64.b64encode(value).decode("ascii")


def context_bytes(context):
    return (field(context["deployment_id"].encode())
            + field(context["collection_id"].encode())
            + context["key_epoch"].to_bytes(8, "big"))


def generate():
    suite = "xchacha20poly1305-hkdf-sha256-v1"
    context = dict(deployment_id="a" * 64, collection_id="b" * 64,
                   key_epoch=7, epoch_salt=b64(bytes([3]) * 32))
    root = bytes([9]) * 32
    nonce = bytes([5]) * 24
    objects = []
    for kind, object_id in [("entry", "c" * 64), ("index", "")]:
        header = dict(entry_format_version=1, suite=suite, context=context,
                      kind=kind, object_id=object_id, revision=11)
        info = (field(b"petika:entry-format:kdf:v1") + (1).to_bytes(4, "big")
                + field(suite.encode()) + context_bytes(context)
                + field(kind.encode()) + field(object_id.encode()))
        aad = (field(b"petika:entry-format:aead:v1") + field(info)
               + field(bytes([3]) * 32) + (11).to_bytes(8, "big"))
        key = HKDF(algorithm=hashes.SHA256(), length=32, salt=bytes([3]) * 32,
                   info=info).derive(root)
        plaintext = ("synthetic " + kind + " payload: café").encode()
        ciphertext = crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, aad, nonce, key)
        envelope = dict(header=header, nonce=b64(nonce), ciphertext=b64(ciphertext))
        objects.append(dict(header=header, key_info=b64(info), aad=b64(aad),
                            object_key=b64(key), plaintext=b64(plaintext),
                            envelope=json.dumps(envelope, separators=(",", ":"))))
    profile = "argon2id-v19-xchacha20poly1305-entry-root-v1"
    salt = bytes([4]) * 16
    tag = b"petika:entry-root:v1\0"
    wrapper = dict(wrapper_version=1, profile=profile, suite=suite, context=context,
                   wrapper_id="e" * 64, salt=b64(salt), memory_kib=65536,
                   iterations=3, lanes=1, nonce=b64(nonce))
    aad = (field(b"petika:entry-format:recovery:v1") + (1).to_bytes(4, "big")
           + field(profile.encode()) + field(suite.encode()) + context_bytes(context)
           + field(bytes([3]) * 32) + field(wrapper["wrapper_id"].encode()) + field(salt)
           + (65536).to_bytes(4, "big") + (3).to_bytes(4, "big")
           + (1).to_bytes(4, "big") + field(tag))
    key = crypto_pwhash_alg(32, b"synthetic vector passphrase", salt, 3, 65536 * 1024,
                           crypto_pwhash_ALG_ARGON2ID13)
    wrapper["ciphertext"] = b64(crypto_aead_xchacha20poly1305_ietf_encrypt(tag + root, aad, nonce, key))
    return dict(provenance="cryptography 46.0.3 HKDF-SHA256; PyNaCl 1.6.2 libsodium XChaCha20-Poly1305 and Argon2id",
                objects=objects, wrapper=json.dumps(wrapper, separators=(",", ":")), wrapper_aad=b64(aad))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    path = Path(__file__).resolve().parents[1] / "crates/petika-core/tests/fixtures/entry-format-v1.json"
    encoded = json.dumps(generate(), indent=2, ensure_ascii=True) + "\n"
    if args.check:
        if path.read_text() != encoded:
            raise SystemExit("Entry-format fixture differs from the independent reference")
        print("Independent entry-format fixtures match")
    else:
        path.write_text(encoded)
        print(f"Wrote {path.name}")
