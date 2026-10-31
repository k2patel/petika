#!/usr/bin/env python3
"""Independent public enrollment fixtures using synthetic inputs; never production keys."""
import argparse
import hashlib
import json
import base64
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from generate_device_key_vectors import FIXTURES, field, b64, public, digest, synthetic_seed, generate as records
from generate_entry_trust_vectors import lextract, lexpand


def signed_digest(message, signature):
    return digest(message + field(signature))


def generate():
    source = records()
    baseline = source["chain"][0]
    device = source["chain"][1]["roster"]["devices"][1]
    authority = baseline["roster"]["authority"]
    signer = ed25519.Ed25519PrivateKey.from_private_bytes(synthetic_seed("device-1"))
    approver = ed25519.Ed25519PrivateKey.from_private_bytes(synthetic_seed("separate-authority"))
    request = dict(request_version=1, authority=authority, device=device, roster_generation=1,
                   roster_digest=baseline["digest"], nonce="c" * 64, issued_at=100, expires_at=400)
    message = (field("petika:device-enrollment-request:experimental-v1") + (1).to_bytes(4, "big")
               + field(bytes.fromhex(source["authority_transcript_hex"])) + field(authority["fingerprint"])
               + field(bytes.fromhex(source["device_transcripts_hex"][1])) + field(device["fingerprint"])
               + field(base64.b64decode(device["signature"])) + (1).to_bytes(8, "big")
               + field(request["roster_digest"]) + field(request["nonce"])
               + (100).to_bytes(8, "big") + (400).to_bytes(8, "big"))
    signature = signer.sign(message)
    request["signature"] = b64(signature)
    request_digest = signed_digest(message, signature)
    request_canonical = b64(message)
    kat = json.loads((FIXTURES / "xwing-draft06.json").read_text())[1]
    packets = []
    for hybrid in [False, True]:
        profile = "experimental-xwing-draft06" if hybrid else "standard"
        binding = field(request_digest) + field(profile)
        info = field("petika:device-enrollment-hpke-info:experimental-v1") + field(binding)
        aad = field("petika:device-enrollment-hpke-aad:experimental-v1") + field(binding)
        kem_id = 0x647a if hybrid else 0x20
        if hybrid:
            enc, shared = bytes.fromhex(kat["ct"]), bytes.fromhex(kat["ss"])
        else:
            ephemeral = x25519.X25519PrivateKey.from_private_bytes(synthetic_seed("enrollment-ephemeral"))
            recipient = x25519.X25519PrivateKey.from_private_bytes(synthetic_seed("standard-1"))
            enc = public(ephemeral)
            kem_suite = b"KEM" + kem_id.to_bytes(2, "big")
            shared = lexpand(kem_suite, lextract(kem_suite, b"", b"eae_prk", ephemeral.exchange(recipient.public_key())),
                             b"shared_secret", enc + public(recipient), 32)
        suite = b"HPKE" + kem_id.to_bytes(2, "big") + b"\x00\x01\x00\x03"
        schedule = b"\x00" + lextract(suite, b"", b"psk_id_hash", b"") + lextract(suite, b"", b"info_hash", info)
        secret = lextract(suite, shared, b"secret", b"")
        key, nonce = lexpand(suite, secret, b"key", schedule, 32), lexpand(suite, secret, b"base_nonce", schedule, 12)
        payload = b"petika:device-possession:experimental-v1\0" + synthetic_seed("challenge-hybrid" if hybrid else "challenge-standard")
        packets.append(dict(enc=b64(enc), ciphertext=b64(ChaCha20Poly1305(key).encrypt(nonce, payload, aad))))
    challenge = dict(challenge_version=1, request=request, standard=packets[0], hybrid=packets[1])
    message = field("petika:device-enrollment-challenge:experimental-v1") + (1).to_bytes(4, "big") + field(request_digest)
    for profile, packet in zip(["standard", "experimental-xwing-draft06"], packets):
        message += field(profile) + field(base64.b64decode(packet["enc"])) + field(base64.b64decode(packet["ciphertext"]))
    signature = approver.sign(message)
    challenge["signature"] = b64(signature)
    challenge_digest = signed_digest(message, signature)
    response = hashlib.sha256(field("petika:device-enrollment-response:experimental-v1") + field(challenge_digest)
                              + field(synthetic_seed("challenge-standard")) + field(synthetic_seed("challenge-hybrid"))).digest()
    proof = dict(proof_version=1, request_digest=request_digest, challenge_digest=challenge_digest, response=b64(response))
    proof_bytes = (field("petika:device-enrollment-proof:experimental-v1") + (1).to_bytes(4, "big")
                   + field(request_digest) + field(challenge_digest) + field(response))
    proof["signature"] = b64(signer.sign(proof_bytes))
    return dict(provenance="Independent Python HPKE schedule, ChaCha20-Poly1305 and Ed25519; public synthetic labels and upstream X-Wing KAT; no production secrets",
                request=request, request_canonical=request_canonical, request_digest=request_digest,
                challenge=challenge, challenge_canonical=b64(message), challenge_digest=challenge_digest,
                proof=proof, proof_canonical=b64(proof_bytes))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    path = FIXTURES / "device-enrollment-v1.json"
    encoded = json.dumps(generate(), indent=2) + "\n"
    if args.check:
        if path.read_text() != encoded:
            raise SystemExit("Device enrollment vectors differ")
        print("Independent device enrollment vectors match")
    else:
        path.write_text(encoded)
        print("Wrote public device enrollment fixtures")
