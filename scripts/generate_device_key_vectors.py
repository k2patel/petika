#!/usr/bin/env python3
"""Independent candidate device-format fixtures; all keys are public test inputs.
Only public records, signatures, transcripts and hashes are written. No Rust invoked.
"""
import argparse
import base64
import hashlib
import json
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

FIXTURES = Path(__file__).resolve().parents[1] / "crates/petika-core/tests/fixtures"


def field(value):
    if isinstance(value, str):
        value = value.encode("ascii")
    return len(value).to_bytes(4, "big") + value


def b64(value):
    return base64.b64encode(value).decode("ascii")


def public(key):
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def digest(value):
    return hashlib.sha256(value).hexdigest()


def synthetic_seed(label):
    return hashlib.sha256(("PUBLIC PETIKA DEVICE FORMAT TEST ONLY: " + label).encode()).digest()


def generate():
    kats = json.loads((FIXTURES / "xwing-draft06.json").read_text())
    devices, transcripts = [], []
    for index in range(2):
        signer = ed25519.Ed25519PrivateKey.from_private_bytes(synthetic_seed(f"device-{index}"))
        standard = public(x25519.X25519PrivateKey.from_private_bytes(synthetic_seed(f"standard-{index}")))
        hybrid = bytes.fromhex(kats[index]["pk"])
        record = dict(record_version=1, deployment_id="a" * 64, user_id="b" * 64,
                      device_id=str(index + 1) * 64, standard_public_key=b64(standard),
                      hybrid_public_key=b64(hybrid), signing_public_key=b64(public(signer)))
        transcript = field("petika:device-record:experimental-v1") + (1).to_bytes(4, "big")
        for key in ["deployment_id", "user_id", "device_id"]:
            transcript += field(record[key])
        for suite, key in [("x25519", standard), ("xwing-draft06", hybrid), ("ed25519", public(signer))]:
            transcript += field(suite) + field(key)
        record["fingerprint"] = digest(transcript)
        message = field("petika:device-self-signature:experimental-v1") + field(transcript) + field(record["fingerprint"])
        record["signature"] = b64(signer.sign(message))
        devices.append(record)
        transcripts.append(transcript)
    signer = ed25519.Ed25519PrivateKey.from_private_bytes(synthetic_seed("separate-authority"))
    authority = dict(authority_version=1, deployment_id="a" * 64, user_id="b" * 64,
                     signing_public_key=b64(public(signer)))
    auth_bytes = (field("petika:device-authority:experimental-v1") + (1).to_bytes(4, "big")
                  + field(authority["deployment_id"]) + field(authority["user_id"])
                  + field("ed25519") + field(public(signer)))
    authority["fingerprint"] = digest(auth_bytes)
    chain, parent = [], ""
    for generation, active, revoked in [(1, [0], []), (2, [0, 1], []), (3, [1], [devices[0]["device_id"]])]:
        roster = dict(roster_version=1, authority=authority, generation=generation,
                      parent_digest=parent, devices=[devices[i] for i in active], revoked_device_ids=revoked)
        message = (field("petika:device-roster:experimental-v1") + (1).to_bytes(4, "big")
                   + field(auth_bytes) + field(authority["fingerprint"]) + generation.to_bytes(8, "big")
                   + field(parent) + len(active).to_bytes(4, "big"))
        for index in active:
            record = devices[index]
            message += field(transcripts[index]) + field(record["fingerprint"]) + field(base64.b64decode(record["signature"]))
        message += len(revoked).to_bytes(4, "big")
        for device_id in revoked:
            message += field(device_id)
        signature = signer.sign(message)
        roster["signature"] = b64(signature)
        parent = digest(message + field(signature))
        chain.append(dict(roster=roster, canonical_hex=message.hex(), digest=parent))
    return dict(provenance="Independent Python hashlib/cryptography encoding and Ed25519; synthetic labels; existing upstream X-Wing public KATs; no production secrets",
                device_transcripts_hex=[t.hex() for t in transcripts], authority_transcript_hex=auth_bytes.hex(), chain=chain)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    path = FIXTURES / "device-keys-v1.json"
    encoded = json.dumps(generate(), indent=2) + "\n"
    if args.check:
        if path.read_text() != encoded:
            raise SystemExit("Device-key vectors differ")
        print("Independent device-key vectors match")
    else:
        path.write_text(encoded)
        print("Wrote public device-key fixtures")
