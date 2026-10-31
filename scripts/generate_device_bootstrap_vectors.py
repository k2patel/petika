#!/usr/bin/env python3
"""Independent public device-authority continuity fixture. Synthetic inputs only."""
import argparse
import base64
import json
from cryptography.hazmat.primitives.asymmetric import ed25519
from generate_device_key_vectors import FIXTURES, field, b64, public, digest, synthetic_seed, generate


def fixture():
    source = generate()
    authority = source["chain"][0]["roster"]["authority"]
    approver = ed25519.Ed25519PrivateKey.from_private_bytes(synthetic_seed("separate-authority"))
    roster = dict(roster_version=1, authority=authority, generation=1, parent_digest="",
                  devices=[], revoked_device_ids=[])
    message = (field("petika:device-roster:experimental-v1") + (1).to_bytes(4, "big")
               + field(bytes.fromhex(source["authority_transcript_hex"])) + field(authority["fingerprint"])
               + (1).to_bytes(8, "big") + field("") + (0).to_bytes(4, "big") * 2)
    signature = approver.sign(message)
    roster["signature"] = b64(signature)
    roster_digest = digest(message + field(signature))
    device = source["chain"][0]["roster"]["devices"][0]
    signer = ed25519.Ed25519PrivateKey.from_private_bytes(synthetic_seed("legacy-bootstrap"))
    legacy = dict(deployment_id="a" * 64, user_id="b" * 64, identity_version=3,
                  standard_public_key=device["standard_public_key"], hybrid_public_key=device["hybrid_public_key"],
                  signing_public_key=b64(public(signer)))
    transcript = field("petika:recipient-identity:v1") + field(legacy["deployment_id"]) + field(legacy["user_id"]) + (3).to_bytes(8, "big")
    for suite, name in [("x25519", "standard_public_key"), ("xwing-draft06", "hybrid_public_key"), ("ed25519", "signing_public_key")]:
        transcript += field(suite) + field(base64.b64decode(legacy[name]))
    legacy["fingerprint"] = digest(transcript)
    legacy["signature"] = b64(signer.sign(field("petika:recipient-enrollment:v1") + field(transcript) + field(legacy["fingerprint"])))
    message = (field("petika:device-authority-bootstrap:experimental-v1") + (1).to_bytes(4, "big")
               + field(legacy["deployment_id"]) + field(legacy["user_id"]) + (7).to_bytes(8, "big") + (3).to_bytes(8, "big")
               + field(legacy["fingerprint"]) + field(authority["fingerprint"]) + field(roster_digest))
    bootstrap = dict(bootstrap_version=1, source_bundle_revision=7, legacy_identity=legacy,
                     initial_roster=roster, signature=b64(signer.sign(message)))
    return dict(provenance="Independent Python Ed25519 and transcript encoding, public synthetic labels and upstream public KAT; no real account data",
                bootstrap=bootstrap, canonical=b64(message), initial_digest=roster_digest)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    path = FIXTURES / "device-bootstrap-v1.json"
    encoded = json.dumps(fixture(), indent=2) + "\n"
    if args.check:
        if path.read_text() != encoded:
            raise SystemExit("Device bootstrap vectors differ")
        print("Independent device bootstrap vectors match")
    else:
        path.write_text(encoded)
        print("Wrote public device bootstrap fixture")
