#!/usr/bin/env python3
"""Fail closed on unreviewed resolved Cargo dependency license declarations."""
import json
import subprocess
import sys

# Exact SPDX declarations only; review compound expressions before adding them.
ALLOWED = {"MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "Zlib", "CC0-1.0", "Unicode-3.0"}

metadata = json.loads(subprocess.check_output(
    ["cargo", "metadata", "--locked", "--format-version", "1"], text=True
))
failures = []
for package in metadata["packages"]:
    license_id = package.get("license")
    if license_id not in ALLOWED:
        failures.append(f"{package['name']} {package['version']}: {license_id or 'missing license'}")
if failures:
    print("License review required:\n" + "\n".join(failures), file=sys.stderr)
    sys.exit(1)
print(f"License declarations accepted for {len(metadata['packages'])} packages.")
