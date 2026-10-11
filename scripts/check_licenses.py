#!/usr/bin/env python3
"""Fail closed on unreviewed resolved Cargo dependency license declarations."""
import json
import subprocess
import sys

# Exact reviewed declarations only; unknown expressions fail closed.
# For OR expressions below, select the MIT branch. Preserve Unicode notices too.
ALLOWED = {"MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "Zlib", "CC0-1.0", "Unicode-3.0"}

ALLOWED.update({
    "MIT OR Apache-2.0", "Apache-2.0 OR MIT", "MIT/Apache-2.0",
    "Unlicense OR MIT", "MIT OR Apache-2.0 OR BSD-1-Clause", "MIT OR Apache-2.0 OR LGPL-2.1-or-later",
    "Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT",
    "(MIT OR Apache-2.0) AND Unicode-3.0",
    "CC0-1.0 OR MIT-0 OR Apache-2.0", "(Apache-2.0 OR MIT) AND BSD-3-Clause",
    "Unlicense/MIT", "Zlib OR Apache-2.0 OR MIT",
})

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
