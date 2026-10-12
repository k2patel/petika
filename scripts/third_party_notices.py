#!/usr/bin/env python3
"""Emit dependency license declarations and the shipped upstream notice files."""
import json
from pathlib import Path
import subprocess

metadata = json.loads(subprocess.check_output(
    ["cargo", "metadata", "--locked", "--format-version", "1"], text=True
))
print("Petika third-party notices\n==========================")
for package in sorted(metadata["packages"], key=lambda p: (p["name"], p["version"])):
    if package["source"] is None:
        continue
    print(f"\n{package['name']} {package['version']} — {package.get('license', 'UNKNOWN')}")
    print(package.get("repository") or "")
    root = Path(package["manifest_path"]).parent
    paths = set()
    for pattern in ("LICENSE*", "LICENCE*", "COPYING*", "NOTICE*", "license*", "licence*"):
        paths.update(p for p in root.glob(pattern) if p.is_file())
    if package.get("license_file"):
        paths.add(root / package["license_file"])
    if package["name"] == "ring":
        paths.update(root.glob("src/polyfill/once_cell/LICENSE-*"))
        paths.update(root.glob("third_party/fiat/LICENSE"))
    for path in sorted(paths):
        print(f"\n--- {path.name} ---\n{path.read_text(errors='replace')}")
