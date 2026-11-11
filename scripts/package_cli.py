#!/usr/bin/env python3
"""Package a native Petika CLI and smoke-test the executable from its archive."""

import argparse
import hashlib
import json
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile
import tomllib

ROOT = Path(__file__).resolve().parent.parent
TARGETS = {
    ("Darwin", "arm64"): "aarch64-apple-darwin",
    ("Darwin", "x86_64"): "x86_64-apple-darwin",
    ("Linux", "aarch64"): "aarch64-unknown-linux-gnu",
    ("Linux", "x86_64"): "x86_64-unknown-linux-gnu",
    ("Windows", "AMD64"): "x86_64-pc-windows-msvc",
}


def smoke_test(binary, version):
    def run(*args, stdin=""):
        result = subprocess.run(
            [binary, *args], input=stdin, capture_output=True, text=True,
            timeout=60,
        )
        if result.returncode:
            raise SystemExit(f"Packaged CLI exited with {result.returncode}: {result.stderr.strip()}")
        return result.stdout.strip()

    if run("--version") != f"petika {version}":
        raise SystemExit(f"Packaged executable does not report version {version}")

    store = binary.parent / "smoke.petika"
    common = ("--no-config", "--store", str(store), "--passphrase-stdin")
    passphrase = "synthetic release smoke passphrase\n"
    secret = "synthetic release smoke secret"
    run(*common, "init", stdin=passphrase * 2)
    run(*common, "put", "release-test", "--password-stdin", stdin=passphrase + secret + "\n")
    if secret.encode() in store.read_bytes():
        raise SystemExit("Packaged executable wrote the test secret in plaintext")
    if run(*common, "get", "release-test", "--reveal", stdin=passphrase) != secret:
        raise SystemExit("Packaged executable failed the vault round-trip")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--target", required=True)
    parser.add_argument("--notices", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    system, machine = platform.system(), platform.machine()
    if TARGETS.get((system, machine)) != args.target:
        raise SystemExit(f"Cannot test {args.target} natively on {system} {machine}")

    version = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))["workspace"]["package"]["version"]
    source = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    executable = "petika.exe" if system == "Windows" else "petika"
    archive_format = "zip" if system == "Windows" else "gztar"
    archive_name = f"petika-{version}-{args.target}"
    args.output.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory() as temp:
        stage = Path(temp) / "stage"
        stage.mkdir()
        shutil.copy2(args.binary, stage / executable)
        if system == "Darwin":
            shutil.copy2(args.binary.with_name("petika-macos-unlock"), stage / "petika-macos-unlock")
        shutil.copyfile(ROOT / "LICENSE", stage / "LICENSE")
        shutil.copyfile(args.notices, stage / "THIRD_PARTY_NOTICES.txt")
        metadata = {
            "version": version,
            "target": args.target,
            "source": f"https://github.com/k2patel/petika/tree/{source}",
            "tested_on": platform.platform(),
        }
        (stage / "build.json").write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
        archive = Path(shutil.make_archive(str(Path(temp) / archive_name), archive_format, stage))
        extracted = Path(temp) / "extracted"
        shutil.unpack_archive(archive, extracted)
        smoke_test(extracted / executable, version)
        if system == "Darwin":
            result = subprocess.run(
                [extracted / "petika-macos-unlock", "unlock"],
                input=b"{}", capture_output=True, timeout=10,
            )
            if result.returncode == 0 or result.stdout:
                raise SystemExit("The macOS helper accepted an invalid credential")
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        shutil.copyfile(archive, args.output / archive.name)
        (args.output / f"{archive.name}.sha256").write_bytes(f"{digest}  {archive.name}\n".encode("ascii"))
        print(f"Packaged and smoke-tested {archive.name}")


if __name__ == "__main__":
    main()
