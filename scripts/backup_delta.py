"""Offline, baseline-bound recovery deltas. No live import or account merging."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import tempfile

import backup_recovery as backup


def digest(value):
    return hashlib.sha256(value).hexdigest()


def checked_manifest(path, expected):
    if not re.fullmatch(r'[0-9a-f]{64}', expected):
        raise ValueError('Supply the independently retained manifest SHA-256')
    value = backup.evidence(path)
    if digest(value) != expected:
        raise ValueError('Recovery evidence does not match its independently retained hash')
    return value


def validate_files(files):
    if not isinstance(files, dict) or set(files) != set(backup.ROOTS):
        raise ValueError('Missing complete target inventory')
    for records in files.values():
        if not isinstance(records, dict):
            raise ValueError('Invalid target inventory')
        for name, record in records.items():
            path = PurePosixPath(name)
            if (not name or name in ('.', '..') or path.is_absolute() or str(path) != name
                    or any(part in ('.', '..') for part in path.parts)
                    or '\\' in name or ':' in name or '\x00' in name):
                raise ValueError('Unsafe inventory path')
            if record != {'directory': True}:
                if (not isinstance(record, dict) or set(record) != {'size', 'sha256'}
                        or type(record['size']) is not int or record['size'] < 0
                        or not isinstance(record['sha256'], str)
                        or not re.fullmatch(r'[0-9a-f]{64}', record['sha256'])):
                    raise ValueError('Invalid file record')
            for parent in path.parents:
                if str(parent) != '.' and records.get(str(parent)) != {'directory': True}:
                    raise ValueError('Missing directory or file used as parent')
    if 'sha256' not in files['data'].get('accounts.json', {}):
        raise ValueError('Complete current account state is required')


def blobs_needed(base, target):
    """Always carry accounts, even if unchanged; never infer access from a journal."""
    result = {}
    for root, records in target.items():
        for name, record in records.items():
            if 'sha256' in record and (base[root].get(name) != record
                                      or (root, name) == ('data', 'accounts.json')):
                previous = result.setdefault(record['sha256'], record)
                if previous != record:
                    raise ValueError('Conflicting blob metadata')
    return result


def copy_file(source, target):
    with source.open('rb') as src, target.open('xb') as dst:
        os.chmod(target, 0o600)
        shutil.copyfileobj(src, dst)
        dst.flush()
        os.fsync(dst.fileno())


def verify(delta, base, manifest_bytes):
    manifest = json.loads(manifest_bytes)
    if (not isinstance(manifest, dict) or manifest.get('version') != 1
            or manifest.get('mode') != 'offline-recovery-delta'
            or manifest.get('release') != base['release']
            or not isinstance(manifest.get('created_utc'), str)):
        raise ValueError('Unsupported delta or incompatible release')
    validate_files(manifest.get('files'))
    needed = blobs_needed(base['files'], manifest['files'])
    expected = {'blobs': {'directory': True},
                'delta.json': {'size': len(manifest_bytes), 'sha256': digest(manifest_bytes)}}
    expected.update({'blobs/' + sha: record for sha, record in needed.items()})
    if backup.inventory(delta) != expected:
        raise ValueError('Delta has missing, changed or unexpected fragments/access evidence')
    return manifest


def create(args):
    if not args.offline:
        raise ValueError('Stop all source writers, then specify --offline')
    sources = {name: getattr(args, name) for name in backup.ROOTS}
    backup.separate([args.baseline, args.output, *sources.values()])
    base_bytes = backup.evidence(args.baseline / 'manifest.json')
    base = backup.verify(args.baseline)
    if base != json.loads(base_bytes) or base['release'] != args.release:
        raise ValueError('Baseline changed or release mismatch')
    before = {name: backup.inventory(path) for name, path in sources.items()}
    validate_files(before)
    needed = blobs_needed(base['files'], before)
    args.output.mkdir(mode=0o700)
    (args.output / 'blobs').mkdir(mode=0o700)
    copied = set()
    for root, records in before.items():
        for name, record in records.items():
            sha = record.get('sha256')
            if sha in needed and sha not in copied:
                copy_file(sources[root] / name, args.output / 'blobs' / sha)
                copied.add(sha)
    if ({name: backup.inventory(path) for name, path in sources.items()} != before
            or backup.verify(args.baseline) != base
            or backup.evidence(args.baseline / 'manifest.json') != base_bytes):
        raise ValueError('Source or baseline changed during delta capture')
    # Validate every copied blob before publishing a completion manifest.
    if backup.inventory(args.output / 'blobs') != needed:
        raise ValueError('Incomplete delta copy')
    manifest = {'version': 1, 'mode': 'offline-recovery-delta', 'release': args.release,
                'created_utc': datetime.now(timezone.utc).isoformat(),
                'baseline_manifest_sha256': digest(base_bytes), 'files': before}
    if len(json.dumps(manifest, indent=2).encode()) + 1 > 16 * 1024 * 1024:
        raise ValueError('Delta manifest exceeds the evidence size limit')
    with tempfile.TemporaryDirectory(prefix='.petika-delta-', dir=args.output.parent) as temp:
        marker = Path(temp) / 'delta.json'
        backup.durable_json(marker, manifest)
        os.link(marker, args.output / 'delta.json')
    print('Offline recovery delta captured. Retain its manifest hash, head report and exact baseline independently.')


def replay(args):
    backup.separate([args.baseline, args.delta, args.output, args.baseline_report, args.expected_report])
    if args.output.exists() or args.output.is_symlink():
        raise ValueError('Output exists; choose a new directory')
    delta_bytes = checked_manifest(args.delta / 'delta.json', args.expected_delta_sha256)
    base_bytes = backup.evidence(args.baseline / 'manifest.json')
    base = backup.verify(args.baseline)
    manifest = verify(args.delta, base, delta_bytes)
    if (base != json.loads(base_bytes) or manifest['baseline_manifest_sha256'] != digest(base_bytes)
            or args.release != base['release']):
        raise ValueError('Wrong baseline or release; deltas cannot be rebased')
    baseline_report = backup.evidence(args.baseline_report)
    expected_report = backup.evidence(args.expected_report)
    needed = blobs_needed(base['files'], manifest['files'])
    with tempfile.TemporaryDirectory(prefix='.petika-replay-', dir=args.output.parent) as temp:
        temp = Path(temp)
        old_report, new_report = temp / 'baseline.json', temp / 'expected.json'
        for path, value in [(old_report, baseline_report), (new_report, expected_report)]:
            with path.open('xb') as stream:
                os.chmod(path, 0o600)
                stream.write(value)
        # Audit a disposable baseline copy, keeping source backups free of lock sidecars.
        backup.private_copy(args.baseline / 'data', temp / 'baseline-data')
        result = subprocess.run([str(args.recovery_tool), str(temp / 'baseline-data'), '--expect', str(old_report)],
                                capture_output=True, timeout=120, check=False)
        if result.returncode:
            raise ValueError('Baseline does not match retained head evidence')
        assembled = temp / 'assembled'
        assembled.mkdir(mode=0o700)
        # Materialize the target tree from immutable baseline files and verified fragments.
        # Absent paths are deletions. No overlay of stale permissions and no in-place replay.
        for root, records in manifest['files'].items():
            (assembled / root).mkdir(mode=0o700)
            for name, record in sorted(records.items()):
                target = assembled / root / name
                if record.get('directory'):
                    target.mkdir(mode=0o700)
                else:
                    sha = record['sha256']
                    source = (args.delta / 'blobs' / sha if sha in needed
                              else args.baseline / root / name)
                    copy_file(source, target)
        full_manifest = {'version': 1, 'release': args.release,
                         'created_utc': manifest['created_utc'], 'files': manifest['files']}
        backup.durable_json(assembled / 'manifest.json', full_manifest)
        backup.verify(assembled)
        if (backup.verify(args.baseline) != base or backup.evidence(args.baseline / 'manifest.json') != base_bytes
                or checked_manifest(args.delta / 'delta.json', args.expected_delta_sha256) != delta_bytes
                or verify(args.delta, base, delta_bytes) != manifest):
            raise ValueError('Recovery sources changed during reconstruction')
        backup.reconcile(argparse.Namespace(
            backup=assembled, output=args.output, release=args.release,
            baseline_report=old_report, expected_report=new_report, recovery_tool=args.recovery_tool,
            expected_manifest_sha256=digest(backup.evidence(assembled / 'manifest.json'))),
            provenance={'mode': 'offline-recovery-delta', 'delta_sha256': args.expected_delta_sha256,
                        'baseline_manifest_sha256': digest(base_bytes),
                        'account_state': 'complete current account snapshot from pinned delta; no access merge'})


def add_commands(commands):
    command = commands.add_parser('create-delta', help='Capture offline fragments and current access state against a full baseline')
    command.add_argument('--baseline', type=Path, required=True)
    for name in backup.ROOTS:
        command.add_argument('--' + name, type=Path, required=True)
    command.add_argument('--output', type=Path, required=True)
    command.add_argument('--release', required=True)
    command.add_argument('--offline', action='store_true')
    command.set_defaults(handler=create)
    command = commands.add_parser('replay-delta', help='Reconstruct and verify a new candidate from an exact baseline and recovery delta')
    command.add_argument('--baseline', type=Path, required=True)
    command.add_argument('--delta', type=Path, required=True)
    command.add_argument('--output', type=Path, required=True)
    command.add_argument('--release', required=True)
    command.add_argument('--baseline-report', type=Path, required=True)
    command.add_argument('--expected-report', type=Path, required=True)
    command.add_argument('--expected-delta-sha256', required=True)
    command.add_argument('--recovery-tool', type=Path, required=True)
    command.set_defaults(handler=replay)
