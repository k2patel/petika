#!/usr/bin/env python3
"""Offline full backups and authenticated historical ciphertext recovery (stdlib only)."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile

ROOTS = ('data', 'mirror', 'config')
LIMIT = 12 * 1024 * 1024


def inventory(root):
    """Reject links and special files; record empty directories as well as file hashes."""
    if root.is_symlink() or not root.is_dir():
        raise ValueError('Backup root must be a real directory')
    result = {}
    for path in sorted(root.rglob('*')):
        mode = path.lstat().st_mode
        name = path.relative_to(root).as_posix()
        if stat.S_ISDIR(mode):
            result[name] = {'directory': True}
        elif stat.S_ISREG(mode):
            digest = hashlib.sha256()
            with path.open('rb') as stream:
                for block in iter(lambda: stream.read(1024 * 1024), b''):
                    digest.update(block)
            result[name] = {'size': path.stat().st_size, 'sha256': digest.hexdigest()}
        else:
            raise ValueError('Symlinks and special files are not supported')
    return result


def private_copy(source, destination):
    destination.mkdir(mode=0o700)
    for name, record in inventory(source).items():
        target = destination / name
        if record.get('directory'):
            target.mkdir(mode=0o700)
        else:
            with (source / name).open('rb') as src, target.open('xb') as dst:
                os.chmod(target, 0o600)
                shutil.copyfileobj(src, dst)
                dst.flush()
                os.fsync(dst.fileno())


def separate(paths):
    resolved = [path.resolve() for path in paths]
    for i, left in enumerate(resolved):
        for right in resolved[i + 1:]:
            if left == right or left in right.parents or right in left.parents:
                raise ValueError('Source and destination directories must not overlap')


def create(args):
    if not args.offline:
        raise ValueError('Stop the server and mirror writers, then specify --offline')
    sources = {name: getattr(args, name) for name in ROOTS}
    separate([*sources.values(), args.output])
    before = {name: inventory(path) for name, path in sources.items()}
    # Exclusive destination: a failed backup has no manifest and cannot be restored.
    args.output.mkdir(mode=0o700)
    for name, source in sources.items():
        private_copy(source, args.output / name)
    after = {name: inventory(path) for name, path in sources.items()}
    copied = {name: inventory(args.output / name) for name in ROOTS}
    if before != after or before != copied:
        raise ValueError('Source changed or copy is incomplete; discard this incomplete backup')
    manifest = {'version': 1, 'created_utc': datetime.now(timezone.utc).isoformat(),
                'release': args.release, 'files': copied}
    with (args.output / 'manifest.json').open('x') as stream:
        os.chmod(stream.name, 0o600)
        json.dump(manifest, stream, indent=2)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())
    verify(args.output)
    print('Complete offline backup verified. Keep it private and copy it off-site.')


def verify(backup):
    inventory(backup)  # Reject links even in manifest.json or unexpected paths.
    if {p.name for p in backup.iterdir()} != {*ROOTS, 'manifest.json'}:
        raise ValueError('Incomplete backup or unexpected top-level files')
    manifest = json.loads((backup / 'manifest.json').read_text())
    if not isinstance(manifest, dict) or manifest.get('version') != 1 or set(manifest.get('files', {})) != set(ROOTS):
        raise ValueError('Unsupported or incomplete backup manifest')
    if not isinstance(manifest.get('release'), str) or not manifest['release']:
        raise ValueError('Missing compatible release identifier')
    actual = {name: inventory(backup / name) for name in ROOTS}
    if actual != manifest['files']:
        raise ValueError('Backup integrity check failed: missing, changed, or extra files')
    return manifest


def restore(args, announce=True):
    separate([args.backup, args.output])
    manifest = verify(args.backup)
    if manifest['release'] != args.release:
        raise ValueError('Release does not match backup; use the recorded compatible binary/image')
    args.output.mkdir(mode=0o700)
    for name in ROOTS:
        private_copy(args.backup / name, args.output / name)
    actual = {name: inventory(args.output / name) for name in ROOTS}
    if actual != manifest['files']:
        raise ValueError('Restore verification failed; do not start this server')
    with (args.output / 'RESTORE.json').open('x') as stream:
        os.chmod(stream.name, 0o600)
        json.dump({'version': 1, 'release': manifest['release'],
                   'backup_created_utc': manifest['created_utc'],
                   'restored_utc': datetime.now(timezone.utc).isoformat()}, stream, indent=2)
    if announce:
        print('Verified restore staged. Start isolated with the recorded release before cutover.')


def evidence(path):
    if not stat.S_ISREG(path.lstat().st_mode) or path.stat().st_size > 16 * 1024 * 1024:
        raise ValueError('Evidence must be a bounded regular file, not a link')
    with path.open('rb') as stream:
        value = stream.read(16 * 1024 * 1024 + 1)
    if len(value) > 16 * 1024 * 1024:
        raise ValueError('Evidence exceeds limit')
    return value


def durable_json(path, value):
    with path.open('x') as stream:
        os.chmod(path, 0o600)
        json.dump(value, stream, indent=2)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())


def reconcile(args):
    """Stage an independently identified complete successor backup; never replay fragments."""
    separate([args.backup, args.output, args.baseline_report, args.expected_report])
    if args.output.exists() or args.output.is_symlink():
        raise ValueError('Output exists; choose a new directory')
    if not re.fullmatch(r'[0-9a-f]{64}', args.expected_manifest_sha256):
        raise ValueError('Supply the independently retained manifest SHA-256')
    manifest_bytes = evidence(args.backup / 'manifest.json')
    if hashlib.sha256(manifest_bytes).hexdigest() != args.expected_manifest_sha256:
        raise ValueError('Backup does not match the independently retained manifest hash')
    baseline = evidence(args.baseline_report)
    expected = evidence(args.expected_report)
    manifest = verify(args.backup)
    if manifest != json.loads(manifest_bytes):
        raise ValueError('Manifest changed during validation')
    if manifest['release'] != args.release:
        raise ValueError('Release does not match backup')
    with tempfile.TemporaryDirectory(prefix='.petika-reconcile-', dir=args.output.parent) as temporary:
        temporary = Path(temporary)
        stage = temporary / 'candidate'
        restore(argparse.Namespace(backup=args.backup, output=stage, release=args.release), announce=False)
        old_report, new_report = temporary / 'baseline.json', temporary / 'expected.json'
        for path, content in [(old_report, baseline), (new_report, expected)]:
            with path.open('xb') as stream:
                os.chmod(path, 0o600)
                stream.write(content)
        def compare(path):
            result = subprocess.run([str(args.recovery_tool), str(stage / 'data'), '--compare', str(path)],
                                    capture_output=True, timeout=120, check=False)
            if result.returncode not in (0, 2) or len(result.stdout) > 16 * 1024 * 1024:
                raise ValueError('Offline journal/evidence validation failed; no output published')
            report = json.loads(result.stdout)
            if (report.get('version') != 1 or not isinstance(report.get('collections'), list)
                    or not report['collections']
                    or report.get('exact_match') is not (result.returncode == 0)):
                raise ValueError('Unexpected or empty comparison report')
            return report
        latest = compare(new_report)
        if not latest['exact_match'] or any(r['status'] != 'matches' for r in latest['collections']):
            raise ValueError('Candidate does not match every expected retained head')
        ancestry = compare(old_report)
        permitted = {'matches', 'retained-head-in-local-history', 'not-in-retained-report'}
        if (any(r['status'] not in permitted for r in ancestry['collections'])
                or not any(r['status'] == 'retained-head-in-local-history' for r in ancestry['collections'])):
            raise ValueError('Candidate is not a proven successor of the retained baseline')
        # Native audit may create lock sidecars, but no backed-up bytes may change.
        for name in ROOTS:
            actual = inventory(stage / name)
            if any(actual.get(path) != value for path, value in manifest['files'][name].items()):
                raise ValueError('Audit changed backed-up state')
        if verify(args.backup) != manifest or evidence(args.backup / 'manifest.json') != manifest_bytes:
            raise ValueError('Source backup changed during validation')
        # This command has its own last-written completion marker.
        (stage / 'RESTORE.json').unlink()
        staged = inventory(stage)
        private_copy(stage, args.output)
        if inventory(args.output) != staged:
            raise ValueError('Published candidate differs from verified stage; do not start it')
        # Last marker: failures during publication leave an incomplete, unapproved directory.
        receipt = temporary / 'RECONCILIATION.json'
        durable_json(receipt, {
            'version': 1, 'mode': 'complete-successor-backup', 'release': args.release,
            'manifest_sha256': args.expected_manifest_sha256,
            'baseline_report_sha256': hashlib.sha256(baseline).hexdigest(),
            'expected_report_sha256': hashlib.sha256(expected).hexdigest(),
            'account_state': 'entire selected backup; no account or access merge',
            'ancestry': ancestry, 'expected': latest,
            'next': 'verify retained client pins, decrypt, and validate access in isolation before cutover'})
        os.link(receipt, args.output / 'RECONCILIATION.json')
    print('Complete successor backup staged with journal receipts and account state. Verify client trust and access in isolation before cutover.')


def git(repository, *arguments):
    result = subprocess.run(['git', '--no-replace-objects', '-C', str(repository), *arguments],
                            capture_output=True, check=False)
    if result.returncode:
        raise ValueError('Git operation failed; verify repository, commit, and complete object history')
    return result.stdout


def check_repository(repository):
    if git(repository, 'rev-parse', '--is-shallow-repository').strip() != b'false':
        raise ValueError('Shallow mirrors are incomplete; fetch full history first')
    git(repository, 'fsck', '--full', '--strict')


def snapshot(repository, commit):
    if not re.fullmatch(r'[0-9a-f]{40}|[0-9a-f]{64}', commit):
        raise ValueError('Select a full commit ID from history')
    git(repository, 'cat-file', '-e', commit + '^{commit}')
    spec = commit + ':snapshot.json'
    if int(git(repository, 'cat-file', '-s', spec)) > LIMIT:
        raise ValueError('Snapshot exceeds size limit')
    saved = json.loads(git(repository, 'show', spec))
    if (not isinstance(saved, dict) or saved.get('schema_version', 1) != 1 or type(saved.get('revision')) is not int
            or saved['revision'] < 1 or not isinstance(saved.get('encrypted'), str)):
        raise ValueError('Unsupported mirror snapshot')
    return saved


def complete_history(repository, tip):
    rows = git(repository, 'rev-list', '--first-parent', '--parents', tip).decode().splitlines()
    records = []
    for index, row in enumerate(rows):
        fields = row.split()
        # Petika mirrors start at revision 1 and never merge or skip revisions.
        if len(fields) != (2 if index + 1 < len(rows) else 1):
            raise ValueError('Mirror history is incomplete or contains a merge')
        saved = snapshot(repository, fields[0])
        if saved['revision'] != len(rows) - index:
            raise ValueError('Mirror history has missing or out-of-order revisions')
        records.append((fields[0], saved['revision']))
    if not records:
        raise ValueError('Empty mirror history')
    return records


def history(args):
    check_repository(args.repository)
    if not re.fullmatch(r'legacy|collections/[0-9a-f]{64}', args.branch):
        raise ValueError('Expected legacy or collections/<64 lowercase hex characters>')
    records = complete_history(args.repository, 'refs/heads/' + args.branch)
    for commit, revision in records:
        print(f'{commit} revision={revision}')


def recover(args):
    check_repository(args.repository)
    saved = snapshot(args.repository, args.commit)
    complete_history(args.repository, args.commit)
    if args.output.exists() or args.output.is_symlink():
        raise ValueError('Output exists; choose a new file')
    # Same filesystem allows atomic, no-clobber publication after Rust authentication.
    with tempfile.TemporaryDirectory(prefix='.petika-recovery-', dir=args.output.parent) as temp:
        candidate = Path(temp) / 'store.petika'
        candidate.write_text(saved['encrypted'])
        candidate.chmod(0o600)
        command = [str(args.cli), '--store', str(candidate)]
        if args.passphrase_stdin:
            command.append('--passphrase-stdin')
        # list authenticates and parses the entire envelope, including v2 recovery wrappers.
        # Suppress entry names; secrets are read by the Rust process, never Python arguments.
        result = subprocess.run(command + ['list'], stdout=subprocess.DEVNULL, check=False)
        if result.returncode:
            raise ValueError('Snapshot authentication failed; no recovered file was published')
        with candidate.open('rb') as stream:
            os.fsync(stream.fileno())
        os.link(candidate, args.output)
    print(f'Authenticated snapshot recovered locally from revision {saved["revision"]}, commit {args.commit}. Server unchanged.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    command = commands.add_parser('create', help='Copy a stopped server and operator configuration')
    for name in ROOTS:
        command.add_argument('--' + name, type=Path, required=True)
    command.add_argument('--output', type=Path, required=True)
    command.add_argument('--release', required=True, help='Exact compatible git SHA or image digest')
    command.add_argument('--offline', action='store_true', help='Confirm all source writers are stopped')
    command = commands.add_parser('verify')
    command.add_argument('backup', type=Path)
    command = commands.add_parser('restore', help='Stage into a new directory; never overwrite live state')
    command.add_argument('backup', type=Path)
    command.add_argument('--output', type=Path, required=True)
    command.add_argument('--release', required=True)
    command = commands.add_parser('reconcile', help='Stage a proven complete successor backup into a new directory')
    command.add_argument('backup', type=Path)
    command.add_argument('--output', type=Path, required=True)
    command.add_argument('--release', required=True)
    command.add_argument('--baseline-report', type=Path, required=True)
    command.add_argument('--expected-report', type=Path, required=True)
    command.add_argument('--expected-manifest-sha256', required=True)
    command.add_argument('--recovery-tool', type=Path, required=True)
    command = commands.add_parser('history', help='List commits in a full bare backup clone')
    command.add_argument('repository', type=Path)
    command.add_argument('--branch', required=True)
    command = commands.add_parser('recover', help='Authenticate and recover a selected commit locally')
    command.add_argument('repository', type=Path)
    command.add_argument('--commit', required=True)
    command.add_argument('--output', type=Path, required=True)
    command.add_argument('--cli', type=Path, required=True)
    command.add_argument('--passphrase-stdin', action='store_true')
    args = parser.parse_args()
    try:
        if args.command == 'verify':
            verify(args.backup)
            print('Backup file inventory and SHA-256 checks passed.')
        else:
            globals()[args.command](args)
    except (ValueError, OSError, KeyError, TypeError, subprocess.TimeoutExpired) as error:
        parser.exit(1, f'Error: {error}\n')


if __name__ == '__main__':
    main()
