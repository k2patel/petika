#!/usr/bin/env python3
"""Private subprocess for administrator-managed, outbound-only encrypted Git copies.

Credentials arrive on stdin, never in process arguments or persistent plaintext files.
No fetch, checkout, merge, force push, automatic host-key trust, or TLS bypass.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tempfile
import time
from urllib.parse import urlsplit


class TransferError(Exception):
    pass


def private(path, value, executable=False):
    with path.open('x') as stream:
        path.chmod(0o700 if executable else 0o600)
        stream.write(value)


def environment(payload, work):
    url = urlsplit(payload['remote'])
    user = payload['username']
    if (url.scheme not in ('https', 'ssh') or not url.hostname or url.password
            or url.hostname.startswith('-') or not re.fullmatch(r'[A-Za-z0-9._:\[\]-]{1,253}', url.hostname)
            or url.query or url.fragment or not url.path.strip('/')
            or any(c.isspace() or ord(c) < 32 or c == '\\' for c in payload['remote'])
            or not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.@-]{0,99}', user)
            or (url.scheme == 'https' and url.username)
            or (url.scheme == 'ssh' and url.username != user)):
        raise TransferError('invalid_configuration')
    env = {'PATH': os.environ.get('PATH', '/usr/bin:/bin'), 'HOME': str(work),
           'LANG': 'C', 'LC_ALL': 'C', 'GIT_CONFIG_NOSYSTEM': '1',
           'GIT_CONFIG_GLOBAL': os.devnull, 'GIT_TERMINAL_PROMPT': '0',
           'GIT_PROTOCOL_FROM_USER': '0', 'GIT_ATTR_NOSYSTEM': '1'}
    credentials = payload['credentials']
    if url.scheme == 'https':
        token = credentials.get('token', '')
        if not token or len(token) > 4096 or any(ord(c) < 32 or ord(c) == 127 for c in token):
            raise TransferError('invalid_configuration')
        private(work / 'username', user)
        private(work / 'token', token)
        # The helper reads private files; no secret value enters its source or argv.
        helper = '#!' + sys.executable + '\nfrom pathlib import Path\nimport sys\nroot=Path(__file__).parent\nprompt=sys.argv[1].lower()\nname="username" if "username" in prompt else "token" if "password" in prompt else None\nif name is None: sys.exit(1)\nprint((root/name).read_text())\n'
        private(work / 'askpass', helper, True)
        env['GIT_ASKPASS'] = str(work / 'askpass')
    else:
        key = credentials.get('ssh_private_key', '')
        hosts = credentials.get('ssh_known_hosts', '')
        if not key.startswith('-----BEGIN OPENSSH PRIVATE KEY-----') or not hosts.strip() or len(key) > 16384 or len(hosts) > 16384:
            raise TransferError('invalid_configuration')
        private(work / 'identity', key + '\n')
        private(work / 'known_hosts', hosts + '\n')
        env['GIT_SSH_COMMAND'] = shlex.join(['ssh', '-F', os.devnull, '-i', str(work / 'identity'),
            '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes', '-o', 'IdentityAgent=none',
            '-o', 'StrictHostKeyChecking=yes', '-o', 'UserKnownHostsFile=' + str(work / 'known_hosts'),
            '-o', 'GlobalKnownHostsFile=' + os.devnull, '-o', 'ConnectTimeout=10',
            '-o', 'ServerAliveInterval=5', '-o', 'ServerAliveCountMax=2'])
        env['GIT_SSH_VARIANT'] = 'ssh'
    return env


def git(args, env, repository=None):
    command = ['git']
    if repository:
        command += ['--git-dir=' + str(repository), '-c', 'safe.directory=' + str(repository)]
    command += ['-c', 'credential.helper=', '-c', 'credential.interactive=false',
        '-c', 'core.hooksPath=' + os.devnull, '-c', 'protocol.allow=never',
        '-c', 'protocol.https.allow=always', '-c', 'protocol.ssh.allow=always',
        '-c', 'http.followRedirects=false', '-c', 'http.sslVerify=true',
        '-c', 'http.lowSpeedTime=10', '-c', 'http.lowSpeedLimit=1'] + args
    # Bound output without keeping remote-controlled text in memory or logging it.
    with tempfile.TemporaryFile() as output:
        process = subprocess.Popen(command, env=env, stdin=subprocess.DEVNULL,
                                   stdout=output, stderr=subprocess.DEVNULL)
        deadline = time.monotonic() + 30
        try:
            while process.poll() is None:
                if time.monotonic() > deadline or output.tell() > 1024 * 1024:
                    raise TransferError('connection_failed')
                time.sleep(.05)
            if process.returncode:
                raise TransferError('connection_failed')
            output.seek(0)
            result = output.read(1024 * 1024 + 1)
            if len(result) > 1024 * 1024:
                raise TransferError('connection_failed')
            return result.decode('utf-8')
        finally:
            if process.poll() is None:
                process.kill()
            process.wait()


def repositories(root):
    root = Path(root)
    if root.is_symlink() or not root.is_dir():
        raise TransferError('invalid_configuration')
    found = []
    if (root / 'repository.git').exists():
        found.append((root / 'repository.git', 'legacy'))
    for directory in root.iterdir():
        if not re.fullmatch('[0-9a-f]{64}', directory.name):
            continue
        if directory.is_symlink():
            raise TransferError('invalid_configuration')
        for suffix, branch in [('repository.git', 'collections/'), ('entries/repository.git', 'entries/')]:
            repo = directory / suffix
            if repo.exists():
                if repo.is_symlink() or repo.parent.is_symlink():
                    raise TransferError('invalid_configuration')
                found.append((repo, branch + directory.name))
        if len(found) > 8193:
            raise TransferError('invalid_configuration')
    if any(repo.is_symlink() for repo, _ in found):
        raise TransferError('invalid_configuration')
    return sorted(found, key=lambda item: item[1])


def transfer(payload, work):
    env = environment(payload, work)
    remote = payload['remote']
    if payload['action'] == 'test':
        git(['ls-remote', '--heads', '--', remote], env)
        return {'status': 'tested'}  # Read access only; sync verifies write access.
    heads = []
    for repo, branch in repositories(payload['mirror']):
        # gix may create an unborn repository before its first encrypted revision.
        head = repo / 'HEAD'
        if not head.is_file():
            raise TransferError('failed')
        try:
            oid = git(['rev-parse', '--verify', 'HEAD'], env, repo).strip()
        except TransferError:
            # Do not silently skip a corrupt/nonempty repository.
            if (repo / 'objects').is_dir() and not any((repo / 'objects').iterdir()):
                continue
            raise
        if not re.fullmatch('[0-9a-f]{40}|[0-9a-f]{64}', oid):
            raise TransferError('failed')
        heads.append((repo, branch, oid))
    if not heads:
        return {'status': 'empty'}
    fingerprint = hashlib.sha256(json.dumps([(branch, oid) for _, branch, oid in heads]).encode()).hexdigest()
    if fingerprint == payload.get('fingerprint'):
        return {'status': 'unchanged'}
    for repo, branch, oid in heads:
        try:
            git(['push', '--porcelain', '--', remote, oid + ':refs/heads/' + branch], env, repo)
        except TransferError:
            raise TransferError('push_rejected') from None
        confirmation = git(['ls-remote', '--heads', '--', remote, 'refs/heads/' + branch], env)
        if confirmation.strip() != oid + '\trefs/heads/' + branch:
            raise TransferError('push_rejected')
    return {'status': 'synced', 'fingerprint': fingerprint, 'repositories': len(heads)}


def main():
    if len(sys.argv) != 3 or sys.argv[1] != 'git':
        raise SystemExit(2)
    root = Path(sys.argv[2])
    try:
        payload = json.loads(sys.stdin.buffer.read(65537))
        with tempfile.TemporaryDirectory(prefix='git-', dir=root) as work:
            result = transfer(payload, Path(work))
    except TransferError as error:
        result = {'status': str(error)}
    except Exception:
        result = {'status': 'failed'}
    private(root / 'result.json', json.dumps(result))


if __name__ == '__main__':
    main()
