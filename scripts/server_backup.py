#!/usr/bin/env python3
"""Internal server push worker. Invoked by Petika with private stdin, never over HTTP."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shlex
import sys
import tempfile

import backup_recovery as backup
import offsite_backup as offsite
from user_backup import verify_user_bundle, write_json


def credential(path, value):
    with path.open('x') as stream:
        os.chmod(path, 0o600)
        stream.write(value)
        stream.write('\n')


def capture_user(root):
    bundle=root/'bundle'
    index=json.loads((bundle/'index.json').read_text())
    write_json(bundle/'manifest.json',{'backup_version':1,'kind':'user','owner_id':index['user']['id'],
        'deployment_id':index['deployment_id'],'created_utc':datetime.now(timezone.utc).isoformat(),
        'files':backup.inventory(bundle)})
    verify_user_bundle(bundle)


def push(root, job):
    destination=job['destination']
    secrets=job['credentials']
    result={'verified':False}
    try:
        with tempfile.TemporaryDirectory(prefix='credentials-',dir=root) as temporary:
            private=Path(temporary)
            credential(private/'password',secrets['repository_password'])
            client=offsite.Restic(os.environ.get('PETIKA_BACKUP_RESTIC','restic'),destination['repository'],private/'password',destination['repository_id'])
            # Never inherit ambient provider credentials or restic overrides into a user's job.
            for name in list(client.environment):
                if name.startswith(('AWS_','RESTIC_','PETIKA_')) or name in ('SSH_AUTH_SOCK','SSH_ASKPASS'):
                    client.environment.pop(name)
            client.environment.update(RESTIC_REPOSITORY=destination['repository'],RESTIC_PASSWORD_FILE=str(private/'password'))
            if destination['kind']=='s3':
                client.environment.update(AWS_ACCESS_KEY_ID=secrets['access_key'],AWS_SECRET_ACCESS_KEY=secrets['secret_key'],AWS_EC2_METADATA_DISABLED='true')
                if secrets.get('session_token'): client.environment['AWS_SESSION_TOKEN']=secrets['session_token']
                if secrets.get('region'): client.environment['AWS_DEFAULT_REGION']=secrets['region']
            elif destination['kind']=='sftp':
                credential(private/'identity',secrets['ssh_private_key'])
                credential(private/'known_hosts',secrets['ssh_known_hosts'])
                args=['-F','/dev/null','-oBatchMode=yes','-oIdentitiesOnly=yes','-oStrictHostKeyChecking=yes',
                      '-oGlobalKnownHostsFile=/dev/null','-oUserKnownHostsFile='+str(private/'known_hosts'),'-i',str(private/'identity')]
                client.command=client.command[:4]+['-o','sftp.args='+shlex.join(args)]
            else:
                raise ValueError('Unsupported destination')
            if not destination['repository_id']:
                if not destination['initialize_repository']: raise ValueError('Repository ID required')
                # Init is explicit, never silently attach to an existing unknown repository.
                client.run('init','--repository-version','2')
                client.repository_id=client.identity(required=False)
                result['repository_id']=client.repository_id
                write_json(root/'result.json',result)
            else:
                result['repository_id']=client.identity()
            offsite.publish(client,root/'bundle','petika-'+job['owner'],root/'receipt.json',root/'verification')
            receipt=json.loads((root/'receipt.json').read_text())
            result.update(verified=True,snapshot_id=receipt['snapshot_id'],repository_id=receipt['repository_id'])
    except Exception:
        # Provider messages may contain credentials; expose only a generic failed status.
        pass
    target=root/'result.json'
    if target.exists(): target.unlink()
    write_json(target,result)
    return result['verified']


def main():
    action, directory=sys.argv[1:]
    root=Path(directory)
    job=json.load(sys.stdin)
    if action=='capture-user':
        capture_user(root)
    elif action=='capture-server':
        backup.create(argparse.Namespace(offline=True,output=root/'bundle',release=job['release'],
            **{name:Path(job[name]) for name in backup.ROOTS}))
    elif action=='push':
        (root/'verification').mkdir(mode=0o700)
        if not push(root,job): return 1
    else:
        return 1
    return 0


if __name__=='__main__':
    try:
        sys.exit(main())
    except Exception:
        sys.exit(1)
