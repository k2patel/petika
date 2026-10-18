import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
const source = fs.readFileSync(new URL('../clients/web/app.js', import.meta.url), 'utf8');
const context = vm.createContext({URL});
vm.runInContext(source.slice(source.indexOf('function backupRepository('), source.indexOf('function destinationDialog(')), context);
const repository = values => context.backupRepository(new Map(Object.entries(values)));
assert.equal(repository({kind:'s3',s3_endpoint:'https://store.example.com:9443/',s3_bucket:'my-backups',s3_folder:'/family/petika/'}),'s3:https://store.example.com:9443/my-backups/family/petika');
assert.equal(repository({kind:'s3',s3_endpoint:'https://store.example.com',s3_bucket:'my-backups',s3_folder:''}),'s3:https://store.example.com/my-backups');
assert.equal(repository({kind:'sftp',ssh_host:'backup.example.com',ssh_user:'backup',ssh_port:'2222',ssh_path:'/backups/petika'}),'sftp://backup@backup.example.com:2222//backups/petika');
assert.equal(repository({kind:'sftp',ssh_host:'10.0.0.5',ssh_user:'backup',ssh_path:'/backups'}),'sftp://backup@10.0.0.5//backups');
const advanced='sftp://backup@[2001:db8::1]:2222//custom/path';
assert.equal(repository({advanced_repository:'on',repository:advanced}),advanced);
for(const endpoint of ['http://store.example.com','https://user:secret@store.example.com','https://store.example.com/path','https://store.example.com?token=secret']) {
 assert.throws(()=>repository({kind:'s3',s3_endpoint:endpoint,s3_bucket:'my-backups'}));
}
for(const path of ['../escape','a/../escape','a//b','a/./b','a?b','a#b']) {
 assert.throws(()=>repository({kind:'s3',s3_endpoint:'https://store.example.com',s3_bucket:'my-backups',s3_folder:path}));
 assert.throws(()=>repository({kind:'sftp',ssh_host:'host',ssh_user:'user',ssh_path:'/'+path}));
}
for(const port of ['0','65536','22:80','22.5']) assert.throws(()=>repository({kind:'sftp',ssh_host:'host',ssh_user:'user',ssh_path:'/backups',ssh_port:port}));
assert.throws(()=>repository({kind:'sftp',ssh_host:'host/other',ssh_user:'user',ssh_path:'/backups'}));
console.log('Backup URL construction, advanced preservation and unsafe-input rejection passed.');
