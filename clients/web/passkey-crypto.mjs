// One worker, one verified action. No unwrapped vault key is returned to the page.
import {totp,parseOtp} from './otp.js';
const utf8=new TextEncoder();
export function encode(bytes) {let text='';for(const b of new Uint8Array(bytes))text+=String.fromCharCode(b);return btoa(text).replaceAll('+','-').replaceAll('/','_').replaceAll('=','');}
export function decode(value,expected) {
  if(typeof value!=='string'||!value.length||value.length>2048||!/^[A-Za-z0-9_-]+$/.test(value))throw new Error('Invalid passkey data');
  const bytes=Uint8Array.from(atob(value.replaceAll('-','+').replaceAll('_','/')+'='.repeat((4-value.length%4)%4)),c=>c.charCodeAt(0));
  if(encode(bytes)!==value||(expected!==undefined&&bytes.length!==expected))throw new Error('Invalid passkey data');return bytes;
}
export const random=n=>crypto.getRandomValues(new Uint8Array(n));
export const operationId=()=>Array.from(random(32),n=>n.toString(16).padStart(2,'0')).join('');
export function binding(protection,wrapper) {
  if(protection.policy!=='browser-passkey')throw new Error('A browser passkey cannot claim biometric-only protection.');
  return utf8.encode(JSON.stringify(['petika:browser-passkey-wrap:v1',protection.origin,protection.context.deployment_id,
    protection.owner_user_id,protection.context.collection_id,protection.context.key_epoch,wrapper.credential_id,'browser-passkey',wrapper.prf_input]));
}
async function wrappingKey(prf,wrapper) {
  if(!(prf instanceof Uint8Array)||prf.length!==32)throw new Error('This passkey cannot unlock an encrypted vault. Try another supported authenticator.');
  const material=await crypto.subtle.importKey('raw',prf,'HKDF',false,['deriveKey']);
  return crypto.subtle.deriveKey({name:'HKDF',hash:'SHA-256',salt:decode(wrapper.kdf_salt,32),info:utf8.encode('petika:browser-passkey-kdf:v1')},material,{name:'AES-GCM',length:256},false,['encrypt','decrypt']);
}
export async function wrap(prf,seed,protection,credentialId,input) {
  const wrapper={credential_id:credentialId,prf_input:input,kdf_salt:encode(random(32)),nonce:encode(random(12)),wrapped_key:''};
  wrapper.wrapped_key=encode(await crypto.subtle.encrypt({name:'AES-GCM',iv:decode(wrapper.nonce,12),additionalData:binding(protection,wrapper)},await wrappingKey(prf,wrapper),seed));
  return wrapper;
}
export async function unwrap(prf,protection,credentialId) {
  const wrapper=protection.wrappers.find(w=>w.credential_id===credentialId);
  if(!wrapper)throw new Error('This passkey is not authorized for the vault.');
  return new Uint8Array(await crypto.subtle.decrypt({name:'AES-GCM',iv:decode(wrapper.nonce,12),additionalData:binding(protection,wrapper)},await wrappingKey(prf,wrapper),decode(wrapper.wrapped_key,48)));
}
function checked(protection,scope) {
  const c=protection?.context;
  if(protection?.version!==1||protection.policy!=='browser-passkey'||protection.origin!==scope.origin||protection.owner_user_id!==scope.user_id
    ||c?.deployment_id!==scope.deployment_id||c?.collection_id!==scope.collection_id||c?.key_epoch!==1||!Array.isArray(protection.wrappers)||protection.wrappers.length>16)throw new Error('Vault protection does not match this account and collection.');
}
export async function execute(Session,request,generate) {
  const {scope,action,args=[],credentialId,input,operationId:op}=request;
  const prf=new Uint8Array(request.prf),newPrf=request.newPrf?new Uint8Array(request.newPrf):null;
  let seed,session;
  try {
    let vault=request.vault;
    if(action==='create'||action==='migrate') {
      if(vault)throw new Error('An existing vault cannot be replaced by setup.');
      const protection={version:1,policy:'browser-passkey',context:{deployment_id:scope.deployment_id,collection_id:scope.collection_id,key_epoch:1},owner_user_id:scope.user_id,origin:scope.origin,wrappers:[]};
      seed=random(32);protection.wrappers.push(await wrap(prf,seed,protection,credentialId,input));
      if(action==='migrate') {
        if(typeof request.legacy!=='string'||JSON.parse(request.legacy).version!==1)throw new Error('Only legacy personal vaults can migrate.');
        session=Session.migrate_bound(utf8.encode(request.legacy),args[0],encode(seed),JSON.stringify(protection.context));
        args[0]='';
      } else session=Session.create_bound(encode(seed),JSON.stringify(protection.context));
      vault={version:3,kind:'petika-passkey-vault',protection,encrypted_snapshot:new TextDecoder().decode(session.seal()),operation_id:op};
      return {vault,rows:JSON.parse(session.list())};
    }
    if(vault?.version!==3||vault.kind!=='petika-passkey-vault')throw new Error('Unsupported vault format');
    checked(vault.protection,scope);
    seed=await unwrap(prf,vault.protection,credentialId);
    if(seed.length!==32)throw new Error('Invalid protected key');
    session=Session.open_bound(utf8.encode(vault.encrypted_snapshot),encode(seed),JSON.stringify(vault.protection.context));
    let value;
    switch(action) {
      case 'open':case 'list':value=JSON.parse(session.list());break;
      case 'generate':value=generate(args[0]);break;
      case 'authorize-copy':value=true;break;
      case 'view': {const e=JSON.parse(session.get(args[0]));value={username:e.username,url:e.url,notes:e.notes,otp:Boolean(e.otp)};break;}
      case 'reveal-password':case 'copy-password':value=JSON.parse(session.get(args[0])).password;break;
      case 'copy-username':value=JSON.parse(session.get(args[0])).username;break;
      case 'edit':value=JSON.parse(session.get(args[0]));break;
      case 'otp':value=await totp(JSON.parse(session.get(args[0])).otp||'');break;
      case 'put':parseOtp(args[1].otp||'');session.put(args[0],JSON.stringify(args[1]),Boolean(args[2]));break;
      case 'remove':session.remove(args[0]);break;
      case 'add-key': {
        if(!newPrf||!request.newCredentialId||vault.protection.wrappers.some(w=>w.credential_id===request.newCredentialId))throw new Error('Invalid additional passkey');
        vault=structuredClone(vault);vault.protection.wrappers.push(await wrap(newPrf,seed,vault.protection,request.newCredentialId,request.newInput));
        vault.operation_id=op;return {vault,rows:JSON.parse(session.list())};
      }
      default:throw new Error('Unsupported passkey operation');
    }
    if(action==='put'||action==='remove') {
      vault={...vault,encrypted_snapshot:new TextDecoder().decode(session.seal()),operation_id:op};
      return {vault,rows:JSON.parse(session.list())};
    }
    return {value};
  } finally {if(action==='migrate')args.fill('');session?.free();seed?.fill(0);prf.fill(0);newPrf?.fill(0);}
}
