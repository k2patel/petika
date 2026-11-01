import {decode,encode,operationId,random} from './passkey-crypto.mjs';
export const canonical=value=>JSON.stringify(value,(_,v)=>v&&typeof v==='object'&&!Array.isArray(v)?Object.fromEntries(Object.keys(v).sort().map(k=>[k,v[k]])):v);
export async function capabilities(env=globalThis) {
  const supported=Boolean(env.isSecureContext&&env.PublicKeyCredential&&env.navigator?.credentials?.create&&env.navigator?.credentials?.get&&env.crypto?.subtle);
  let platform=null,prf=null;
  if(supported) {
    try {platform=await env.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable?.()??null;}catch{}
    try {prf=(await env.PublicKeyCredential.getClientCapabilities?.())?.['extension:prf']??null;}catch{}
  }
  return {supported,platformAuthenticator:platform,prfHint:prf,biometricOnlyProven:false};
}
function options(source,registration) {
  const o=structuredClone(source.publicKey);o.challenge=decode(o.challenge);
  if(registration) {o.user.id=decode(o.user.id);o.excludeCredentials=o.excludeCredentials?.map(c=>({...c,id:decode(c.id)}));o.extensions={...o.extensions,prf:{}};}
  else {o.allowCredentials=o.allowCredentials?.map(c=>({...c,id:decode(c.id)}));}
  return o;
}
// Explicit allowlist: never send PRF extension outputs or encryption material to the server.
export function serialize(credential,registration=false) {
  const response={clientDataJSON:encode(credential.response.clientDataJSON)};
  if(registration) {response.attestationObject=encode(credential.response.attestationObject);response.transports=credential.response.getTransports?.()||[];}
  else {response.authenticatorData=encode(credential.response.authenticatorData);response.signature=encode(credential.response.signature);response.userHandle=credential.response.userHandle?encode(credential.response.userHandle):null;}
  return {id:encode(credential.rawId),rawId:encode(credential.rawId),type:'public-key',response,clientExtensionResults:{}};
}
export class PasskeyClient {
  constructor(api,credentials=navigator.credentials) {this.api=api;this.credentials=credentials;this.controller=null;this.busy=false;this.generation=0;}
  cancel() {this.generation++;this.controller?.abort();}
  async enroll(password,label) {
    const generation=this.generation;
    const start=await this.api('/v1/passkeys/registration/start',{method:'POST',body:{current_password:password,label}});
    if(generation!==this.generation)throw new DOMException('Operation cancelled','AbortError');
    this.controller=new AbortController();const signal=this.controller.signal;
    const c=await this.credentials.create({publicKey:options(start.options,true),signal});signal.throwIfAborted();
    if(!c)throw new Error('Passkey setup was cancelled.');
    const result=await this.api('/v1/passkeys/registration/finish',{method:'POST',body:{ceremony_id:start.ceremony_id,credential:serialize(c,true)}});
    signal.throwIfAborted();if(generation!==this.generation)throw new DOMException('Operation cancelled','AbortError');return result;
  }
  async verify(collectionId,credentialId,action,revision,input,newCredentialId=null) {
    const generation=this.generation;
    const op=operationId();
    const body={collection_id:collectionId,credential_id:credentialId,action,revision,operation_id:op,...(newCredentialId?{new_credential_id:newCredentialId}:{})};
    const start=await this.api('/v1/passkeys/authentication/start',{method:'POST',body});
    if(generation!==this.generation)throw new DOMException('Operation cancelled','AbortError');
    this.controller=new AbortController();const signal=this.controller.signal;
    const publicKey=options(start.options,false);publicKey.userVerification='required';
    publicKey.extensions={...publicKey.extensions,prf:{eval:{first:decode(input,32)}}};
    const c=await this.credentials.get({publicKey,signal});signal.throwIfAborted();
    if(!c||encode(c.rawId)!==credentialId)throw new Error('Passkey mismatch');
    const bytes=new Uint8Array(c.response.authenticatorData);
    if(bytes.length<37||(bytes[32]&5)!==5)throw new Error('Passkey user verification is required.');
    const output=c.getClientExtensionResults()?.prf?.results?.first;
    if(!output||output.byteLength!==32)throw new Error('This passkey cannot unlock an encrypted vault. Try a compatible authenticator or browser.');
    const exposed=ArrayBuffer.isView(output)?new Uint8Array(output.buffer,output.byteOffset,output.byteLength):new Uint8Array(output);const prf=exposed.slice();exposed.fill(0);
    try {
      const verified=await this.api('/v1/passkeys/authentication/finish',{method:'POST',body:{ceremony_id:start.ceremony_id,credential:serialize(c)}});
      signal.throwIfAborted();if(verified.verified!==true||verified.operation_id!==op||verified.policy!=='browser-passkey')throw new Error('Passkey verification failed.');
      return {prf,operationId:op,grantId:verified.grant_id};
    } catch(e) {prf.fill(0);throw e;}
  }
  async worker(message) {
    const signal=this.controller?.signal;signal?.throwIfAborted();
    const worker=new Worker('/worker.js',{type:'module'});let abort,timer;
    try {return await new Promise((resolve,reject)=>{
      timer=setTimeout(()=>reject(new Error('Protected operation timed out.')),30000);
      abort=()=>reject(new DOMException('Operation cancelled','AbortError'));
      signal?.addEventListener('abort',abort,{once:true});
      worker.onmessage=({data})=>{clearTimeout(timer);data.error?reject(new Error(data.error)):resolve(data.value)};
      worker.onerror=()=>{clearTimeout(timer);reject(new Error('Protected operation failed.'))};
      const transfers=[message.prf];if(message.newPrf)transfers.push(message.newPrf);
      worker.postMessage({id:1,action:'passkey-execute',args:[message]},transfers);
    });}finally{clearTimeout(timer);if(abort)signal?.removeEventListener('abort',abort);worker.terminate();}
  }
  async run(vault,scope,credentialId,action,args=[],extra={}) {
    if(this.busy)throw new Error('Finish the current passkey operation first.');
    this.busy=true;let approval;const generation=this.generation;
    vault=structuredClone(vault);scope=structuredClone(scope);args=structuredClone(args);
    try {
      const current=await this.api(`/v1/${action==='migrate'?'passkey-migrations':'passkey-vaults'}/${scope.collection_id}`);
      if(generation!==this.generation)throw new DOMException('Operation cancelled','AbortError');
      if(current.revision!==scope.revision)throw new Error('The vault changed. Refresh before trying again.');
      if(action==='migrate'&&(current.vault||current.legacy!==vault))throw new Error('The legacy vault changed. Refresh and review before migrating.');
      if(action!=='migrate'&&vault&&canonical(current.vault)!==canonical(vault))throw new Error('The vault changed. Refresh before trying again.');
      const input=current.vault?.protection.wrappers.find(w=>w.credential_id===credentialId)?.prf_input||encode(random(32));
      approval=await this.verify(scope.collection_id,credentialId,action,scope.revision,input,extra.newCredentialId);
      const result=await this.worker({scope,action,args:structuredClone(args),vault:current.vault,legacy:action==='migrate'?current.legacy:null,credentialId,input,operationId:approval.operationId,prf:approval.prf.buffer,newCredentialId:extra.newCredentialId,newPrf:extra.newPrf,newInput:extra.newInput});
      this.controller.signal.throwIfAborted();if(generation!==this.generation)throw new DOMException('Operation cancelled','AbortError');
      if(result.vault) {
        result.pending={grant_id:approval.grantId,vault:result.vault};
        result.expectedRevision=scope.revision;
      }
      return result;
    } finally {if(action==='migrate')args.fill('');if(approval?.prf.byteLength)approval.prf.fill(0);this.busy=false;}
  }
}
