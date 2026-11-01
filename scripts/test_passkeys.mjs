import test from 'node:test';
import assert from 'node:assert/strict';
import {wrap,unwrap,encode,decode,binding,random} from '../clients/web/passkey-crypto.mjs';
import {capabilities,serialize,PasskeyClient,canonical} from '../clients/web/passkeys.mjs';
const context={deployment_id:'a'.repeat(64),collection_id:'b'.repeat(64),key_epoch:1};
const profile=()=>({version:1,policy:'browser-passkey',context:{...context},owner_user_id:'b'.repeat(64),origin:'https://vault.example',wrappers:[]});
test('PRF wrapper authenticates every binding and supports two independent passkeys',async()=>{
  const seed=random(32),a=random(32),b=random(32),p=profile();
  p.wrappers.push(await wrap(a,seed,p,encode(random(32)),encode(random(32))));
  p.wrappers.push(await wrap(b,seed,p,encode(random(32)),encode(random(32))));
  assert.deepEqual(await unwrap(a,p,p.wrappers[0].credential_id),seed);
  assert.deepEqual(await unwrap(b,p,p.wrappers[1].credential_id),seed);
  await assert.rejects(unwrap(b,p,p.wrappers[0].credential_id));
  for(const mutate of [p=>p.origin='https://other.example',p=>p.owner_user_id='c'.repeat(64),p=>p.context.key_epoch=2,p=>p.context.collection_id='d'.repeat(64),p=>p.policy='strict-biometric',p=>p.wrappers[0].prf_input=encode(random(32))]){
    const wrong=structuredClone(p);mutate(wrong);await assert.rejects(unwrap(a,wrong,p.wrappers[0].credential_id));
  }
  for(const field of ['kdf_salt','nonce','wrapped_key']) {const wrong=structuredClone(p);const value=decode(wrong.wrappers[0][field]);value[0]^=1;wrong.wrappers[0][field]=encode(value);await assert.rejects(unwrap(a,wrong,p.wrappers[0].credential_id));}
  assert.equal(new TextDecoder().decode(binding(p,p.wrappers[0])),JSON.stringify(['petika:browser-passkey-wrap:v1','https://vault.example',context.deployment_id,p.owner_user_id,context.collection_id,1,p.wrappers[0].credential_id,'browser-passkey',p.wrappers[0].prf_input]));
});
test('browser capability checks never claim biometric-only assurance',async()=>{
  const env={isSecureContext:true,crypto,PublicKeyCredential:{isUserVerifyingPlatformAuthenticatorAvailable:async()=>true,getClientCapabilities:async()=>({'extension:prf':true})},navigator:{credentials:{create(){},get(){}}}};
  assert.deepEqual(await capabilities(env),{supported:true,platformAuthenticator:true,prfHint:true,biometricOnlyProven:false});
  delete env.PublicKeyCredential.getClientCapabilities;delete env.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable;
  assert.deepEqual(await capabilities(env),{supported:true,platformAuthenticator:null,prfHint:null,biometricOnlyProven:false});
  env.isSecureContext=false;assert.equal((await capabilities(env)).supported,false);
});
function fixture() {
  const id=random(32),key=random(32);let calls=0,finish=0,observed;
  const flags=new Uint8Array(37);flags[32]=5;
  const state={flags,wrongId:false,missingPrf:false,deny:false,late:null};
  const credentials={async get(options){calls++;assert.equal(options.publicKey.userVerification,'required');assert.deepEqual(options.publicKey.allowCredentials[0].id,id);observed=key.slice().buffer;
    return {rawId:state.wrongId?random(32):id,response:{authenticatorData:state.flags,clientDataJSON:random(32),signature:random(64),userHandle:null},getClientExtensionResults:()=>state.missingPrf?{}:{prf:{results:{first:observed}}}};}};
  let operation;
  const api=async(path,{body})=>{
    if(path.endsWith('/start')){operation=body.operation_id;return {ceremony_id:'c'.repeat(64),options:{publicKey:{challenge:encode(random(32)),allowCredentials:[{id:encode(id),type:'public-key'}]}}};}
    assert.equal(canonical(body.credential.clientExtensionResults),'{}');assert.equal(JSON.stringify(body).includes('prf'),false);finish++;
    if(state.late)await state.late;
    if(state.deny)throw new Error('Backend signature verification failed');
    return {verified:true,operation_id:operation,grant_id:null,policy:'browser-passkey'};
  };
  const client=new PasskeyClient(api,credentials);
  return {id,key,state,client,counters:()=>({calls,finish}),observed:()=>observed};
}
test('each action uses a new ceremony and never forwards PRF output to server',async()=>{
  const f=fixture();for(let i=0;i<2;i++){const approval=await f.client.verify('b'.repeat(64),encode(f.id),'view',1,encode(random(32)));assert.deepEqual(approval.prf,f.key);approval.prf.fill(0);assert.ok(new Uint8Array(f.observed()).every(b=>b===0));}
  assert.deepEqual(f.counters(),{calls:2,finish:2});
});
test('missing PRF, missing UV, substituted credentials and backend denial fail closed',async()=>{
  for(const mutate of [s=>s.missingPrf=true,s=>s.flags[32]=1,s=>s.wrongId=true,s=>s.deny=true]){
    const f=fixture();mutate(f.state);await assert.rejects(f.client.verify('b'.repeat(64),encode(f.id),'view',1,encode(random(32))));
  }
});
test('cancellation rejects late verification instead of returning a usable key',async()=>{
  const f=fixture();let release;f.state.late=new Promise(resolve=>release=resolve);
  const pending=f.client.verify('b'.repeat(64),encode(f.id),'view',1,encode(random(32)));
  while(!f.counters().finish)await new Promise(resolve=>setImmediate(resolve));
  f.client.cancel();release();await assert.rejects(pending,{name:'AbortError'});
});
test('credential serializer excludes all extensions and canonical comparison ignores object order',()=>{
  const c={rawId:new Uint8Array([1]),response:{clientDataJSON:new Uint8Array([2]),authenticatorData:new Uint8Array([3]),signature:new Uint8Array([4]),userHandle:null},getClientExtensionResults:()=>{throw new Error('Secret extensions must not be serialized')}};
  assert.deepEqual(serialize(c).clientExtensionResults,{});
  assert.equal(canonical({b:2,a:[{z:1,x:2}]}),canonical({a:[{x:2,z:1}],b:2}));
  for(const bad of ['AA==','AA+','', '%%%'])assert.throws(()=>decode(bad));
});
test('cancellation generation remains monotonic when an in-flight operation finishes',async()=>{
  const f=fixture();assert.equal(f.client.generation,0);
  let release;f.client.api=()=>new Promise(resolve=>release=resolve);
  const pending=f.client.run(null,{collection_id:'b'.repeat(64),revision:0},encode(f.id),'create');
  f.client.cancel();release({revision:0,vault:null});
  await assert.rejects(pending,{name:'AbortError'});
  assert.equal(f.client.generation,1);assert.equal(f.client.busy,false);
  f.client.cancel();assert.equal(f.client.generation,2);
});
test('registration requests a discoverable verified passkey and preserves duplicate exclusion',async()=>{
  const id=encode(random(32));let finishes=0;
  const client=new PasskeyClient(async path=>{
    if(path.endsWith('/finish')){finishes++;return {};}
    return {ceremony_id:'c'.repeat(64),options:{publicKey:{challenge:encode(random(32)),user:{id:encode(random(16)),name:'fixture',displayName:'Fixture'},authenticatorSelection:{residentKey:'discouraged'},excludeCredentials:[{type:'public-key',id}]}}};
  },{async create({publicKey}){
    assert.equal(publicKey.authenticatorSelection.residentKey,'required');
    assert.equal(publicKey.authenticatorSelection.userVerification,'required');
    assert.deepEqual(publicKey.excludeCredentials[0].id,decode(id));
    throw new DOMException('The object is in an invalid state.','InvalidStateError');
  }});
  await assert.rejects(client.enroll('synthetic password','Fixture'),error=>error.code==='passkey-already-registered'&&error.cause.name==='InvalidStateError'&&error.message.includes('registered passkey'));
  assert.equal(finishes,0);
});
