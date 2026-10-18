import {authorizeFill, httpsOrigin, fillPage} from './fill.mjs';
const $ = id => document.getElementById(id);
const {endpoint} = await (await fetch('./config.json')).json();
let token, worker, sequence = 0, collection, target, unlocked = false, timer;
let collections = [], snapshotRevision = 0, accessState = null, editable = false, saveBlocked = false, generation = 0;
const pending = new Map();
const message = text => { $('message').textContent = text; };
async function request(path, body, raw = false, method, headers = {}) {
  const response = await fetch(endpoint + path, {
    method:method || (body === undefined ? 'GET' : 'POST'), credentials:'omit', cache:'no-store', redirect:'error',
    headers:{'Content-Type':'application/json','X-Petika-Request':'1',...(token ? {Authorization:`Bearer ${token}`} : {}),...headers},
    body:body === undefined ? undefined : typeof body === 'string' ? body : JSON.stringify(body), signal:AbortSignal.timeout(15000)
  });
  if (!response.ok) {
    const error = new Error(response.status === 409 ? 'This collection changed on another device. Reopen and unlock before saving again.' : `Petika request failed (${response.status}). Check your connection and account session.`);
    error.status = response.status; throw error;
  }
  return raw === 'response' ? response : raw ? response.text() : response.json();
}
function rpc(action, ...args) {
  if (!worker) {
    worker = new Worker('./worker.js', {type:'module'});
    worker.onmessage = ({data}) => {
      const promise = pending.get(data.id);
      pending.delete(data.id);
      if (data.error) promise?.reject(new Error(data.error)); else promise?.resolve(data.value);
    };
    worker.onerror = () => lock();
  }
  return new Promise((resolve,reject) => {
    const id = ++sequence;
    pending.set(id,{resolve,reject}); worker.postMessage({id,action,args});
  });
}
function lock() {
  generation++; snapshotRevision = 0; accessState = null; editable = false; saveBlocked = false;
  clearGenerator(); $('generate').hidden = true;
  worker?.terminate(); worker = null; unlocked = false; clearTimeout(timer);
  for (const p of pending.values()) p.reject(new Error('Vault locked.'));
  pending.clear(); $('passphrase').value = ''; $('matches').replaceChildren();
  $('vault').hidden = true; $('unlock').hidden = !token;
}
function touch() { clearTimeout(timer); timer = setTimeout(() => { lock(); message('Locked after five minutes.'); },300000); }
async function showAccount() {
  const status = await request('/v1/auth/status');
  if (!status.user) {
    token = null; await chrome.storage.session.remove('token'); lock();
    $('connect').hidden = false; $('disconnect').hidden = true;
    throw new Error('Session ended. Connect to Petika again.');
  }
  collections = await request('/v1/collections');
  $('collection').replaceChildren(...collections.map(c => new Option(c.name,c.id)));
  $('connect').hidden = true; $('unlock').hidden = false; $('disconnect').hidden = false;
  message(`Signed in as ${status.user.username}. Unlock to find matching logins.`);
}
async function capturedDocument() {
  const [tab] = await chrome.tabs.query({active:true,currentWindow:true});
  if (!tab?.id) throw new Error('Open Petika from the toolbar on a website.');
  const origin = httpsOrigin(tab.url);
  const [result] = await chrome.scripting.executeScript({target:{tabId:tab.id,frameIds:[0]},func:() => ({url:location.href})});
  if (!result?.documentId || httpsOrigin(result.result.url) !== origin) throw new Error('Website changed. Reopen Petika.');
  return {tabId:tab.id,documentId:result.documentId,origin};
}
async function fill(name, kind) {
  if (!unlocked || !target) throw new Error('Unlock on a website first.');
  const current = await capturedDocument();
  if (current.tabId !== target.tabId || current.documentId !== target.documentId || current.origin !== target.origin) throw new Error('Website changed. Reopen Petika.');
  // Each fill rechecks account access, collection access, and live website permissions.
  const status = await request('/v1/auth/status');
  if (!status.user) { lock(); throw new Error('Account session revoked.'); }
  await request(`/v1/collections/${collection}/status`);
  const {origins} = await request('/v1/auth/websites');
  const entry = (await rpc('list')).find(row => row.name === name);
  if (!entry) throw new Error('Login is no longer available.');
  authorizeFill(current.origin,entry.url,origins);
  let values, expiresAt = Date.now()+5000;
  if (kind === 'otp') {
    const code = await rpc('otp',name);
    if (!code || code.remaining <= 5) throw new Error('Code is about to expire. Wait a few seconds and choose Fill code again.');
    values = {code:code.code}; expiresAt = Math.min(expiresAt,Date.now()+(code.remaining-2)*1000);
  } else {
    const login = await rpc('get',name);
    values = {username:login.username || '',password:login.password || ''};
    login.password = '';
  }
  try {
    const results = await chrome.scripting.executeScript({target:{tabId:target.tabId,documentIds:[target.documentId]},world:'ISOLATED',func:fillPage,args:[current.origin,kind,values,expiresAt]});
    if (!results[0]?.result?.filled) throw new Error('No field was filled. Use copy from the Petika web app.');
    message(kind === 'otp' ? 'Verification code filled. Submit when ready.' : kind === 'new-password' ? 'Saved password filled into the new-password fields. Complete the website change yourself.' : 'Login filled. Submit when ready.');
    touch();
  } finally { values = null; entry.password = ''; }
}
function run(fn) {
  return async event => {
    event?.preventDefault();
    const controls = [...document.querySelectorAll('button,input,select')]; controls.forEach(el => el.disabled = true);
    try { await fn(); } catch(e) { message(e.message); }
    finally { controls.forEach(el => el.disabled = false); }
  };
}
$('start').onclick = run(async () => {
  const grant = await request('/v1/auth/device/start',{});
  await chrome.storage.session.set({grant:{...grant,endpoint,expiresAt:Date.now()+grant.expires_in*1000}});
  $('code').textContent = grant.user_code; $('approval').hidden = false;
  message('Open the approval page, enter this code, then return here and finish connecting.');
});
$('approve').onclick = () => chrome.tabs.create({url:endpoint+'/?cli=1'});
$('finish').onclick = run(async () => {
  const {grant} = await chrome.storage.session.get('grant');
  if (!grant || grant.endpoint !== endpoint || Date.now() >= grant.expiresAt) throw new Error('Code expired. Start a new connection.');
  const result = await request('/v1/auth/device/poll',{device_code:grant.device_code});
  if (result.status !== 'approved') throw new Error(`Approval ${result.status}. Approve your code in Petika, then try again.`);
  if (!/^cli_[a-f0-9]{64}$/.test(result.token)) throw new Error('Unexpected session token.');
  token = result.token; await chrome.storage.session.set({token,endpoint}); await chrome.storage.session.remove('grant');
  await showAccount();
});
$('unlock').onsubmit = run(async () => {
  lock();
  target = await capturedDocument(); $('site').textContent = target.origin; collection = $('collection').value;
  const {origins} = await request('/v1/auth/websites');
  if (!origins.includes(target.origin)) throw new Error('Allow this website under Browser autofill → Manage websites in Petika.');
  const response = await request(`/v1/collections/${collection}/snapshot`,undefined,'response');
  snapshotRevision = readRevision(response.headers.get('ETag'));
  const snapshot = await response.text();
  accessState = JSON.parse(snapshot).version === 2 ? await request(`/v1/collections/${collection}/key-access`) : null;
  if (accessState && accessState.snapshot_revision !== snapshotRevision) throw new Error('Collection changed while unlocking. Try again.');
  collections = await request('/v1/collections');
  editable = Boolean(collections.find(c => c.id === collection)?.edit);
  // Passphrase is read below by the form handler before lock clears it.
  await rpc('open',snapshot,unlockPassphrase);
  unlockPassphrase = ''; unlocked = true; touch();
  await renderMatches(origins);
  $('unlock').hidden=true; $('vault').hidden=false;
});
async function renderMatches(origins) {
  const rows = await rpc('list');
  $('matches').replaceChildren(); let count = 0;
  for (const row of rows) {
    try { authorizeFill(target.origin,row.url,origins); } catch { continue; }
    const section = document.createElement('div'); section.className = 'match';
    const title = document.createElement('h3'); title.textContent = row.name; section.append(title);
    const actions = document.createElement('div'); actions.className = 'actions';
    for (const [label,kind] of [['Fill login','login'],['Fill new password','new-password'],...(row.otp ? [['Fill code','otp']] : [])]) {
      const button = document.createElement('button'); button.type='button'; button.className='btn'; button.textContent=label;
      button.onclick=run(() => fill(row.name,kind)); actions.append(button);
    }
    section.append(actions); $('matches').append(section); count++;
  }
  $('generate').hidden = !editable || saveBlocked;
  message(count ? 'Choose what to fill. Petika will not submit the form.' : editable ? 'No matching logins. Generate and save one here, or add one in the web app.' : 'No matching logins in this read-only collection.');
}
// Capture before lock() clears the input; clear on both success and failure.
let unlockPassphrase = '';
const unlockHandler = $('unlock').onsubmit;
$('unlock').onsubmit = async event => { unlockPassphrase=$('passphrase').value; try { await unlockHandler(event); } finally { unlockPassphrase=''; $('passphrase').value=''; } };
$('collection').onchange=lock;
$('lock').onclick=() => { lock(); message('Vault locked.'); };
$('open').onclick=() => chrome.tabs.create({url:endpoint});
$('disconnect').onclick=run(async () => {
  await request('/v1/auth/logout',{});
  await chrome.storage.session.clear(); token=null; lock(); $('connect').hidden=false; $('disconnect').hidden=true;
  message('Disconnected.');
});
addEventListener('pagehide',lock);
try {
  await chrome.storage.session.setAccessLevel({accessLevel:'TRUSTED_CONTEXTS'});
  const stored = await chrome.storage.session.get(['token','grant','endpoint']); token=stored.endpoint === endpoint ? stored.token : null;
  if (stored.token && !token) await chrome.storage.session.clear();
  if (stored.grant?.endpoint === endpoint && stored.grant.expiresAt > Date.now()) { $('approval').hidden=false; $('code').textContent=stored.grant.user_code; }
  const [tab]=await chrome.tabs.query({active:true,currentWindow:true});
  try { $('site').textContent=httpsOrigin(tab.url); } catch { $('site').textContent='Open the toolbar popup on an HTTPS website.'; }
  if (token) await showAccount();
} catch(e) { message(e.message); }

function readRevision(value) {
  if (!/^"[0-9]+"$/.test(value || '')) throw new Error('Missing collection revision. Reopen and unlock.');
  const revision = Number(value.slice(1,-1));
  if (!Number.isSafeInteger(revision)) throw new Error('Invalid collection revision.');
  return revision;
}
function clearGenerator() {
  $('generator').reset(); $('generator').hidden = true; $('matches').hidden = false;
  $('generated-password').value = '';
  $('generate').hidden = !unlocked || !editable || saveBlocked;
}
async function generatePassword() {
  if (!unlocked || !editable || saveBlocked) throw new Error('Unlock a writable collection first.');
  const activeGeneration = generation;
  const password = await rpc('generate', Number($('generated-length').value));
  if (activeGeneration !== generation || !unlocked) throw new Error('Vault locked.');
  $('generated-password').value = password; touch();
}
$('generate').onclick = run(async () => {
  clearGenerator();
  $('generated-name').value = `${new URL(target.origin).hostname.slice(0,180)} ${new Date().toISOString()}`;
  await generatePassword(); $('generator').hidden = false; $('matches').hidden = true; $('generate').hidden = true;
  message('Generate a password, then save the encrypted login before filling.');
});
$('regenerate').onclick = run(generatePassword);
$('generated-length').onchange = run(generatePassword);
$('cancel-generation').onclick = clearGenerator;
$('generator').onsubmit = run(async () => {
  if (!unlocked || !editable || saveBlocked) throw new Error('Reopen and unlock a writable collection first.');
  const activeGeneration = generation;
  const current = await capturedDocument();
  if (current.tabId !== target.tabId || current.documentId !== target.documentId || current.origin !== target.origin) throw new Error('Website changed. Reopen Petika.');
  const status = await request('/v1/auth/status');
  if (!status.user) { lock(); throw new Error('Account session revoked.'); }
  const permissions = await request('/v1/collections');
  if (!permissions.find(c => c.id === collection)?.edit) throw new Error('This collection is read-only.');
  const {origins} = await request('/v1/auth/websites');
  authorizeFill(current.origin,current.origin,origins);
  const name = $('generated-name').value.trim();
  if (!name || !$('generated-password').value) throw new Error('Enter a login name and generate a password.');
  // Never replace an existing login; retain the old password during website changes.
  if ((await rpc('list')).some(row => row.name === name)) throw new Error('That login name already exists. Choose a new name to preserve it.');
  const revision = snapshotRevision;
  const guard = accessState;
  const entry = {username:$('generated-username').value,password:$('generated-password').value,url:current.origin,notes:'Generated by Petika. Complete signup or the password change on the website.',otp:null};
  let staged = false, saved = false;
  try {
    if (activeGeneration !== generation || !unlocked) throw new Error('Vault locked.');
    await rpc('put',name,entry,false); staged = true;
    const encrypted = await rpc('seal');
    if (activeGeneration !== generation || !unlocked) throw new Error('Vault locked.');
    if (guard) {
      const result = await request(`/v1/collections/${collection}/recipient-snapshot`,{
        expected_snapshot_revision:revision,expected_key_epoch:guard.key_epoch,
        expected_membership_generation:guard.membership_generation,packages:[],encrypted_snapshot:encrypted
      });
      if (!Number.isSafeInteger(result.snapshot_revision) || result.snapshot_revision !== revision+1) throw new Error('Save acknowledgement was invalid. Reopen to check the server copy.');
      snapshotRevision = result.snapshot_revision;
    } else {
      const response = await request(`/v1/collections/${collection}/snapshot`,encrypted,'response','PUT',{'If-Match':`"${revision}"`});
      const next = readRevision(response.headers.get('ETag'));
      if (next !== revision+1) throw new Error('Save acknowledgement was invalid. Reopen to check the server copy.');
      snapshotRevision = next;
    }
    saved = true;
    if (activeGeneration !== generation || !unlocked) throw new Error('Saved encrypted login. Reopen and unlock to fill it.');
    clearGenerator(); await renderMatches(origins); touch();
    message('Encrypted login saved. Choose Fill new password to use it on the website. Your previous login is unchanged.');
  } catch (error) {
    if (staged && !saved && activeGeneration === generation && unlocked) {
      saveBlocked = true; $('generate').hidden = true;
      try { await rpc('remove',name); } catch { lock(); }
      // A network failure may happen after server acceptance. Never fill an unconfirmed draft.
      error.message += ' Nothing was filled. Reopen and check the server before trying again; the save may have reached it.';
    }
    throw error;
  } finally { entry.password = ''; }
});
