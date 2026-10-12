const $ = (s, root = document) => root.querySelector(s);
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
  "'": '&#39;'
} [c]));
const paths = {
  box: 'M3 8 12 3l9 5-9 5-9-5Zm0 0v10l9 4 9-4V8M12 13v9',
  key: 'M14 7a5 5 0 1 1-3 9l-6 6H2v-3l6-6a5 5 0 0 1 6-6Z',
  search: 'm21 21-5-5M18 10a8 8 0 1 1-16 0 8 8 0 0 1 16 0',
  shield: 'M12 3 3 7v5c0 5 9 9 9 9s9-4 9-9V7l-9-4Zm-4 9 3 3 5-6',
  users: 'M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2m20 0v-2a4 4 0 0 0-3-4M13 3a4 4 0 0 1 0 8M13 7a4 4 0 1 1-8 0 4 4 0 0 1 8 0',
  user: 'M20 21v-2a5 5 0 0 0-5-5H9a5 5 0 0 0-5 5v2M16 7a4 4 0 1 1-8 0 4 4 0 0 1 8 0',
  lock: 'M6 10h12v11H6V10Zm2 0V6a4 4 0 0 1 8 0v4m-4 5v2',
  plus: 'M12 5v14M5 12h14',
  copy: 'M8 8h13v13H8V8ZM4 16H2V2h14v2',
  eye: 'M2 12s4-7 10-7 10 7 10 7-4 7-10 7-10-7-10-7Zm13 0a3 3 0 1 1-6 0 3 3 0 0 1 6 0',
  refresh: 'M20 7v5h-5M4 17v-5h5M5 7a8 8 0 0 1 14-1l1 6M4 12l1 6a8 8 0 0 0 14-1',
  download: 'M12 3v12m-5-5 5 5 5-5M4 16v5h16v-5',
  upload: 'M12 16V4m-5 5 5-5 5 5M4 16v5h16v-5',
  settings: 'M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8ZM12 2v3m0 14v3M2 12h3m14 0h3M5 5l2 2m10 10 2 2M5 19l2-2M17 7l2-2',
  logout: 'M9 4H3v16h6m5-13 5 5-5 5m-7-5h12',
  arrow: 'M7 17 17 7M7 7h10v10',
  check: 'm5 12 4 4 10-10',
  note: 'M5 3h14v18H5V3Zm4 5h6m-6 4h6m-6 4h4',
  browser: 'M3 4h18v16H3V4Zm0 5h18M6 7h.01M9 7h.01',
  clock: 'M12 8v5l3 2M22 12a10 10 0 1 1-20 0 10 10 0 0 1 20 0',
  close: 'm6 6 12 12M6 18 18 6',
  menu: 'M4 6h16M4 12h16M4 18h16',
  edit: 'm16 3 5 5-12 12-6 1 1-6L16 3Zm-3 3 5 5',
  trash: 'M3 6h18M9 6V3h6v3M5 6l1 15h12l1-15M10 10v7m4-7v7',
  sun: 'M12 2v2m0 16v2M2 12h2m16 0h2M5 5l1 1m12 12 1 1M5 19l1-1M18 6l1-1M16 12a4 4 0 1 1-8 0 4 4 0 0 1 8 0'
};
const icon = name => `<svg class="icon" viewBox="0 0 24 24" aria-hidden="true"><path d="${paths[name]||paths.box}"/></svg>`;
const button = (label, action, i = '', cls = '') => `<button type="button" class="btn ${cls}" data-action="${action}">${i?icon(i):''}${label}</button>`;
const mark = (alt = '') => `<span class="theme-mark"><img class="mark-light" src="/brand.png" alt="${alt}"><img class="mark-dark" src="/brand-dark.png" alt="${alt}"></span>`;
const brand = () => `<div class="brand">${mark("Petika chest")}<span>Petika<small>Your private workspace</small></span></div>`;
const themeSelect = () => `<select class="control" aria-label="Appearance" data-theme-picker>${['system','light','dark'].map(t=>`<option value="${t}" ${document.documentElement.dataset.theme===t?'selected':''}>${({system:'System appearance',light:'Light',dark:'Dark'})[t]}</option>`).join('')}</select>`;
const state = {
  user: null,
  collections: [],
  collection: null,
  view: 'items',
  filter: 'all',
  rows: [],
  selected: null,
  unlocked: false,
  revision: 0,
  dirty: false,
  conflict: false,
  mode: 'standard',
  demo: false,
  status: null,
  query: '',
  busy: false
};
let worker, sequence = 0,
  pending = new Map(),
  lastActivity = Date.now(),
  otpInterval, toastTimer;

function rpc(action, ...args) {
  if (!worker) {
    worker = new Worker('/worker.js', {
      type: 'module'
    });
    worker.onmessage = ({
      data
    }) => {
      const p = pending.get(data.id);
      if (!p) return;
      pending.delete(data.id);
      data.error ? p.reject(new Error(data.error)) : p.resolve(data.value)
    };
    worker.onerror = () => {
      for (const p of pending.values()) p.reject(new Error('Encryption module could not load. Check the web build.'));
      pending.clear()
    };
  }
  return new Promise((resolve, reject) => {
    const id = ++sequence;
    pending.set(id, {
      resolve,
      reject
    });
    worker.postMessage({
      id,
      action,
      args
    })
  })
}

function discardWorker() {
  worker?.terminate();
  worker = null;
  for (const p of pending.values()) p.reject(new Error('Session locked'));
  pending.clear()
}

function toast(message) {
  const el = $('#toast');
  el.textContent = message;
  el.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.hidden = true, 5000)
}

function errorText(error) {
  return error?.message || String(error)
}
async function api(path, {
  method = 'GET',
  body
} = {}) {
  const response = await fetch(path, {
    method,
    credentials: 'same-origin',
    cache: 'no-store',
    headers: {
      'Content-Type': 'application/json',
      'X-Petika-Request': '1'
    },
    body: body === undefined ? undefined : JSON.stringify(body)
  });
  const value = await response.json();
  if (!response.ok) throw new Error(value.error || 'Request failed');
  return value
}

function bind(root = document) {
  root.querySelectorAll('[data-action]').forEach(el => el.onclick = () => Promise.resolve(action(el.dataset.action, el)).catch(e => toast(errorText(e))));
  root.querySelectorAll('[data-theme-picker]').forEach(el => el.onchange = () => {
    document.documentElement.dataset.theme = el.value;
    try {
      localStorage.setItem('petika-theme', el.value)
    } catch {}
  })
}

function form(id, handler) {
  const el = $(id);
  el.onsubmit = async event => {
    event.preventDefault();
    const submit = el.querySelector('[type=submit]');
    const error = el.querySelector('.form-error');
    error.textContent = '';
    submit.disabled = true;
    try {
      await handler(new FormData(el), el)
    } catch (e) {
      error.textContent = errorText(e)
    } finally {
      submit.disabled = false
    }
  }
}

function field(label, name, type = 'text', value = '', extra = '') {
  return `<div class="field"><label for="f-${name}">${label}</label><input id="f-${name}" name="${name}" type="${type}" value="${esc(value)}" ${extra}></div>`
}

function dialog(title, body) {
  const el = $('#dialog');
  el.innerHTML = `<div class="dialog-head"><h2 id="dialog-title">${title}</h2>${button('','close','close','icon-only')}</div><div class="dialog-body">${body}</div>`;
  el.querySelector('[data-action=close]').setAttribute('aria-label', 'Close dialog');
  el.onclose = () => {
    el.innerHTML = ''
  };
  el.showModal();
  bind(el)
}

function closeDialog() {
  $('#dialog').close()
}

function authScreen(initialized = true) {
  clearInterval(otpInterval);
  $('#app').innerHTML = `<div class="auth-layout"><section class="auth-story">${brand()}<div class="auth-art"><div class="chest-tile">${mark()}</div><h1>A private place.<br>For your digital life.</h1><p>Keep passwords, verification codes, and shared secrets together. On infrastructure you control.</p><div class="actions"><span class="pill">${icon('lock')}Encrypted on your device</span></div></div><div class="trust-line">${icon('shield')}Open source. Self-hosted. Yours.</div></section><main id="main" class="auth-panel"><div class="theme-top">${themeSelect()}</div><div class="auth-form"><h2>${initialized?'Welcome back':'Make Petika yours'}</h2><p>${initialized?'Sign in to your private workspace.':'Create the first administrator for this instance.'}</p><form id="auth-form">${!initialized?field('Setup token','token','password','','required autocomplete="off"')+field('Your name','name','text','','required maxlength="100" autocomplete="name"'):''}${field('Username','username','text','','required autocomplete="username" maxlength="100"')}${field(initialized?'Account password':'Create an account password','password','password','','required minlength="12" maxlength="1024" autocomplete="'+(initialized?'current-password':'new-password')+'"')}${!initialized?'<p class="small muted">Use at least 12 characters. Your collection unlock passphrase is set separately.</p>':''}<div class="form-error" role="alert"></div><button class="btn primary full" type="submit">${initialized?'Sign in':'Create administrator'}</button></form><div class="separator">Just looking around?</div>${button('Explore the demo','demo','arrow','full')}<p class="auth-footer">Experimental release • Use test data only</p></div></main></div>`;
  bind();
  form('#auth-form', async (data, el) => {
    const body = Object.fromEntries(data);
    if (!initialized) {
      await api('/v1/auth/bootstrap', {
        method: 'POST',
        body
      });
    }
    state.user = await api('/v1/auth/login', {
      method: 'POST',
      body: {
        username: body.username,
        password: body.password
      }
    });
    el.reset();
    await enter()
  })
}
async function enter() {
  if (new URLSearchParams(location.search).get('cli') === '1') return cliApprovalScreen();
  state.collections = await api('/v1/collections');
  state.collection = state.collections[0];
  state.view = 'items';
  await loadCollection()
}

function draftKey() {
  return `petika-encrypted-${state.collection.id}`
}

function getDraft() {
  if (state.demo) return null;
  try {
    return JSON.parse(localStorage.getItem(draftKey()) || 'null')
  } catch {
    return null
  }
}
async function loadCollection() {
  discardWorker();
  state.unlocked = false;
  state.rows = [];
  state.selected = null;
  state.query = '';
  state.dirty = false;
  state.conflict = false;
  state.snapshot = null;
  state.status = null;
  state.revision = 0;
  const draft = getDraft();
  try {
    const response = await fetch(`/v1/collections/${state.collection.id}/snapshot`, {
      credentials: 'same-origin',
      cache: 'no-store'
    });
    if (response.status === 404) {
      state.revision = 0;
    } else {
      if (!response.ok) throw new Error('Cannot access this collection');
      state.snapshot = await response.text();
      state.revision = Number((response.headers.get('ETag') || '"0"').replaceAll('"', ''));
    }
    if (draft?.dirty) {
      state.conflict = draft.revision !== state.revision;
      state.snapshot = draft.encrypted;
      state.revision = draft.revision;
      state.dirty = true;
    }
  } catch (e) {
    if (draft) {
      state.snapshot = draft.encrypted;
      state.revision = draft.revision;
      state.dirty = Boolean(draft.dirty);
      toast('Using the encrypted copy on this device.')
    } else throw e;
  }
  shell();
}

function nav(label, view, i, count = '') {
  return `<button class="nav-btn ${state.view===view?'active':''}" data-action="nav" data-view="${view}">${icon(i)}${label}${count!==''?`<span class="count">${count}</span>`:''}</button>`
}

function shell() {
  clearInterval(otpInterval);
  const user = state.user;
  $('#app').innerHTML = `<div class="shell"><aside class="sidebar">${brand()}<div class="workspace-switch"><span class="initial">P</span>Private workspace<span class="pill neutral">${state.demo?'Demo':'Self-hosted'}</span></div><nav aria-label="Main navigation">${nav('All items','items','box',state.unlocked?state.rows.length:'')}${nav('Security check','security','shield')}${nav('Password generator','generator','key')}<div class="nav-label">Tools</div>${nav('Import & export','transfer','download')}${nav('GPG keys','gpg','key')}${nav('Browser autofill','autofill','browser')}${user.admin?`<div class="nav-label">Administration</div>${nav('Users','users','user')}${nav('Groups','groups','users')}`:''}</nav><div class="sidebar-bottom">${nav('Sync & backup','sync','refresh')}${nav('Settings','settings','settings')}<button class="profile-btn" data-action="profile"><span class="avatar">${esc(user.name.slice(0,2).toUpperCase())}</span><span>${esc(user.name)}<small>${user.admin?'Administrator':'Member'}</small></span></button></div></aside><section class="workspace"><header class="topbar"><div class="breadcrumb">${button('','menu','menu','icon-only mobile-menu')}<span>Workspace</span><span>/</span><strong>${({items:'My collection',security:'Security check',generator:'Password generator',transfer:'Import & export',gpg:'GPG keys',autofill:'Browser autofill',users:'Users',groups:'Groups',sync:'Sync & backup',settings:'Settings'})[state.view]}</strong></div><div class="actions"><span class="pill ${state.unlocked?'':'neutral'}">${icon(state.unlocked?'shield':'lock')}${state.unlocked?'Unlocked locally':'Locked'}</span>${button(state.unlocked?'Lock':'Sign out',state.unlocked?'lock':'logout',state.unlocked?'lock':'logout','ghost')}</div></header>${state.demo?'<div class="demo-banner">Demo workspace — sample data only. Changes stay in memory and are never sent to the server.</div>':''}<main id="main" class="page"></main></section></div>`;
  $('.mobile-menu').setAttribute('aria-label', 'Toggle navigation');
  bind();
  renderPage().catch(e => {
    $('#main').innerHTML = `<div class="notice warning">${esc(errorText(e))}</div>`
  })
}

function title(name, description, actions = '') {
  return `<div class="page-title"><div><h1>${name}</h1><p>${description}</p></div><div class="actions">${actions}</div></div>`
}

function collectionTabs() {
  return `<div class="collection-tabs" aria-label="Collections">${state.collections.map((c,i)=>`<button data-action="collection" data-index="${i}" aria-pressed="${c.id===state.collection.id}">${icon(c.group?'users':'lock')} ${esc(c.name)}</button>`).join('')}</div>`
}

function unlockView() {
  return `${collectionTabs()}<div class="lock-panel"><div class="chest-tile">${mark()}</div><h2>${state.snapshot?'Unlock':'Set up'} ${esc(state.collection.name)}</h2><p>${state.snapshot?'Your passphrase stays on this device.':'Choose how to protect this collection.'}</p>${state.collection.group?'<div class="notice">This group uses a separate unlock passphrase. Share it with authorized members through a trusted channel. Membership alone does not provide the key.</div>':''}${!state.snapshot&&!state.collection.edit?'<div class="notice">A member with edit access must initialize this collection.</div>':`<form id="unlock-form">${field('Unlock passphrase','passphrase','password','','required autocomplete="'+(state.snapshot?'current-password':'new-password')+'"')}${!state.snapshot?field('Confirm passphrase','confirm','password','','required minlength="12" autocomplete="new-password"')+'<div class="choice-grid"><label class="choice"><input type="radio" name="mode" value="standard" checked><span><strong>Standard</strong><small>XChaCha20-Poly1305</small></span></label><label class="choice"><input type="radio" name="mode" value="hybrid"><span><strong>Hybrid</strong><small>Post-quantum · experimental</small></span></label></div>':''}<div class="form-error" role="alert"></div><button type="submit" class="btn primary full">${state.snapshot?'Unlock collection':'Create encrypted collection'}</button></form>${!state.snapshot?button('Import an encrypted Petika file','import','upload','full ghost'):''}`}<p class="auth-footer">Petika cannot recover a forgotten unlock passphrase.</p></div>`
}

function bindUnlock() {
  if (!$('#unlock-form')) return;
  form('#unlock-form', async (data, el) => {
    const pass = data.get('passphrase');
    if (!state.snapshot) {
      if (pass !== data.get('confirm')) throw new Error('Passphrases do not match.');
      await rpc('create', pass, data.get('mode') === 'hybrid');
    } else {
      await rpc('open', state.snapshot, pass);
    }
    el.reset();
    state.unlocked = true;
    lastActivity = Date.now();
    state.mode = await rpc('mode');
    if (!state.snapshot) await persist();
    await refreshRows();
    shell()
  })
}
async function renderPage() {
  const main = $('#main');
  if (['items', 'security', 'generator'].includes(state.view) && !state.unlocked) {
    main.innerHTML = unlockView();
    bind(main);
    bindUnlock();
    return;
  }
  if (state.view === 'items') {
    renderItems();
    return;
  }
  if (state.view === 'security') {
    const weak = state.rows.filter(r => r.weak || r.reused);
    main.innerHTML = title('A little attention goes a long way', 'Review short or reused passwords in this collection.') + `<div class="panel"><div class="panel-header"><div><h2>${weak.length?'Passwords to review':'No short or reused passwords found'}</h2><p>This is a local check, not a breach-monitoring service.</p></div><span class="pill">${weak.length} items</span></div>${weak.length?weak.map(r=>`<button class="item-row" data-action="review" data-index="${state.rows.indexOf(r)}"><span class="item-letter">${esc(r.name[0].toUpperCase())}</span><span class="item-text"><strong>${esc(r.name)}</strong><small>${r.reused?'Used by another item':'Fewer than 16 characters'}</small></span>${icon('arrow')}</button>`).join(''):'<p>Keep using unique, randomly generated passwords. Length alone does not guarantee strength.</p>'}</div>`;
  }
  if (state.view === 'generator') {
    main.innerHTML = title('Make a stronger password', 'Generated locally. Ready when you are.') + `<div class="panel readable"><div class="field"><label for="generated">Generated password</label><textarea id="generated" class="mono" readonly spellcheck="false" aria-label="Generated password"></textarea></div><div class="field"><label for="length">Length</label><select id="length">${[16,24,32,48,64].map(n=>`<option ${n===24?'selected':''}>${n}</option>`).join('')}</select></div><div class="actions">${button('Generate another','generate','refresh','primary')}${button('Copy password','copy-generated','copy')}${state.collection.edit?button('Save as an item','save-generated','plus'):''}</div><p class="small muted">Uses letters, numbers, and symbols from a cryptographically secure random source.</p></div>`;
    $('#generated').value = await rpc('generate', 24);
  }
  if (state.view === 'transfer') {
    main.innerHTML = title('Bring your secrets with you', 'Encrypted backups, kept under your control.') + `<div class="settings-grid"><section class="panel"><h2>Import a Petika file</h2><p class="small">Open an encrypted CLI or web backup. Import is available when the current collection is empty and locked.</p><div class="info-list">${button('Choose encrypted file','import','upload')}</div></section><section class="panel"><h2>Export this collection</h2><p class="small">Download an encrypted snapshot, including item names and verification-code secrets. Keep your passphrase separately.</p><div class="info-list">${button('Download encrypted backup','export','download')}</div></section></div><section class="panel"><h2>Coming from a GPG password store?</h2><p>Import locally with the native Petika CLI, then open the resulting encrypted file here.</p><code class="inline-code">petika init --encryption standard --import-gpg /path/to/password-store</code><p class="small">Use hybrid-post-quantum instead of standard for the experimental hybrid mode. Your source files remain unchanged.</p></section>`;
  }
  if (state.view === 'gpg') {
    main.innerHTML = title('GPG keys', 'Keep private-key operations on your device.') + `<section class="panel readable"><span class="pill neutral">Native integration required</span><h2>Use your existing GPG keys for import</h2><p>GPG imports work today through the native CLI and your local GPG agent. The browser does not upload or manage your private keys.</p><code class="inline-code">petika import-gpg /path/to/password-store --gpg-home /path/to/gnupg</code><div class="notice">Key creation, public-key export, expiry changes, and revocation are planned for the native key-management integration. They are not available in this web release.</div>${button('Open import tools','transfer','upload')}</section>`;
  }
  if (state.view === 'autofill') {
    main.innerHTML = title('Less typing. More control.', 'Website-aware filling, with your permission.') + `<section class="panel readable"><div class="panel-header"><h2>Browser autofill</h2><span class="pill neutral">Extension not connected</span></div><p>The web app can copy credentials and generate website verification codes. Filling forms on another website requires the Petika Chromium or Firefox extension, which is not implemented yet.</p><div class="settings-row"><div><h3>Match the website</h3><p>Save the complete HTTPS address on each login. The planned extension will check the destination before suggesting credentials.</p></div>${icon('browser')}</div><div class="settings-row"><div><h3>Fill only when you choose</h3><p>Explicit selection will fill the username, password, or current one-time code without automatically submitting the form.</p></div>${icon('check')}</div><div class="settings-row"><div><h3>Website OTP</h3><p>Add a setup key or otpauth link to a login to get time-based codes now.</p></div>${button('Go to items','items','key')}</div></section>`;
  }
  if (state.view === 'settings') {
    main.innerHTML = title('A workspace that feels like yours', 'Profile, appearance, and local session preferences.') + `<div class="panel readable"><div class="panel-header"><h2>Your profile</h2><span class="avatar">${esc(state.user.name.slice(0,2).toUpperCase())}</span></div><form id="profile-form">${field('Display name','name','text',state.user.name,'required maxlength="100"')}<p class="small muted">Username: ${esc(state.user.username)}</p><div class="form-error" role="alert"></div><button class="btn" type="submit">Save profile</button></form></div><section class="panel readable"><h2>Preferences</h2><div class="settings-row"><div><h3>Appearance</h3><p>Follow your device, or choose a look for Petika.</p></div>${themeSelect()}</div><div class="settings-row"><div><h3>Automatic lock</h3><p>Lock this collection after inactivity. Signing out also ends the account session.</p></div><select class="control" id="auto-lock" aria-label="Automatic lock">${[1,5,15].map(n=>`<option value="${n}" ${lockMinutes()===n?'selected':''}>${n} minute${n===1?'':'s'}</option>`).join('')}</select></div><div class="settings-row"><div><h3>Biometric unlock</h3><p>Requires the native device integration. This web release uses a passphrase and cannot verify biometrics.</p></div><span class="pill neutral">Not available yet</span></div></section>${!state.demo?'<p><a href="/?cli=1">Connect a CLI session</a></p>':''}${button('Change account password','account-password','key')} ${button('Sign out','logout','logout')}`;
    form('#profile-form', async data => {
      state.user = state.demo ? {
        ...state.user,
        name: data.get('name')
      } : await api('/v1/profile', {
        method: 'POST',
        body: {
          name: data.get('name')
        }
      });
      shell();
      toast('Profile saved')
    });
    $('#auto-lock').onchange = () => {
      try {
        localStorage.setItem('petika-lock-minutes', $('#auto-lock').value)
      } catch {};
      toast('Automatic lock updated')
    };
  }
  if (state.view === 'sync') {
    let status = null;
    if (!state.demo) try {
      status = await api(`/v1/collections/${state.collection.id}/status`)
    } catch {}
    state.status = status;
    main.innerHTML = title('Sync & backup', 'Know where your encrypted data lives.') + `<section class="panel readable"><div class="panel-header"><h2>${esc(state.collection.name)}</h2><span class="pill ${state.dirty?'neutral':''}">${state.demo?'Demo only':state.conflict?'Conflict needs review':state.dirty?'Changes on this device':status?'Connected':'Connection unavailable'}</span></div><div class="settings-row"><div><h3>API revision</h3><p>Only encrypted snapshots are sent to the server.</p></div><strong>${status?.revision??'—'}</strong></div><div class="settings-row"><div><h3>Encrypted Git mirror</h3><p>Item names, websites, and folder structure are encrypted. Size and commit timing remain visible.</p></div><span>${status?.mirror_enabled?`Revision ${status.mirror_revision}`:'Not available'}</span></div><div class="settings-row"><div><h3>Encryption</h3><p>${state.mode==='standard'?'XChaCha20-Poly1305 with Argon2id key protection.':'Experimental X-Wing hybrid key protection and XChaCha20-Poly1305.'}</p></div><span class="pill">${state.unlocked?state.mode:'Locked'}</span></div><div class="actions">${button('Retry sync','sync-now','refresh','primary')}${button('Download backup','export','download')}${state.conflict?button('Load server version','reload-server','download'):''}</div></section>`;
  }
  if (state.view === 'users') await renderUsers();
  if (state.view === 'groups') await renderGroups();
  bind(main);
}

function renderItems() {
  const main = $('#main');
  main.innerHTML = title('Your secrets, in good company.', `A private home for your everyday logins.${state.collection.group?' Shared with your group.':''}`, state.collection.edit ? button('New item', 'new', 'plus', 'primary') : '<span class="pill neutral">Read only</span>') + collectionTabs() + `<div class="collection-tabs" aria-label="Item type">${[['all','All items'],['logins','Logins'],['otp','Verification codes']].map(([id,name])=>`<button data-action="filter" data-filter="${id}" aria-pressed="${state.filter===id}">${name}</button>`).join('')}</div><div class="items-layout"><section class="item-list-panel" aria-label="Items"><div class="list-tools"><div class="search">${icon('search')}<input id="search" type="search" placeholder="Search this collection" aria-label="Search this collection" autocomplete="off" value="${esc(state.query)}"></div></div><div class="list-subtitle"><span id="item-count"></span><span>Name A–Z</span></div><div id="item-rows"></div></section><section class="item-detail" aria-label="Item details"></section></div><div class="bottom-status">${icon('shield')}<span>${state.demo?'Sample workspace. Nothing is saved to the server.':state.conflict?'A newer server version exists. Export your changes before resolving.':state.dirty?'Encrypted changes are saved on this device. Sync is pending.':'Encrypted before sync. Names and folder structure stay private.'}</span>${state.dirty?button('Review sync','sync','refresh','ghost'):''}</div>`;
  $('#search').oninput = event => {
    state.query = event.target.value;
    renderRows()
  };
  renderRows();
  renderDetail();
  bind(main)
}

function renderRows() {
  const filtered = state.rows.filter(r => (state.filter !== 'logins' || r.url) && (state.filter !== 'otp' || r.otp) && `${r.name} ${r.username} ${r.url}`.toLowerCase().includes(state.query.toLowerCase()));
  $('#item-count').textContent = `${filtered.length} item${filtered.length===1?'':'s'}`;
  $('#item-rows').innerHTML = filtered.length ? filtered.map(r => `<button class="item-row ${state.selected===r.name?'selected':''}" data-action="select" data-index="${state.rows.indexOf(r)}" aria-pressed="${state.selected===r.name}"><span class="item-letter">${esc(r.name.split('/').pop().trim()[0]?.toUpperCase() || '?' )}</span><span class="item-text"><strong>${esc(r.name.split('/').pop())}</strong><small>${esc(r.username||r.url||'Secure note')}</small></span>${r.otp?icon('clock'):''}</button>`).join('') : `<div class="empty"><span class="emblem">${icon('search')}</span><h3>${state.query?'No matching items':'A fresh start'}</h3><p>${state.query?'Try a different name, username, or website.':'Add your first login or import an encrypted collection.'}</p>${!state.query&&state.collection.edit?button('Add an item','new','plus'):''}</div>`;
  bind($('#item-rows'))
}
async function renderDetail() {
  clearInterval(otpInterval);
  const detail = $('.item-detail');
  if (!detail) return;
  const name = state.selected;
  if (!name) {
    detail.innerHTML = '<div class="empty"><span class="emblem">' + icon('lock') + '</span><h2>A little space for everything important.</h2><p>Select an item to see its details. Passwords stay hidden until you choose to reveal them.</p></div>';
    return;
  }
  const entry = await rpc('get', name);
  if (state.selected !== name || !state.unlocked) return;
  const url = safeUrl(entry.url);
  detail.innerHTML = `<div class="detail-heading"><span class="item-letter">${esc(name.split('/').pop().trim()[0]?.toUpperCase() || '?' )}</span><div><h2>${esc(name.split('/').pop())}</h2><p class="small">${esc(state.collection.name)}${name.includes('/')?' / '+esc(name.slice(0,name.lastIndexOf('/'))):''}</p></div><div class="actions">${state.collection.edit?button('Edit','edit','edit','ghost'):''}</div></div><div class="detail-field"><span class="label">Username</span><div class="field-value"><span>${esc(entry.username||'Not set')}</span>${button('','copy-username','copy','icon-only')}</div></div><div class="detail-field"><span class="label">Password</span><div class="field-value"><span class="password-value mono" id="password-display">••••••••••••••••</span><div class="actions">${button('','reveal','eye','icon-only')}${button('','copy-password','copy','icon-only')}</div></div></div>${entry.url?`<div class="detail-field"><span class="label">Website</span><div class="field-value">${url?`<a href="${esc(url)}" target="_blank" rel="noopener noreferrer">${esc(entry.url)} ${icon('arrow')}</a>`:`<span>${esc(entry.url)}</span>`}</div></div>`:''}${entry.otp?`<div class="detail-field"><span class="label">Verification code</span><div class="field-value"><span class="otp-code mono" id="otp-code">••• •••</span>${button('','copy-otp','copy','icon-only')}</div><span class="otp-timer" id="otp-time"></span></div>`:''}<div class="detail-field"><span class="label">Notes</span><p class="detail-notes">${esc(entry.notes||'No notes yet.')}</p></div><div class="detail-footer">${icon('shield')}Encrypted in ${esc(state.collection.name)}</div>${state.collection.edit?`<div class="detail-actions">${!entry.otp?button('Set up verification code','edit','clock','ghost'):'<span></span>'}${button('Delete item','delete','trash','ghost danger')}</div>`:''}`;
  for (const [a, label] of [
      ['copy-username', 'Copy username'],
      ['copy-password', 'Copy password'],
      ['reveal', 'Reveal password'],
      ['copy-otp', 'Copy verification code']
    ]) detail.querySelector(`[data-action="${a}"]`)?.setAttribute('aria-label', label);
  bind(detail);
  if (entry.otp) {
    const tick = async () => {
      try {
        const otp = await rpc('otp', name);
        if (state.selected === name && $('#otp-code')) {
          $('#otp-code').textContent = otp.code.replace(/(.{3,4})(.{3,4})/, '$1 $2');
          $('#otp-time').textContent = `New code in ${otp.remaining}s`;
        }
      } catch {}
    };
    await tick();
    otpInterval = setInterval(tick, 1000)
  }
}

function safeUrl(value) {
  try {
    const u = new URL(value);
    return ['https:', 'http:'].includes(u.protocol) && !u.username && !u.password ? u.href : null
  } catch {
    return null
  }
}
async function refreshRows() {
  state.rows = await rpc('list');
  if (!state.rows.some(r => r.name === state.selected)) state.selected = null
}
async function persist() {
  state.snapshot = await rpc('seal');
  if (state.demo) return;
  state.dirty = true;
  try {
    localStorage.setItem(draftKey(), JSON.stringify({
      encrypted: state.snapshot,
      revision: state.revision,
      dirty: true
    }))
  } catch {
    throw new Error('Encrypted changes are in memory only. Download a backup before locking; device storage is full or disabled.')
  }
  await sync()
}
async function sync() {
  if (state.demo || !state.dirty) return;
  if (state.conflict) throw new Error('Resolve the revision conflict in Sync & backup first.');
  const response = await fetch(`/v1/collections/${state.collection.id}/snapshot`, {
    method: 'PUT',
    credentials: 'same-origin',
    headers: {
      'Content-Type': 'application/json',
      'X-Petika-Request': '1',
      'If-Match': `"${state.revision}"`
    },
    body: state.snapshot
  });
  if (response.status === 409) {
    state.conflict = true;
    throw new Error('Another device changed this collection. Your encrypted changes are kept locally.');
  }
  if (!response.ok) throw new Error('Sync failed. Your encrypted changes are kept locally.');
  state.revision = Number(response.headers.get('ETag').replaceAll('"', ''));
  state.dirty = false;
  localStorage.setItem(draftKey(), JSON.stringify({
    encrypted: state.snapshot,
    revision: state.revision,
    dirty: false
  }))
}

function lockMinutes() {
  try {
    const n = Number(localStorage.getItem('petika-lock-minutes'));
    return [1, 5, 15].includes(n) ? n : 5
  } catch {
    return 5
  }
}

function lock() {
  discardWorker();
  clearInterval(otpInterval);
  state.unlocked = false;
  state.rows = [];
  state.selected = null;
  state.query = '';
  if ($('#dialog').open) closeDialog();
  if (state.demo) {
    state.demo = false;
    state.user = null;
    authScreen(true);
  } else shell()
}
async function renderUsers() {
  const users = state.demo ? demoUsers : await api('/v1/admin/users');
  state.users = users;
  $('#main').innerHTML = title('People in your workspace', 'Manage accounts and administrator access.', button('Add user', 'add-user', 'plus', 'primary')) + `<div class="panel table-wrap"><table><thead><tr><th>Person</th><th>Role</th><th>Status</th><th>Access</th></tr></thead><tbody>${users.map((u,i)=>`<tr><td class="account-cell">${esc(u.name)}<small>${esc(u.username)}</small></td><td>${u.admin?'Administrator':'Member'}</td><td><span class="pill ${u.disabled?'neutral':''}">${u.disabled?'Disabled':'Active'}</span></td><td>${u.id===state.user.id?'<span class="muted">You</span>':`<button class="btn ghost" data-action="user-status" data-index="${i}">${u.disabled?'Enable':'Disable'}</button>`}</td></tr>`).join('')}</tbody></table></div><p class="small muted">Disabling an account revokes its server sessions and collection access. Previously copied secrets cannot be recalled.</p>`
}
async function renderGroups() {
  const groups = state.demo ? demoGroups : await api('/v1/admin/groups');
  state.groups = groups;
  $('#main').innerHTML = title('Shared work. Clear boundaries.', 'Give teams access to the secrets they need.', button('Create group', 'add-group', 'plus', 'primary')) + `<div class="group-grid">${groups.map((g,i)=>`<section class="group-card">${icon('users')}<h2>${esc(g.name)}</h2><p>${g.members.length} member${g.members.length===1?'':'s'} · Separate encrypted collection</p><button class="btn" data-action="edit-group" data-index="${i}">Manage members</button></section>`).join('')}</div>${groups.length?'':'<div class="empty"><span class="emblem">'+icon('users')+'</span><h2>Your first shared collection starts here.</h2><p>Create a group, add members, and choose who can read or edit its secrets.</p></div>'}<div class="notice readable">Groups control server access. Share the collection passphrase separately. Removing a member does not rotate the encryption key or erase previously downloaded data.</div>`
}
async function editItem(prefill = null) {
  if (!state.unlocked || !state.collection.edit) throw new Error('Unlock a collection with edit access first.');
  const original = prefill ? '' : state.selected;
  const entry = prefill || (original ? await rpc('edit', original) : {
    username: '',
    password: '',
    url: '',
    notes: '',
    otp: ''
  });
  dialog(original ? 'Edit item' : 'New item', `<form id="item-form">${field('Name','name','text',original||'','required maxlength="256" '+(original?'readonly':''))}${field('Username','username','text',entry.username,'autocomplete="off" maxlength="1024"')}<div class="field"><label for="f-password">Password</label><div class="input-action"><input id="f-password" name="password" type="password" autocomplete="new-password" value="${esc(entry.password)}" maxlength="4096">${button('Generate','generate-item','refresh')}</div></div>${field('Website','url','url',entry.url,'placeholder="https://example.com" maxlength="2048"')}<div class="field"><label for="f-otp">Verification-code setup key</label><input id="f-otp" name="otp" type="password" autocomplete="off" value="${esc(entry.otp||'')}" placeholder="Base32 secret or otpauth://totp/…" maxlength="4096"><small>Get the setup key from the website’s two-factor authentication settings. It is encrypted with this item.</small></div><div class="field"><label for="f-notes">Notes</label><textarea id="f-notes" name="notes" maxlength="20000">${esc(entry.notes)}</textarea></div><div class="form-error" role="alert"></div><div class="dialog-footer">${button('Cancel','close')}<button class="btn primary" type="submit">Save item</button></div></form>`);
  form('#item-form', async data => {
    const name = data.get('name');
    await rpc('put', name, {
      username: data.get('username'),
      password: data.get('password'),
      url: data.get('url'),
      notes: data.get('notes'),
      otp: data.get('otp') || null
    }, Boolean(original));
    state.selected = name;
    let message = 'Item saved';
    try {
      await persist()
    } catch (e) {
      message = errorText(e)
    }
    await refreshRows();
    closeDialog();
    state.view = 'items';
    shell();
    toast(message)
  })
}
async function importDialog() {
  if (state.unlocked || state.snapshot || !state.collection.edit) throw new Error('Import is available only into an empty, locked collection. Use a new group to keep an existing collection intact.');
  dialog('Import encrypted collection', `<form id="import-form"><div class="field"><label for="import-file">Petika encrypted file</label><input id="import-file" name="file" type="file" accept=".petika,.json" required></div>${field('File unlock passphrase','passphrase','password','','required autocomplete="off"')}<p class="small muted">The file is decrypted on your device, then synced as ciphertext. GPG files must first be imported with the native CLI.</p><div class="form-error" role="alert"></div><div class="dialog-footer"><button class="btn primary" type="submit">Import collection</button></div></form>`);
  form('#import-form', async data => {
    const file = data.get('file');
    if (file.size > 12 * 1024 * 1024) throw new Error('File is too large.');
    await rpc('open', await file.text(), data.get('passphrase'));
    state.unlocked = true;
    state.mode = await rpc('mode');
    let message = 'Collection imported';
    try {
      await persist()
    } catch (e) {
      message = errorText(e)
    }
    await refreshRows();
    closeDialog();
    state.view = 'items';
    shell();
    toast(message)
  })
}
async function exportFile() {
  if (state.unlocked) state.snapshot = await rpc('seal');
  if (!state.snapshot) throw new Error('There is no encrypted collection to export yet.');
  const url = URL.createObjectURL(new Blob([state.snapshot], {
    type: 'application/json'
  }));
  const a = document.createElement('a');
  a.href = url;
  a.download = 'petika-backup.petika';
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
  toast('Encrypted backup downloaded')
}
async function userDialog() {
  dialog('Add a workspace member', `<form id="user-form">${field('Display name','name','text','','required maxlength="100"')}${field('Username','username','text','','required minlength="3" maxlength="100" autocomplete="off"')}${field('Initial account password','password','password','','required minlength="12" maxlength="1024" autocomplete="new-password"')}<label class="check"><input name="admin" type="checkbox">Administrator access</label><p class="small muted">Deliver the initial credentials privately. This does not give access to an encrypted collection or send an email.</p><div class="form-error" role="alert"></div><div class="dialog-footer"><button class="btn primary" type="submit">Create user</button></div></form>`);
  form('#user-form', async data => {
    const body = {
      name: data.get('name'),
      username: data.get('username'),
      password: data.get('password'),
      admin: data.has('admin')
    };
    if (state.demo) demoUsers.push({
      ...body,
      password: undefined,
      id: crypto.randomUUID(),
      disabled: false
    });
    else await api('/v1/admin/users', {
      method: 'POST',
      body
    });
    closeDialog();
    shell();
    toast('User created')
  })
}
async function groupDialog(group = null) {
  const users = state.demo ? demoUsers : await api('/v1/admin/users');
  dialog(group ? 'Manage group' : 'Create group', `<form id="group-form">${field('Group name','name','text',group?.name||'','required maxlength="100"')}<h3>Members and permissions</h3>${users.filter(u=>!u.disabled).map(u=>{const m=group?.members.find(m=>m.user_id===u.id);return `<div class="group-member"><label for="member-${u.id}">${esc(u.name)}</label><select id="member-${u.id}" name="member-${u.id}"><option value="none">No access</option><option value="read" ${m&&!m.edit?'selected':''}>Read</option><option value="edit" ${m?.edit?'selected':''}>Read & edit</option></select></div>`}).join('')}<div class="notice">Choose access explicitly, including your own. Group secrets use a separate unlock passphrase.</div><div class="form-error" role="alert"></div><div class="dialog-footer"><button class="btn primary" type="submit">Save group</button></div></form>`);
  form('#group-form', async data => {
    const body = {
      name: data.get('name'),
      members: users.filter(u => ['read', 'edit'].includes(data.get('member-' + u.id))).map(u => ({
        user_id: u.id,
        edit: data.get('member-' + u.id) === 'edit'
      }))
    };
    if (group) body.id = group.id;
    if (state.demo) {
      if (group) Object.assign(group, body);
      else demoGroups.push({
        ...body,
        id: crypto.randomUUID()
      })
    } else {
      await api('/v1/admin/groups', {
        method: 'POST',
        body
      });
      state.collections = await api('/v1/collections')
    }
    closeDialog();
    shell();
    toast('Group saved')
  })
}
async function action(name, el) {
  lastActivity = Date.now();
  switch (name) {
    case 'account-password':
      accountPasswordDialog();
      break;
    case 'close':
      closeDialog();
      break;
    case 'menu':
      $('.shell').classList.toggle('nav-open');
      break;
    case 'profile':
      state.view = 'settings';
      shell();
      break;
    case 'nav':
      state.view = el.dataset.view;
      state.query = '';
      shell();
      break;
    case 'items':
    case 'transfer':
    case 'sync':
      state.view = name;
      shell();
      break;
    case 'filter':
      state.filter = el.dataset.filter;
      renderItems();
      break;
    case 'select':
      state.selected = state.rows[Number(el.dataset.index)].name;
      renderRows();
      await renderDetail();
      break;
    case 'review':
      state.selected = state.rows[Number(el.dataset.index)].name;
      state.view = 'items';
      shell();
      break;
    case 'collection': {
      const c = state.collections[Number(el.dataset.index)];
      if (c.id === state.collection.id) break;
      if (state.dirty) throw new Error('Sync or export your pending changes before switching collections.');
      state.collection = c;
      await loadCollection();
      break;
    }
    case 'new':
      state.selected = null;
      await editItem();
      break;
    case 'edit':
      await editItem();
      break;
    case 'lock':
      lock();
      break;
    case 'logout':
      if (!state.demo) await api('/v1/auth/logout', {
        method: 'POST',
        body: {}
      });
      discardWorker();
      state.user = null;
      state.demo = false;
      state.unlocked = false;
      state.rows = [];
      state.selected = null;
      state.snapshot = null;
      closeDialog();
      authScreen(true);
      break;
    case 'demo':
      await demo();
      break;
    case 'generate':
      $('#generated').value = await rpc('generate', Number($('#length').value));
      break;
    case 'generate-item':
      $('#f-password').value = await rpc('generate', 24);
      toast('New password generated');
      break;
    case 'copy-generated':
      await navigator.clipboard.writeText($('#generated').value);
      toast('Password copied');
      break;
    case 'save-generated':
      await editItem({
        username: '',
        password: $('#generated').value,
        url: '',
        notes: '',
        otp: ''
      });
      break;
    case 'reveal': {
      const display = $('#password-display');
      const revealed = el.getAttribute('aria-label') === 'Hide password';
      display.textContent = revealed ? '••••••••••••••••' : (await rpc('get', state.selected)).password;
      el.setAttribute('aria-label', revealed ? 'Reveal password' : 'Hide password');
      break;
    }
    case 'copy-password':
    case 'copy-username': {
      const entry = await rpc('get', state.selected);
      await navigator.clipboard.writeText(name === 'copy-password' ? entry.password : entry.username);
      toast(name === 'copy-password' ? 'Password copied' : 'Username copied');
      break;
    }
    case 'copy-otp': {
      const otp = await rpc('otp', state.selected);
      await navigator.clipboard.writeText(otp.code);
      toast('Verification code copied');
      break;
    }
    case 'delete':
      dialog('Delete this item?', `<p>Delete ${esc(state.selected)} from this collection? Encrypted Git history and existing backups may retain older copies.</p><div class="dialog-footer">${button('Keep item','close')}${button('Delete item','confirm-delete','trash','danger')}</div>`);
      break;
    case 'confirm-delete':
      await rpc('remove', state.selected);
      try {
        await persist()
      } catch (e) {
        toast(errorText(e))
      }
      await refreshRows();
      closeDialog();
      shell();
      break;
    case 'import':
      await importDialog();
      break;
    case 'export':
      await exportFile();
      break;
    case 'sync-now':
      await sync();
      shell();
      toast('Sync checked');
      break;
    case 'reload-server':
      dialog('Load server version?', `<p>Download your encrypted backup first. Loading the server version replaces the pending copy on this device.</p><div class="dialog-footer">${button('Download my changes','export','download')}${button('Load server version','confirm-reload')}</div>`);
      break;
    case 'confirm-reload':
      localStorage.removeItem(draftKey());
      closeDialog();
      await loadCollection();
      break;
    case 'add-user':
      await userDialog();
      break;
    case 'user-status': {
      const u = state.users[Number(el.dataset.index)];
      if (state.demo) u.disabled = !u.disabled;
      else await api('/v1/admin/user-status', {
        method: 'POST',
        body: {
          id: u.id,
          disabled: !u.disabled
        }
      });
      shell();
      break;
    }
    case 'add-group':
      await groupDialog();
      break;
    case 'edit-group':
      await groupDialog(state.groups[Number(el.dataset.index)]);
      break;
  }
}
const demoUsers = [{
  id: 'demo-owner',
  name: 'Alex Morgan',
  username: 'alex@example.test',
  admin: true,
  disabled: false
}, {
  id: 'demo-member',
  name: 'Sam Rivera',
  username: 'sam@example.test',
  admin: false,
  disabled: false
}];
const demoGroups = [{
  id: 'demo-engineering',
  name: 'Engineering',
  members: [{
    user_id: 'demo-owner',
    edit: true
  }, {
    user_id: 'demo-member',
    edit: false
  }]
}];
async function demo() {
  discardWorker();
  state.demo = true;
  state.user = demoUsers[0];
  state.collection = {
    id: 'demo-personal',
    name: 'Personal',
    edit: true,
    group: false
  };
  state.collections = [state.collection];
  state.view = 'items';
  state.filter = 'all';
  state.dirty = false;
  state.conflict = false;
  state.mode = 'standard';
  state.query = '';
  state.snapshot = null;
  await rpc('create', crypto.randomUUID(), false);
  for (const [name, username, url, notes, otp] of [
      ['GitHub', 'alex@example.test', 'https://github.com', 'Personal development account. Recovery codes are kept separately.', 'JBSWY3DPEHPK3PXP'],
      ['Linear', 'alex@example.test', 'https://linear.app', 'Product planning and issue tracking.', null],
      ['Figma', 'alex@example.test', 'https://figma.com', 'Design files and prototypes.', null],
      ['Cloudflare', 'alex@example.test', 'https://dash.cloudflare.com', 'Domain and DNS management.', null],
      ['Home / Wi-Fi', '', '', 'Guest network credentials.', null]
    ]) {
    await rpc('put', name, {
      username,
      url,
      notes,
      otp,
      password: await rpc('generate', 24)
    }, false)
  }
  state.unlocked = true;
  lastActivity = Date.now();
  await refreshRows();
  state.selected = 'GitHub';
  shell()
}
for (const event of ['pointerdown', 'keydown']) document.addEventListener(event, () => lastActivity = Date.now(), {
  passive: true
});
setInterval(() => {
  if (state.unlocked && Date.now() - lastActivity > lockMinutes() * 60000) lock()
}, 1000);
window.addEventListener('pagehide', () => {
  if (state.unlocked) lock();
  else discardWorker()
});
window.addEventListener('pageshow', event => {
  if (event.persisted) {
    state.unlocked = false;
    state.rows = [];
    state.selected = null;
    if (state.user) shell()
  }
});
window.addEventListener('beforeunload', event => {
  if (state.dirty) {
    event.preventDefault();
    event.returnValue = ''
  }
});
(async () => {
  try {
    if (!isSecureContext) throw new Error('Petika requires HTTPS or localhost for browser encryption.');
    const status = await api('/v1/auth/status');
    if (status.user) {
      state.user = status.user;
      await enter()
    } else authScreen(status.initialized)
  } catch (e) {
    authScreen(true);
    $('#auth-form .form-error').textContent = errorText(e)
  }
})();

function accountPasswordDialog() {
  if (state.demo) {
    toast('Account password changes are unavailable in the demo.');
    return;
  }
  dialog('Change account password', `<form id="account-password-form">${field('Current account password','current','password','','required autocomplete="current-password"')}${field('New account password','replacement','password','','required minlength="12" maxlength="1024" autocomplete="new-password"')}${field('Confirm new account password','confirm','password','','required autocomplete="new-password"')}<p class="small muted">Other account sessions will be signed out. This does not change any collection unlock passphrase.</p><div class="form-error" role="alert"></div><div class="dialog-footer"><button class="btn primary" type="submit">Change password</button></div></form>`);
  form('#account-password-form', async data => {
    if (data.get('replacement') !== data.get('confirm')) throw new Error('Passwords do not match.');
    await api('/v1/auth/password', {
      method: 'POST',
      body: {
        current: data.get('current'),
        replacement: data.get('replacement')
      }
    });
    closeDialog();
    toast('Account password changed')
  });
}

// The code is entered manually from the user's terminal, never prefilled from a link.
function cliApprovalScreen() {
  $('#app').innerHTML = `<main class="auth-panel"><div class="auth-form">${brand()}<h1>Connect your CLI</h1><p>Signed in as <strong>${esc(state.user.username)}</strong>.</p><p>Only continue if you started <code>petika login</code> yourself. Enter the code shown in your terminal. Never approve a code someone sent you.</p><p>This grants an eight-hour session with your account permissions. Your collection passphrases stay on your device.</p><form id="cli-approval-form">${field('Code from your terminal','user_code','text','','required maxlength="11" autocomplete="off" spellcheck="false"')}${field('Confirm account password','password','password','','required autocomplete="current-password"')}<div class="field"><label for="cli-decision">Decision</label><select id="cli-decision" name="decision"><option value="deny">Deny this request</option><option value="approve">Approve this CLI</option></select></div><div class="form-error" role="alert"></div><button class="btn primary full" type="submit">Confirm decision</button></form><p><a href="/">Back to Petika</a></p></div></main>`;
  form('#cli-approval-form', async (data, el) => {
    await api('/v1/auth/device/approve', {method:'POST',body:{user_code:data.get('user_code'),password:data.get('password'),approve:data.get('decision')==='approve'}});
    el.reset();
    $('.auth-form').innerHTML = `${brand()}<h1>Request answered</h1><p>Return to your terminal. You can close this page.</p><a href="/">Back to Petika</a>`;
  });
}
