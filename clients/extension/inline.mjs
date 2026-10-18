// Runs only in an isolated world, after an explicit toolbar action. No vault data.
export function installInline(expectedOrigin, grantId, expiresAt, css) {
  if (window !== window.top || location.protocol !== 'https:' || location.origin !== expectedOrigin || Date.now() >= expiresAt) throw new Error('Website changed. Reopen Petika.');
  globalThis.petikaInlineCleanup?.();
  let field, host, stopped = false;
  const eligible = el => {
    if (!(el instanceof HTMLInputElement) || el.type !== 'password' || el.autocomplete !== 'new-password' || el.disabled || el.readOnly || el.closest('[inert]')) return false;
    if (el.form && new URL(el.form.action || location.href,location.href).origin !== expectedOrigin) return false;
    for (let node=el;node;node=node.parentElement) {
      const s=getComputedStyle(node);
      if (s.display === 'none' || s.visibility !== 'visible' || Number(s.opacity) === 0) return false;
    }
    const r=el.getBoundingClientRect();
    return r.width > 0 && r.height > 0 && r.top >= 0 && r.bottom <= innerHeight && r.left >= 0 && r.right <= innerWidth && document.elementFromPoint(r.left+r.width/2,r.top+r.height/2) === el;
  };
  const remove = () => { host?.remove(); host=null; };
  const focus = event => {
    if (!event.isTrusted || stopped) return;
    if (Date.now() >= expiresAt || location.origin !== expectedOrigin) { cleanup(); return; }
    if (event.target === host) return;
    remove(); field=event.target;
    if (!eligible(field)) return;
    host=document.createElement('span'); host.setAttribute('data-petika-prompt','');
    const shadow=host.attachShadow({mode:'closed'});
    const sheet=new CSSStyleSheet(); sheet.replaceSync(css); shadow.adoptedStyleSheets=[sheet];
    const button=document.createElement('button'); button.type='button'; button.textContent='Create password in Petika';
    const dismiss=document.createElement('button'); dismiss.type='button'; dismiss.textContent='Dismiss';
    dismiss.addEventListener('click',event => { if (event.isTrusted) cleanup(); });
    button.addEventListener('click',async event => {
      if (!event.isTrusted || stopped || Date.now() >= expiresAt || location.origin !== expectedOrigin || !field?.isConnected || !eligible(field)) return;
      button.disabled=true;
      try {
        const result=await chrome.runtime.sendMessage({type:'petika.generate',grantId});
        if (!result?.ok) throw new Error('Open Petika from the toolbar to continue.');
        cleanup();
      } catch { button.textContent='Open Petika from the toolbar'; }
    });
    const controls=document.createElement('span'); controls.className='petika-inline';
    controls.append(button,dismiss); shadow.append(controls); field.insertAdjacentElement('afterend',host);
  };
  const cleanup = () => {
    stopped=true; remove(); clearTimeout(timeout);
    document.removeEventListener('focusin',focus,true);
    window.removeEventListener('pagehide',cleanup);
  };
  const timeout=setTimeout(cleanup,Math.max(0,expiresAt-Date.now()));
  document.addEventListener('focusin',focus,true); window.addEventListener('pagehide',cleanup,{once:true});
  globalThis.petikaInlineCleanup=cleanup;
  return {installed:true};
}
