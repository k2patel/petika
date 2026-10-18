// Pure policy helpers are also exercised without a browser.
export function httpsOrigin(value) {
  const url = new URL(value);
  if (url.protocol !== 'https:' || url.username || url.password) throw new Error('HTTPS websites only.');
  return url.origin;
}
export function authorizeFill(target, itemUrl, origins) {
  const origin = httpsOrigin(target);
  if (!origins.includes(origin)) throw new Error('Allow this exact website in Petika before filling.');
  if (httpsOrigin(itemUrl) !== origin) throw new Error('This login belongs to a different website.');
  return origin;
}
// Serialized by chrome.scripting into an isolated world; no outside dependencies.
export function fillPage(expectedOrigin, kind, values, expiresAt) {
  if (window !== window.top || location.origin !== expectedOrigin || location.protocol !== 'https:') throw new Error('Website changed. Open Petika again.');
  if (Date.now() >= expiresAt) throw new Error('Fill request expired. Try again.');
  const visible = el => {
    const style = getComputedStyle(el);
    const rect = el.getBoundingClientRect();
    for (let node=el; node; node=node.parentElement) {
      const parentStyle=getComputedStyle(node);
      if (Number(parentStyle.opacity) === 0 || parentStyle.visibility !== 'visible' || parentStyle.display === 'none') return false;
    }
    const x=Math.max(0,rect.left)+(Math.min(innerWidth,rect.right)-Math.max(0,rect.left))/2;
    const y=Math.max(0,rect.top)+(Math.min(innerHeight,rect.bottom)-Math.max(0,rect.top))/2;
    if (document.elementFromPoint(x,y) !== el) return false;
    return !el.disabled && !el.readOnly && !el.closest('[inert]') && el.type !== 'hidden'
      && style.visibility === 'visible' && style.display !== 'none' && Number(style.opacity) > 0
      && rect.width > 0 && rect.height > 0 && rect.bottom > 0 && rect.right > 0
      && rect.top < innerHeight && rect.left < innerWidth;
  };
  const inputs = [...document.querySelectorAll('input')].filter(visible);
  const otp = el => el.autocomplete === 'one-time-code' || /^(otp|totp|verification[-_]?code|auth[-_]?code)$/i.test(el.name || el.id);
  const unique = candidates => {
    if (candidates.length !== 1) throw new Error('No unambiguous visible field found. Use copy from Petika instead.');
    return candidates[0];
  };
  let pairs;
  if (kind === 'otp') {
    if (!/^\d{6}(\d{2})?$/.test(values.code)) throw new Error('Invalid verification code.');
    pairs = [[unique(inputs.filter(el => ['text','tel','number','password'].includes(el.type) && otp(el))), values.code]];
  } else if (kind === 'login') {
    const password = unique(inputs.filter(el => el.type === 'password' && !otp(el) && el.autocomplete !== 'new-password'));
    const users = inputs.filter(el => ['email','text'].includes(el.type) && !otp(el) && (el.autocomplete === 'username' || el.type === 'email' || /^(user(name)?|email|login)$/i.test(el.name || el.id)));
    if (users.length > 1) throw new Error('Multiple username fields found. Use copy from Petika instead.');
    pairs = [...(users.length ? [[users[0], values.username]] : []), [password, values.password]];
  } else throw new Error('Unsupported fill operation.');
  for (const [el, value] of pairs) {
    if (el.form && new URL(el.form.action || location.href, location.href).origin !== expectedOrigin) throw new Error('This form submits to a different website.');
    if (el.maxLength >= 0 && value.length > el.maxLength) throw new Error('The field is too short for this value.');
  }
  const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set;
  for (const [el, value] of pairs) {
    if (location.origin !== expectedOrigin || !el.isConnected || !visible(el) || Date.now() >= expiresAt) throw new Error('Page changed before filling.');
    if (el.form && new URL(el.form.action || location.href,location.href).origin !== expectedOrigin) throw new Error('Form destination changed.');
    setter.call(el, value);
    el.dispatchEvent(new Event('input', {bubbles:true}));
    el.dispatchEvent(new Event('change', {bubbles:true}));
  }
  return {filled:pairs.length};
}
