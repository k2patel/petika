// Configuration accepts origins only; never silently drop a path or credentials.
export function serverOrigin(value) {
  if (typeof value !== 'string' || !/^https:\/\/[^/]+\/?$/i.test(value.trim()) || /[\\\s*%?#]/.test(value.trim())) throw new Error('Enter an HTTPS server address without a path, credentials, query, or fragment.');
  const url=new URL(value.trim());
  if (url.protocol !== 'https:' || url.username || url.password || url.pathname !== '/' || !url.hostname) throw new Error('Enter an HTTPS server origin only.');
  return url.origin;
}
export function serverPermission(value) {
  return `https://${new URL(serverOrigin(value)).hostname}/*`;
}
