// RFC 6238 using the browser's Web Crypto HMAC implementation.
export function parseOtp(input) {
  if (!input.trim()) return null;
  let secret = input.trim(),
    algorithm = 'SHA-1',
    digits = 6,
    period = 30;
  if (secret.startsWith('otpauth:')) {
    const uri = new URL(secret);
    if (uri.protocol !== 'otpauth:' || uri.hostname !== 'totp') throw new Error('Only time-based (TOTP) setup links are supported.');
    secret = uri.searchParams.get('secret') || '';
    algorithm = ({
      SHA1: 'SHA-1',
      SHA256: 'SHA-256',
      SHA512: 'SHA-512'
    })[(uri.searchParams.get('algorithm') || 'SHA1').toUpperCase()];
    digits = Number(uri.searchParams.get('digits') || 6);
    period = Number(uri.searchParams.get('period') || 30);
  }
  secret = secret.toUpperCase().replace(/\s/g, '').replace(/=+$/, '');
  if (!/^[A-Z2-7]{16,1024}$/.test(secret) || !algorithm || ![6, 8].includes(digits) || ![30, 60].includes(period)) throw new Error('Use a valid Base32 secret or TOTP link (6/8 digits, 30/60 seconds).');
  let buffer = 0,
    bits = 0;
  const bytes = [];
  for (const char of secret) {
    buffer = (buffer << 5) | 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'.indexOf(char);
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      bytes.push((buffer >>> bits) & 255);
    }
  }
  if (bits && (buffer & ((1 << bits) - 1))) throw new Error('Invalid Base32 padding bits.');
  return {
    bytes: new Uint8Array(bytes),
    algorithm,
    digits,
    period
  };
}
export async function totp(input, seconds = Math.floor(Date.now() / 1000)) {
  const config = parseOtp(input);
  if (!config) return null;
  const counter = new Uint8Array(8);
  new DataView(counter.buffer).setBigUint64(0, BigInt(Math.floor(seconds / config.period)));
  const key = await crypto.subtle.importKey('raw', config.bytes, {
    name: 'HMAC',
    hash: config.algorithm
  }, false, ['sign']);
  config.bytes.fill(0);
  const mac = new Uint8Array(await crypto.subtle.sign('HMAC', key, counter));
  const offset = mac[mac.length - 1] & 15;
  const binary = new DataView(mac.buffer).getUint32(offset) & 0x7fffffff;
  mac.fill(0);
  return {
    code: String(binary % 10 ** config.digits).padStart(config.digits, '0'),
    remaining: config.period - seconds % config.period,
    period: config.period
  };
}
