// Experimental format for random test data only; never a Petika vault format.
const label = new TextEncoder().encode("petika.synthetic.prf-wrapper.v1");
export const random = (size) => crypto.getRandomValues(new Uint8Array(size));

async function keyFor(prf, salt) {
  if (!(prf instanceof Uint8Array) || prf.length !== 32) throw new Error("PRF unavailable");
  const material = await crypto.subtle.importKey("raw", prf, "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey({ name: "HKDF", hash: "SHA-256", salt, info: label },
    material, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}

export async function seal(prf, plaintext, binding) {
  const salt = random(32), iv = random(12);
  const key = await keyFor(prf, salt);
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: binding }, key, plaintext);
  return { salt, iv, ciphertext };
}

export async function open(prf, envelope, binding) {
  const key = await keyFor(prf, envelope.salt);
  return new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: envelope.iv,
    additionalData: binding }, key, envelope.ciphertext));
}
