import { random, seal, open } from "./wrapper.mjs";

function same(a, b) {
  return a.length === b.length && a.every((value, i) => value === b[i]);
}

// Injectable credential interface allows cancellation/missing-PRF tests without
// confusing mock evidence with authenticator or biometric validation.
export class Probe {
  constructor(credentials) { this.credentials = credentials; this.reset(); }

  reset() {
    this.controller?.abort();
    this.controller = new AbortController();
    this.record = null;
  }

  async create() {
    this.reset();
    const signal = this.controller.signal;
    const credential = await this.credentials.create({ signal, publicKey: {
      challenge: random(32), rp: { name: "Petika synthetic unlock probe" },
      user: { id: random(32), name: "petika-synthetic-probe", displayName: "Petika synthetic probe" },
      pubKeyCredParams: [{ type: "public-key", alg: -7 }], attestation: "none",
      authenticatorSelection: { residentKey: "required", userVerification: "required" },
      extensions: { prf: {} }, timeout: 60000,
    } });
    signal.throwIfAborted();
    if (!credential?.getClientExtensionResults().prf?.enabled) throw new Error("PRF unavailable");
    this.record = { id: new Uint8Array(credential.rawId), input: random(32), envelope: null, digest: null };
  }

  async run() {
    const record = this.record, signal = this.controller.signal;
    if (!record) throw new Error("Create a test credential first");
    const credential = await this.credentials.get({ signal, publicKey: {
      challenge: random(32), allowCredentials: [{ type: "public-key", id: record.id }],
      userVerification: "required", timeout: 60000,
      extensions: { prf: { eval: { first: record.input } } },
    } });
    signal.throwIfAborted();
    if (!credential || !same(new Uint8Array(credential.rawId), record.id)) throw new Error("Credential mismatch");
    const authData = new Uint8Array(credential.response.authenticatorData);
    if (authData.length < 37 || (authData[32] & 5) !== 5) throw new Error("User verification absent");
    const result = credential.getClientExtensionResults().prf?.results?.first;
    if (!result || result.byteLength !== 32) throw new Error("PRF unavailable");
    const prf = new Uint8Array(result);
    try {
      if (!record.envelope) {
        const plaintext = random(32);
        try {
          const digest = await crypto.subtle.digest("SHA-256", plaintext);
          const envelope = await seal(prf, plaintext, record.id);
          signal.throwIfAborted();
          record.digest = new Uint8Array(digest);
          record.envelope = envelope;
          return "sealed";
        } finally { plaintext.fill(0); }
      }
      const plaintext = await open(prf, record.envelope, record.id);
      try {
        const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", plaintext));
        signal.throwIfAborted();
        if (!same(digest, record.digest)) throw new Error("Mismatch");
        return "opened";
      } finally { plaintext.fill(0); }
    } finally { prf.fill(0); }
  }
}
