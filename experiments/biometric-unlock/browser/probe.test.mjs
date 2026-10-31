import test from "node:test";
import assert from "node:assert/strict";
import { random, seal, open } from "./wrapper.mjs";
import { Probe } from "./probe.mjs";

test("wrapper rejects wrong PRF, salt, nonce, ciphertext and credential binding", async () => {
  const prf = random(32), data = random(32), binding = random(32);
  const box = await seal(prf, data, binding);
  assert.deepEqual(await open(prf, box, binding), data);
  await assert.rejects(open(random(32), box, binding));
  await assert.rejects(open(prf, box, random(32)));
  for (const field of ["salt", "iv", "ciphertext"]) {
    const changed = new Uint8Array(box[field]);
    changed[0] ^= 1;
    await assert.rejects(open(prf, { ...box, [field]: changed }, binding));
  }
  await assert.rejects(seal(new Uint8Array(0), data, binding));
});

function mock() {
  const id = random(32), prf = random(32);
  const state = { enabled: true, output: true, flags: 5, id, cancel: false };
  const credentials = {
    async create(options) {
      assert.equal(options.publicKey.authenticatorSelection.userVerification, "required");
      return { rawId: id, getClientExtensionResults: () => ({ prf: { enabled: state.enabled } }) };
    },
    async get(options) {
      assert.equal(options.publicKey.userVerification, "required");
      assert.deepEqual(options.publicKey.allowCredentials[0].id, id);
      if (state.cancel) throw new DOMException("Canceled", "NotAllowedError");
      const authenticatorData = new Uint8Array(37);
      authenticatorData[32] = state.flags;
      return { rawId: state.id, response: { authenticatorData },
        getClientExtensionResults: () => state.output ? { prf: { results: { first: prf.slice().buffer } } } : {} };
    },
  };
  return { state, credentials };
}

test("mock ceremonies seal then reopen; never a hardware/biometric result", async () => {
  const { credentials } = mock(), probe = new Probe(credentials);
  await probe.create();
  assert.equal(await probe.run(), "sealed");
  assert.equal(await probe.run(), "opened");
  probe.reset();
  await assert.rejects(probe.run());
});

test("missing PRF, absent verification, substituted credential and cancellation fail closed", async () => {
  for (const change of [{ output: false }, { flags: 1 }, { id: random(32) }, { cancel: true }]) {
    const { credentials, state } = mock(), probe = new Probe(credentials);
    await probe.create();
    Object.assign(state, change);
    await assert.rejects(probe.run());
    assert.equal(probe.record.envelope, null);
  }
  const { credentials, state } = mock(), probe = new Probe(credentials);
  state.enabled = false;
  await assert.rejects(probe.create());
  assert.equal(probe.record, null);
});

test("reset rejects a late credential response instead of restoring cleared state", async () => {
  const { credentials } = mock();
  const response = await credentials.create({ publicKey: { authenticatorSelection: { userVerification: "required" } } });
  let finish;
  credentials.create = () => new Promise(resolve => { finish = resolve; });
  const probe = new Probe(credentials), pending = probe.create();
  probe.reset();
  finish(response);
  await assert.rejects(pending, { name: "AbortError" });
  assert.equal(probe.record, null);
});

test("reset during unlock discards the late assertion", async () => {
  const { credentials } = mock(), probe = new Probe(credentials);
  await probe.create();
  await probe.run();
  const response = await credentials.get({ publicKey: {
    userVerification: "required", allowCredentials: [{ id: probe.record.id }],
  } });
  let finish;
  credentials.get = () => new Promise(resolve => { finish = resolve; });
  const pending = probe.run();
  probe.reset();
  finish(response);
  await assert.rejects(pending, { name: "AbortError" });
  assert.equal(probe.record, null);
});
