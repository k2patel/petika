import { Probe } from "./probe.mjs";
const probe = new Probe(navigator.credentials);
const create = document.getElementById("create"), run = document.getElementById("run");
const result = document.getElementById("result");
const supported = isSecureContext && !!globalThis.PublicKeyCredential && !!crypto.subtle;
document.getElementById("capability").textContent = supported
  ? "WebAuthn is available. PRF support requires an actual authenticator test."
  : "WebAuthn is unavailable here. Use a supporting browser on localhost or HTTPS.";
create.disabled = !supported;
let generation = 0, busy = false;
function reset() {
  generation += 1;
  probe.reset();
  busy = false;
  create.disabled = !supported;
  run.disabled = true;
  run.textContent = "Seal test data";
  result.textContent = "Test state cleared. Any created passkey remains in your authenticator.";
}
async function perform(operation) {
  if (busy) return;
  busy = true;
  const current = generation;
  create.disabled = run.disabled = true;
  result.textContent = "Waiting for your authenticator…";
  try {
    const outcome = await operation();
    if (current !== generation) return;
    result.textContent = outcome === "opened" ? "Passed: the passkey opened the generated test data."
      : outcome === "sealed" ? "Test data sealed. Approve again to test opening it."
      : "PRF-enabled test credential created. Seal test data next.";
    run.textContent = probe.record?.envelope ? "Open test data" : "Seal test data";
  } catch {
    if (current === generation) result.textContent = "Test did not complete: canceled, unsupported, or verification failed. No fallback key was used.";
  } finally {
    if (current === generation) {
      busy = false;
      create.disabled = !supported;
      run.disabled = !probe.record;
    }
  }
}
create.addEventListener("click", () => perform(() => probe.create()));
run.addEventListener("click", () => perform(() => probe.run()));
document.getElementById("reset").addEventListener("click", reset);
document.addEventListener("visibilitychange", () => { if (document.hidden) reset(); });
window.addEventListener("pagehide", reset);
