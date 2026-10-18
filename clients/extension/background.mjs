// No web-page messaging or externally_connectable interface is registered.
// Session tokens are available only to trusted extension contexts, never content scripts.
chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.session.setAccessLevel({accessLevel:'TRUSTED_CONTEXTS'});
});
