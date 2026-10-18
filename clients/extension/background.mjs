// No external or page-window messaging. Content scripts can request only a popup.
// Session tokens remain available exclusively to trusted extension contexts.
chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.session.setAccessLevel({accessLevel:'TRUSTED_CONTEXTS'});
});
chrome.runtime.onMessage.addListener((message,sender,respond) => {
  if (message?.type !== 'petika.generate') return false;
  (async () => {
    if (sender.id !== chrome.runtime.id || sender.frameId !== 0 || !sender.tab?.id || !sender.documentId) throw new Error('Invalid sender');
    const key=`inline:${sender.tab.id}`;
    const stored=await chrome.storage.session.get(key), grant=stored[key];
    if (!grant || grant.id !== message.grantId || grant.documentId !== sender.documentId || grant.expiresAt <= Date.now() || new URL(sender.url).origin !== grant.origin) throw new Error('Expired prompt');
    const tab=await chrome.tabs.get(sender.tab.id);
    if (!tab.active || new URL(tab.url).origin !== grant.origin) throw new Error('Inactive website');
    await chrome.storage.session.set({inlineIntent:{...grant,tabId:tab.id}});
    await chrome.action.openPopup({windowId:tab.windowId});
    await chrome.storage.session.remove(key);
    respond({ok:true});
  })().catch(() => respond({ok:false}));
  return true;
});
chrome.tabs.onRemoved.addListener(tabId => chrome.storage.session.remove(`inline:${tabId}`));
