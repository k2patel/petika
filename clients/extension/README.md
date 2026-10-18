# Chromium autofill preview

Experimental, unpacked Manifest V3 extension for local QA. It packages the existing
Rust/WASM worker and the single web stylesheet; it loads no remote executable code.
It supports explicit toolbar-popup filling of saved usernames/passwords and fresh
TOTP codes. No account password is entered into the extension.

For public preview installation and Chrome/Firefox distribution status, see
[Try Petika before browser-store releases](../../docs/preview-installation.md).

For a user receiving a prepared package, start with the
[user installation guide](../../docs/user-guide.md#install-the-chromium-extension-preview).
Administrators preparing packages can follow the build steps below.

## Build and connect

Build the web WASM first (`scripts/build_web.sh`), then:

```sh
python3 scripts/build_extension.py --endpoint https://petika.k2patel.in
```

In Chromium/Chrome 127 or newer, open `chrome://extensions`, enable Developer mode, choose
**Load unpacked**, and select `output/extension-chromium`. Pin Petika to the toolbar.
This does not install anything automatically or publish to a browser store.

The server must include the client/website APIs from commit `9e9b6dd` or newer.
Packaging the extension does not deploy that server update. The deployment must
serve HTTPS with a certificate trusted by the browser, and the configured endpoint
must be the final canonical origin (redirects are rejected).

1. Open the toolbar popup and choose **Connect to Petika**.
2. Note the code, choose **Open approval page**, and approve that exact code after
   signing in to Petika. Only approve a connection you initiated.
3. Reopen the popup and choose **Finish connecting**. The initial preview uses the
   existing CLI approval protocol: the web approval page says CLI, and Connected
   clients lists the session as CLI. It grants the same eight-hour account API
   session as a CLI client, not a restricted autofill-only token.
4. In the web app, open **Browser autofill → Manage websites** and add the exact
   HTTPS origin, for example `https://example.com`. Subdomains and nondefault ports
   require separate entries. Ensure the saved login's Website has the same origin.
5. Visit that website, open Petika from the toolbar, select a collection and unlock
   it with its collection passphrase. Choose **Fill login** or **Fill code**.
6. Submit the website form yourself. Closing the popup locks the collection; reopen
   and unlock for a later page or a multi-step verification-code prompt.

TOTP setup still happens in the web app: enter the website's Base32 setup key or
`otpauth://totp/` link into the login item, then confirm MFA on the website using a
generated code. The preview never enables website MFA by itself.

**Fill code** supports a single code field or a complete group of six/eight visible
single-character fields. For a split group, every field must have
`autocomplete="one-time-code"`, `maxlength="1"`, a text/tel/password input type,
and the same form owner. The digit count must match the generated code; fields
are filled in DOM order, preserving leading zeroes. Missing digits, mixed forms,
competing code fields, and cross-origin form actions are rejected. Custom widgets
without these markers still require manual entry. Petika does not submit forms;
a website may react to input events and submit its own form.

## Generate a password for signup or a password change

On an allowed HTTPS website, unlock a writable collection and choose **Generate a
password**. Enter a login name and username, choose a length (24 characters by
default), and select **Save encrypted login**. After confirmation, choose **Fill new
password** on the saved login. Only visible fields explicitly marked
`autocomplete="new-password"` are supported, including a confirmation field in the
same form. Current-password fields are left intact; enter the username separately.
The extension never submits the website form.

The suggestion is generated locally using the existing Rust/WASM generator. Saving
creates a separate encrypted login and preserves existing entries. Complete the
website change, verify the new login works, then remove obsolete entries in Petika.
Closing the popup before saving discards the suggestion. Concurrent changes or an
uncertain save acknowledgement block further saves until reopening: check the server
copy before retrying. Read-only collections cannot save new logins. Version-2 group
saves retain the existing key epoch and check membership and snapshot revisions.

## Inline signup prompt

Unlock on an allowed website and choose **Show signup suggestions on this page**.
Close the toolbar popup and focus a visible `autocomplete="new-password"` field.
Choose **Create password in Petika** to open the extension, unlock the collection,
and continue directly to the generator. Save and fill remain explicit actions.
**Dismiss** removes the prompt for this activation. Navigation or five minutes
ends the activation; enable it again from the toolbar when needed.

The prompt is a launcher, not a password dropdown: no password, login list, token,
or passphrase entry is placed in the webpage. The isolated script sends only a
popup request. The background checks its extension sender, top-level document,
active tab, origin, and expiring grant. The popup repeats the usual permission and
unlock checks. A revoked permission may leave the harmless launcher visible until
expiry, but cannot authorize saving or filling. A site can imitate any in-page UI;
enter passphrases only in the actual extension popup. If Chrome cannot open it,
use the toolbar. Chrome 127+ is required for
[`action.openPopup`](https://developer.chrome.com/docs/extensions/reference/api/action#method-openPopup).

Styling is extracted from the marked section of the shared `clients/web/app.css`
into a closed shadow root. There is no second authored stylesheet, remote asset,
page-window message listener, or persistent website permission.

## Boundaries

- Host permission is scoped to the configured Petika server. Website access uses
  `activeTab` only after invoking the toolbar action; there are no always-on content
  scripts or `externally_connectable` handlers. The opt-in inline script can request
  only the trusted popup; it cannot read extension session storage or vault data.
- Website origin, saved-item origin, account website permission, collection access,
  and active session are checked before each fill. Browser document IDs bind the
  operation to the inspected top-level document. Navigation requires reopening.
- Fill code executes in the isolated world and rechecks HTTPS origin and expiry.
  It refuses hidden/offscreen/covered/read-only/ambiguous fields and cross-origin
  form actions. It never clicks a submit button. A website can read values after
  they are filled; autofill cannot protect against malicious code on an allowed site.
- OTP seeds remain in the extension's local crypto worker. Only the generated code
  reaches a website. Codes with five seconds or less remaining require retrying.
- Vault keys/passphrases and plaintext entries are never persisted. Session tokens
  use trusted-context-only `chrome.storage.session`, bound to the configured server;
  restarting the browser clears them. The popup locks on close or after five minutes.
- Revoking a client or website permission blocks subsequent online fills. Revocation
  cannot erase previously downloaded data or values already filled into a webpage.
- The extension enforces website permissions locally. The server's legacy
  `enforced: false` field means the server does not itself enforce browser filling.
  A modified client with vault access can ignore client-side policies.

## Not implemented

Automatic suggestions on every visit, inline saved-login selection, updating an existing login from the extension,
QR capture, Firefox/Safari packaging, unmarked/custom OTP widgets, username-only login steps,
iframe/shadow-DOM forms, device-key unlocking, native biometrics, narrowly scoped
extension credentials, browser-store publishing, and independent security review.
The web app already offers generated passwords when creating/editing items.

## Validation

```sh
node scripts/test_extension_policy.mjs
python3 scripts/test_extension.py
```

The integration test requires Python Playwright, its Chromium download, built WASM,
and `target/debug/petika-server`. It uses a disposable server/profile and synthetic
credentials. Synthetic HTTPS origins are routed to the local server; test-only
website host permission stands in for a toolbar gesture. Tests cover the real
packaged worker, approval, login/TOTP fill, permission/client revocation, navigation,
field rejection and storage isolation. Manual toolbar installation/activation and
real-site compatibility are still QA requirements.

Platform references: [activeTab](https://developer.chrome.com/docs/extensions/develop/concepts/activeTab),
[scripting/document targets](https://developer.chrome.com/docs/extensions/reference/api/scripting),
[packaged WASM CSP](https://developer.chrome.com/docs/extensions/reference/manifest/content-security-policy),
[extension network permissions](https://developer.chrome.com/docs/extensions/develop/concepts/network-requests).
