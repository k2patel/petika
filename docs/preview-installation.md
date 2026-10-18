# Try Petika before browser-store releases

Petika is an experimental, unaudited self-hosted password manager. **Use synthetic
(test) credentials for now.** You can try the web app without installing a browser
extension. There is no Chrome Web Store or Firefox Add-ons release at present.

## Choose how to try it

| Component | Available today | Installation |
| --- | --- | --- |
| Web app | Rust/WASM interface served by your Petika server | Open your server's URL; no extension or store account required |
| Server and CLI | Source builds | Follow the [root README](../README.md#run-from-source) or [administrator guide](administrator-guide.md) |
| Chrome/Chromium extension | Experimental unpacked preview, Chrome 127+ | Build a generic or server-pinned package, then use Developer mode → Load unpacked |
| Firefox extension | Not yet ported or tested | Use the web app; the Chromium package is not a supported Firefox add-on |
| Safari extension, native mobile/desktop apps | Not available | Use the web app; there are no signed native installers to download |

There is no public prebuilt container image or crates.io package yet. A GitHub
source-code ZIP is not an installable browser-extension package. The project does
not require separate browser plugins to use the web app.

## 1. Get a server running

If someone administers Petika for you, ask for its HTTPS URL and your account.
Otherwise follow [Run from source](../README.md#run-from-source), then the
[administrator guide](administrator-guide.md) for remote hosting and backups.
The root README's local HTTP example is for development; the extension requires
an HTTPS server with a certificate trusted by your browser.

Use your own server hostname throughout this guide. `petika.example.com` below
is a placeholder, not a hosted Petika service. Repository examples mentioning
`petika.k2patel.in` describe the maintainer's deployment, not a public signup service.

Sign in, create a test collection, and add a synthetic login using the
[user guide](user-guide.md). Your account password signs you in; your collection
passphrase unlocks the encrypted vault locally. Neither is an extension signing key.

## 2. Optional: build the Chromium preview

On a build machine, install Git, Python 3, and Rust through
[rustup](https://rustup.rs/). The repository pins its Rust toolchain. From a fresh
checkout:

```sh
git clone https://github.com/k2patel/petika.git
cd petika
rustup target add wasm32-unknown-unknown
cargo install wasm-bindgen-cli --version 0.2.114 --locked
sh scripts/build_web.sh
python3 scripts/build_extension.py --generic
```

The generic package asks for your server on first use. To pin a package to one
server instead, use `--endpoint https://petika.example.com` instead of `--generic`,
replacing the placeholder with your final HTTPS origin. The build produces `output/extension-chromium/`, including `manifest.json`,
packaged JavaScript/WASM and the shared stylesheet. It does not contain your vault,
server secrets, or credentials. Do not distribute your checkout's `.secrets` folder.
An administrator can provide this prepared folder to testers who do not build code.

1. Keep the prepared folder in a stable location. Extract it first if provided as a ZIP.
2. In Chrome/Chromium 127+, open `chrome://extensions`.
3. Turn on **Developer mode**, choose **Load unpacked**, and select the folder
   containing `manifest.json`. Do not choose the repository root or **Pack extension**.
4. Pin Petika to the toolbar. In a generic package, enter your own HTTPS server
   address and select **Use this server**, then allow access when Chrome asks.
   A server-pinned package skips this step. On managed computers, an administrator may prohibit
   developer extensions; use the web app if installation is blocked.
5. Choose **Connect to Petika**, open its approval page, and approve your code after
   signing in. The current approval screen calls this a **CLI** session. It has
   your account API permissions for up to eight hours, not an autofill-only scope.
6. Return to the popup and finish connecting. Add the target website's exact HTTPS
   origin under **Browser autofill → Manage websites** in the web app.
7. Visit that website, open Petika, and unlock your collection. Select **Fill login**
   or **Fill code**. See the [user guide](user-guide.md) for password generation,
   inline signup prompts, supported TOTP fields, and revoking clients.

This uses Chrome's documented development installation flow; it does not make the
preview a store-reviewed extension. See Google's
[Load an unpacked extension instructions](https://developer.chrome.com/docs/extensions/get-started/tutorial/hello-world#load-unpacked).

## Updates, removal, and common problems

Unpacked installations have no Petika automatic-update service. Obtain a new build
from trusted source, replace the prepared folder, and click **Reload** on Petika's
card in `chrome://extensions`. Close and reopen its popup; reconnect if required.
In the generic package, **Change server** clears local session state and requests
access to the new host. Revoke the old session on the old server under Connected
clients if needed; changing servers is only a local disconnect. A pinned package
must be rebuilt for a different endpoint. Editing `config.json` alone does not
update its manifest permissions or content-security policy.

To remove it, revoke its CLI session under **Connected clients**, then choose
**Remove** in `chrome://extensions`. Removal does not delete server-side vaults.

| Problem | What to check |
| --- | --- |
| Manifest missing | Select the built folder, not the source ZIP; check that WASM was built before packaging |
| HTTPS/certificate or redirect error | Use your final canonical server origin and a browser-trusted certificate; do not bypass certificate checks |
| No matching login | Allow the exact website origin and set that same origin on the saved login |
| Extension blocked by policy | Ask your administrator or use the web app |
| Firefox rejects the package | Firefox support is not implemented; renaming the ZIP to XPI does not port or sign it |

## How store distribution will work

These are future distribution paths, not releases already submitted or approved.
Browser signing/distribution, HTTPS certificates, and vault encryption are separate
concerns. A signed extension is not evidence of an independent cryptographic audit.

### Chrome Web Store

The normal public-user route is a Web Store extension. A maintainer registers a
developer account, uploads the extension ZIP, supplies listing/privacy information
and reviewer test instructions, and submits it for review. See
[Google's publishing process](https://developer.chrome.com/docs/webstore/publish).

Chrome supports **private** distribution to selected testers, **unlisted**
distribution to anyone with the store URL, and **public** listing. All three have
the same policy and review requirements; unlisted is not a review bypass. See
[Chrome distribution visibility](https://developer.chrome.com/docs/webstore/cws-dashboard-distribution).

A self-packed `.crx` on GitHub is not a general replacement for this flow. Chrome's
self-hosted packed-extension distribution on Windows/macOS requires enterprise
policies; Linux has additional self-hosting options. This is separate from the
unpacked development workflow above. See
[Chrome distribution options](https://developer.chrome.com/docs/extensions/how-to/distribute).

### Firefox / Mozilla Add-ons (AMO)

First Petika needs a Firefox-compatible manifest, API adaptations, and browser tests.
The current Chromium implementation must not be presented as a Firefox build.
For a future compatible build, normal Firefox installation requires Mozilla signing.
Maintainers can choose an AMO listing or **unlisted/self-distributed signing**, then
host the signed XPI themselves, including on GitHub. Unlisted extensions still have
to comply with Mozilla's policies. See
[Mozilla signing and distribution](https://extensionworkshop.com/documentation/publish/signing-and-distribution-overview/).

Firefox also supports temporary developer installation through `about:debugging` →
**This Firefox** → **Load Temporary Add-on**. It lasts until Firefox restarts and is
for testing a compatible build, not a durable unsigned-user distribution channel.
This is not an installation instruction for today's Chromium-only Petika package.
See [Mozilla temporary installation](https://extensionworkshop.com/documentation/develop/temporary-installation-in-firefox/).

## Maintainer release checklist

- [ ] Port and test Firefox separately, including popup launch, storage isolation,
  document binding, permissions, WASM, and all fill rejection cases.
- [x] Generic preview with a user-selected HTTPS origin and optional host permission;
  retain deployment-pinned packages. Generic CSP allows HTTPS connections while
  executable code stays packaged. API requests stay bound to the selected origin.
- [ ] Manually verify permission grant/denial and revocation in supported Chrome
  versions; review the generic package's broader CSP and browser host-permission
  scope before store submission. Host permissions cover all ports on that host.
- [ ] Review extension session scope and security before promoting use with real secrets.
- [ ] Prepare privacy disclosures, permission explanations, support contacts,
  screenshots, source/build instructions, and synthetic reviewer credentials.
- [ ] Establish publisher accounts, protected publishing credentials, versioned
  release artifacts, update procedures, and a staged tester release.
- [ ] Complete browser-store review/signing and add verified install links here.

Distribution guidance checked against official browser documentation on 2026-10-18.
