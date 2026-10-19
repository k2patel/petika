# Install and use Petika

Use this guide to sign in, save logins, set up verification codes, install the
Chromium preview, and protect your recovery copies. Your administrator installs
and operates the Petika server. You do not need Rust, Docker, or command-line tools
to use the web app.

Petika is experimental and unaudited. Use synthetic/test accounts for now. There
are no published mobile apps, browser-store extension, or public binary installer.

## What you need

Ask your administrator for your Petika HTTPS address, your own username, and your
initial account password. Use your installation’s custom domain, such as
`https://petika.example.com`; this is a placeholder, not a hosted service. If you
are testing your own local installation, use `http://localhost:8080` as described
in the [installation guide](deployment.md).

Open that address in your browser. No installation is needed for the web app.
Do not use the administrator's account for everyday access. There is no public
self-registration flow: an administrator creates additional users.

## First sign-in and collection setup

1. Sign in with your assigned username and account password.
2. If you received an initial password, open **Settings → Change account password**
   and choose your own. Changing it signs out other account sessions and revokes
   backup API keys; it does not change the collection unlock passphrase.
3. Open **All items**. For a new Personal collection, enter and confirm a strong
   collection unlock passphrase. Choose **Standard** for the current default
   protection. **Hybrid** is experimental; the planned compliance/device profiles
   are not selectable production features.
4. Choose **Create encrypted collection**. On later visits, choose **Unlock
   collection** with that collection's passphrase.

Your **account password** signs you into the server. Your **collection passphrase**
opens encrypted contents on your device. Keep recovery material separately from
Petika: the server cannot recover a forgotten collection passphrase.

Groups appear only when an administrator gives you access. Group membership alone
is not a decryption key; follow the [group access guide](group-access.md) with the
person sharing the collection. Read-only members cannot edit it.

## Save a login and generate a password

1. Unlock the collection and select **New item**.
2. Enter a name, username, and the website's full HTTPS address.
3. Choose **Use suggested password** to accept the locally generated password, or
   enter an existing password. **Generate another** offers a different suggestion.
4. Choose **Save item**. Saving in Petika does not create an account or change a
   password on the website; complete the website's signup/password-change flow too.
5. Select the saved item to reveal or copy its fields.

When editing an existing item, **Suggest password** does not replace its password
until you choose the suggestion. The separate **Password generator** tool can
also generate, copy, and save a new login. Use **Sync & backup** to investigate
pending changes or conflicts before closing or locking the app.

## Set up website verification codes

This works for websites that support authenticator-app **TOTP**, not SMS/email
codes, push approvals, or security-key-only MFA.

1. On the website, open its security settings and enable two-factor authentication.
   Choose an authenticator app.
2. Ask the website to show its manual setup key or an `otpauth://totp/` link. If it
   only shows a QR code, look for **Can't scan?** or **Enter manually**. Petika QR
   scanning is not implemented yet.
3. Edit the matching Petika login, paste the value into **Verification-code setup
   key**, and save the item. This key is stored encrypted with the login.
4. Copy the generated verification code from the saved item and enter it on the
   website to finish enabling MFA. Retain the website's recovery codes separately.
5. At later sign-ins, copy a current code, or use the Chromium preview below.

Saving the setup key in Petika alone does not enable MFA on the website. If a code
fails, check the device clock, correct login, and expiry countdown. Storing the
password and TOTP key in the same vault makes both available when that vault is
unlocked; use a separate authenticator/security key if you need separate custody.

## Install the Chromium extension preview

Ask your administrator for a built **Petika Chromium preview folder or ZIP** for
this server. A source-code ZIP is not an installable extension: the prepared folder
must contain `manifest.json`, the popup files, and a `wasm` directory. The administrator
build instructions are in the [extension guide](../clients/extension/README.md).

1. Extract the supplied ZIP to a folder you will keep, if necessary.
2. Open `chrome://extensions` in Chrome/Chromium 127 or newer.
3. Turn on **Developer mode**, choose **Load unpacked**, and select the prepared
   folder containing `manifest.json`.
4. Pin Petika using the browser's Extensions menu. This preview is installed locally;
   it is not a Chrome Web Store release. Firefox and Safari are not supported yet.
5. Open Petika from the toolbar. If it asks for a server, enter your own Petika
   HTTPS address, choose **Use this server**, and approve Chrome's host-access
   request. Then select **Connect to Petika**. Note its approval
   code, then select **Open approval page**.
6. Sign in on your Petika website, enter that exact code, confirm your account
   password, select **Approve this CLI**, then choose **Confirm decision**. Only
   approve a code you initiated.
   The preview uses the existing CLI protocol, so the approval page and Connected
   clients list call it a CLI session. It has your account API permissions for up
   to eight hours; it is not a narrowly scoped autofill-only credential.
7. Return to the toolbar popup and choose **Finish connecting**.

### Allow a website and fill

1. In Petika's web app, open **Browser autofill → Manage websites**.
2. Add the exact HTTPS origin, such as `https://example.com`. Do not include a path
   like `/login`. A subdomain or a different port needs its own entry.
3. Ensure the login's **Website** matches that origin.
4. Visit the website, open the Petika toolbar popup, select the collection, and
   unlock it locally with its collection passphrase.
5. Choose **Fill login** or **Fill code**. Petika fills visible matching fields and
   does not submit the form. Complete the website's sign-in yourself.

Closing the popup locks the collection. Reopen and unlock it for a later MFA page.
Codes close to expiry require waiting a few seconds and selecting **Fill code**
again. A code can fill one field or six/eight separate digit boxes when the website
marks all boxes as verification-code fields in the same form. Incomplete or
ambiguous groups are rejected; use the web app to copy the code when unsupported.
The preview does not support inline saved-login lists, QR capture, username-only
steps, or forms inside frames/shadow DOM. Some websites submit themselves once
the last digit is entered; Petika does not click Submit.

### Generate a password in the extension

1. On the allowed signup or password-change page, open Petika and unlock a writable
   collection. Choose **Generate a password**.
2. Enter a login name and username. Keep the suggested 24-character password or
   choose another length and **Generate another**.
3. Choose **Save encrypted login** and wait for confirmation. This creates a new
   login; your previous password remains in its existing entry.
4. Choose **Fill new password** on the new login. Petika fills explicit new-password
   and confirmation fields in the same form, leaving current-password fields alone.
   Enter the username separately and complete the website form yourself.
5. Verify the new password works before removing any obsolete entry in Petika.

If the website's fields are unsupported, copy from the saved item in the web app.
Closing the popup discards an unsaved suggestion. If a save conflicts or its result
is uncertain, reopen and check the collection before retrying. Never assume a
password was changed on the website merely because it was saved in Petika.

### Show a signup prompt beside the website field

On an allowed website, unlock Petika and choose **Show signup suggestions on this
page**. Close the popup and focus the website's new-password field. Select
**Create password in Petika**, then unlock in the extension to open the generator.
Save the encrypted login and choose **Fill new password** as described above.

The prompt expires after five minutes or navigation. **Dismiss** removes it until
you enable suggestions again. It never displays a password or asks for your
passphrase on the website. If it cannot open Petika, use the toolbar. Fields must
be visible, marked as new-password, and belong to a same-origin form. Automatic
prompts on every website visit and inline saved-login selection are not included.

### Change servers in a generic package

Choose **Change server**, enter the new HTTPS origin, and select **Use this server**.
Denying Chrome's permission request keeps your previous setting. Accepting it locks
the vault and clears the extension's local login and pending approvals; connect
to the new server with a fresh approval. Revoke the old session under Connected
clients on the old server if you no longer need it. Your old vault stays there.
If Chrome keeps the previous host permission, Petika reports it; review the
extension's site access and reopen the popup.
A deployment-pinned package has no Change server button; ask your administrator
for another build. Revoked Chrome host access must be granted again before connecting.

### Update or remove the extension

For an update, get the new prepared package from your administrator, replace the
contents of the installed folder, and choose **Reload** on `chrome://extensions`.
Reconnect if the session was cleared. Do not mix files from different builds.

To stop access, open **Settings → Connected clients** in the web app and revoke
its CLI session, or use **Disconnect** in the popup. Then choose **Remove** on the
browser's extension page if you want to uninstall it. Removing a website permission
stops subsequent fills by this preview; it does not delete the saved login.

## Preferences and connected clients

In **Settings**, choose the sun for Light, moon for Dark, or display icon for
System. Selecting the active Light/Dark button returns to System. The choice is
saved to your account; System follows each device's OS appearance.

**Automatic lock** controls inactivity locking for the web collection on that
browser. The extension has its own five-minute limit and locks on popup close.
**Connected clients** lists active browser/CLI sessions. Revoke unfamiliar sessions;
revocation blocks new server access but cannot erase data already copied.

## Keep backups and recovery material

For a quick encrypted collection copy, unlock it and use **Import & export →
Download encrypted backup**. Keep the collection passphrase separately. If you use
recipient identities, also retain their encrypted identity backup and its passphrase;
a collection export is not a complete backup of every client identity.

For scheduled off-site copies, ask your administrator for independent storage and
open **Settings → Off-site backups → Add S3 or SSH destination**. Use the guided
fields in the [backup guide](offsite-backups.md). S3/SSH jobs run on the Petika
server. A backup API key is instead for external software that downloads your
currently authorized encrypted collections. It is not an autofill connection key.

Choose **Back up now**, then **Refresh status** until a verified success is shown.
**Download profile** contains destination details, not credentials. Keep that
profile, repository password, provider credentials, repository ID, and recovery
passphrases outside the Petika server. A successful upload is not a substitute for
a restore drill with your administrator.

## Common problems

| What you see | What to do |
| --- | --- |
| Wrong username/password | Use your assigned account; ask the administrator to check that it is active. A collection passphrase cannot sign in. |
| Wrong collection passphrase | Use the passphrase for the selected collection; changing the account password does not reset it. |
| Extension cannot connect | Confirm the package points at your server, the certificate is trusted, and the server includes the client/website APIs. Ask the administrator to check its version. |
| Website not allowed/no matching login | Add the exact HTTPS origin and check the saved login URL, including subdomain and port. |
| Website changed/no unambiguous field | Reopen and unlock on the current page; use web-app copy for unsupported forms. |
| Backup buttons unavailable | The operator must enable the push runtime; also check destination credentials and running-job state. |
| Sync conflict | Download your encrypted pending changes before loading the server version. Do not discard your only copy. |
| Certificate or insecure-origin error | Use the administrator-provided HTTPS address and resolve certificate trust; do not disable browser security. |
