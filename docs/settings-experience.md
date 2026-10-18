# Simple security configuration

Date: 2026-10-18. Product requirement for all new security configuration.

## Design contract

Use one shared stylesheet, `clients/web/app.css`, with the existing navy/teal palette,
system font stack, light/dark tokens and shared form controls. No CSS framework,
per-feature stylesheet, inline style attributes or remotely loaded fonts. JavaScript
controls behavior and state; CSS controls presentation and responsive layout.

Keep Settings task-based: vault protection, recovery/sharing, backups, account access,
then profile and preferences. Show the affected collection or user scope beside the
action. Full-server settings are operator-only and must be clearly separated from
personal backups. A role label is not a substitute for server-side authorization.

Every setting needs a sensible default, plain-language purpose, current status and
one obvious next action. Put algorithm/provider/certificate details in an expandable
advanced section. Do not ask users to choose nonces, KDF parameters or raw KEM suites.
A future protection profile must bundle reviewed compatible choices and explain its
platform/recovery implications before changing anything.

Unavailable features have no working-looking switches. Keep research status in the
advanced section until there is a usable setup flow. Never display a FIPS badge based
on a feature flag or a biometric badge based only on device capability.

## Appearance

Use three compact icon buttons: Light (sun), Dark (moon), and System (display).
Selecting an active Light or Dark button returns to System. Buttons expose their
selected state with `aria-pressed`, accessible names, tooltips, and visible focus.
The authenticated `POST /v1/appearance` endpoint accepts `appearance` as `light`,
`dark`, or `system` and updates only the session user. The account preference is
restored on sign-in and reload across devices; System follows each device’s OS.
Existing accounts default to System. Signed-out appearance remains browser-local
and does not overwrite an account preference. Failed saves restore the prior choice.

## Future configuration flows

| Task | User-facing flow | Required outcome |
| --- | --- | --- |
| Protect a collection | Recommended supported profile; optional advanced explanation | Preview compatibility and recovery implications; explicit migration, preserved backup and clear completion/failure state |
| Add a device | Name device → verify with trusted device → confirm access | Explain what it can decrypt, actual local protection and how to remove it |
| Enable biometric unlock | Check capability → explain allowed fallback → verify → confirm | Bind verification to key use; show why unsupported devices cannot enable it |
| Set up recovery | Choose method → retain/verify recovery material → confirm scope | Explicitly name recovery holders and warn before removing the last working path |
| S3/SSH backup | Choose provider → destination fields → credentials → schedule → verify | Show only relevant provider fields; separate save, connection success, backup success and restore verification |
| API pull backup | Name external client → expiry → generate → copy once | Clear download-only scope, expiry and revoke action; no storage credentials required |

Use ordinary storage labels such as endpoint, bucket and folder where possible;
construct provider-specific repository syntax internally after validation. Preserve
an advanced URL field for compatible configurations. New destinations now use these guided fields. Existing destinations open in advanced
mode to preserve saved URLs exactly; users can explicitly switch to guided fields
to replace the destination. Connection/restore verification improvements remain planned.

Saving an edited destination must explain whether blank credentials preserve existing
secrets. Never echo saved secrets. Errors belong beside the relevant field and must
say what to fix without exposing credentials. Prevent double submission and retain
non-secret input after recoverable errors. Require fresh authentication only where
security policy needs it, with a clear explanation.

## Accessibility and acceptance

- Native labels, buttons, selects and disclosure controls; keyboard-visible focus.
- Responsive at 390px and desktop widths, with no horizontal page scrolling; also
  verify 200% zoom, long names, error messages and light/dark themes before release.
- No color-only status; meaningful accessible names and announced save/error states.
- One action name throughout each flow. Preserve familiar entry points when regrouping.
- Test first setup, return visit, edit, cancellation, unavailable capability and failure.
- User preferences save predictably; cryptographic changes require an explicit action.

## Initial implementation

Settings now groups security actions with explanations, shows collection protection
only when known, and moves technical/research information into a native disclosure.
Existing profile, theme, automatic-lock and dialog actions are retained. This does not
implement the planned setup wizards or new encryption/device/recovery capabilities.

## Password and TOTP browser experience

Reference reviewed 2026-10-18: [1Password password suggestions](https://support.1password.com/save-fill-passwords/),
[TOTP setup and filling](https://support.1password.com/one-time-passwords/),
and [autofill security](https://support.1password.com/browser-autofill-security/).
1Password offers generated passwords in browser fields and supports filling stored
TOTP codes. Its documentation describes website setup/confirmation separately from
saving the authenticator secret, and requires user input for autofill.

Petika now offers a locally generated password in the new-item form. The user must
select “Use suggested password” before it replaces the field, and save the item to
retain it. Existing passwords are never automatically replaced. TOTP setup accepts
a setup key or otpauth URI, encrypted in the login item; the website still needs a
confirmation code to finish enabling MFA. Code generation/copy exists today.

The [Chromium toolbar preview](../clients/extension/README.md) now fills matching
logins and TOTP codes with explicit actions, live permissions/session checks, and
document-bound injection. Its generator saves a separate encrypted login before
explicitly filling new-password fields, preserving the existing login and using
revision guards to reject concurrent writes. It uses the same shared `app.css`.
Inline suggestions, QR capture, broader field support and
other browser platforms remain open. The full target experience remains:
- Offer generated passwords at signup/change-password fields; explicitly save or update the login.
- Capture a TOTP QR code or setup key with consent and confirm on the website.
- Offer “Fill verification code” for the selected matching login, including a multi-step sign-in.
- Generate a fresh code at fill time; avoid filling an almost-expired code.
- Enforce the account’s exact HTTPS origin allowlist, item website match, browser-provided tab/frame origin, unlocked vault, and explicit user action for each fill. Deny by default.
- Recheck navigation immediately before filling; reject hidden fields and cross-origin frames initially. Never auto-submit or send an OTP seed to a webpage.
- Test spoofed origins, revoked clients/permissions, locked vaults, navigation races, split OTP fields, and code expiry before release.

Settings → Connected clients lists active browser/CLI sessions, their issue time,
remaining lifetime and current-session marker. Users can revoke only their own
sessions. These are not hardware-attested devices: device identity and biometric
key custody remain separate future work. Sessions expire after eight hours and are
in-memory; server restart invalidates them. Backup API keys remain separately listed
under Off-site backups. Revocation stops new server requests, not use of copied data.

Browser autofill → Allowed websites stores an account-scoped list of exact HTTPS
origins (including port); there is no wildcard or inherited subdomain permission.
The list is server-readable configuration, not encrypted vault metadata. The Chromium preview checks this list before each fill. The API
reports `enforced: false` because the server cannot enforce browser-side behavior;
a modified client with decrypted vault access can ignore it. Saving a permission
does not install or connect an extension.
