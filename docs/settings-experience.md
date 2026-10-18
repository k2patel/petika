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
an advanced URL field for compatible configurations. This backup-form improvement
is planned, not part of the initial Settings grouping change.

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
