# Web UI design direction

Petika is a private workspace for personal and group secrets. The chest identity,
navy ink, and teal accent anchor it in safekeeping rather than generic analytics.

Palette: ink #102B3F, teal #087F78, mist #F3F7F7, white #FFFFFF, slate #526778,
night #111E29. Shared CSS custom properties control every component. System appearance
is the default; light and dark overrides are remembered locally. Use the native system
sans-serif at a deliberate 12/14/16/20/28/40 scale; monospace only for secrets and codes.

Layout: left-aligned navigation, searchable item list, and a focused detail pane.
The setup screen uses the chest mark as its single expressive element. Administration
uses readable tables and explicit permission labels; no invented security scores.

```
Navigation | Collection title + search + new item
           | Item list         | Selected item + password + OTP
           |                   | Notes and website actions
Profile    | Connection / save state
```

Review: avoid dashboard statistic tiles, decoration-only gradients, and fake activity.
Use generous detail spacing and tighter list density. A password tool should feel calm,
quick, and predictable. Theme contrast, keyboard focus, small-screen reflow, empty/error
states, and reduced motion are part of the shared system.

Research (2026-10-11):
- [Linear's 2026 design refresh](https://linear.app/now/behind-the-latest-design-refresh):
  quiet navigation, predictable controls, and visual hierarchy.
- [1Password's concept-first design](https://1password.com/blog/concept-first-design):
  organize around user concepts and clear actions.
- [1Password browser filling](https://support.1password.com/save-fill-passwords/):
  website-bound suggestions and explicit filling through a browser extension.
- [1Password groups](https://support.1password.com/groups/) and
  [permissions](https://support.1password.com/permission-enforcement/): separate
  administration from access to items; enforce access on the server.
- [WCAG 2.2](https://www.w3.org/TR/WCAG22/): keyboard access, focus, contrast, and reflow.

These are design references, not a claim that Petika or a particular reference is
objectively the highest-rated UI. No third-party layouts or artwork are copied.

## Contrast revision

The interface uses a dedicated ice-white/mint mark for dark mode and navy/deeper teal
for light mode. No CSS inversion or white badge is applied to the dark sidebar logo.
Target palette contrast: ink/white 14.59:1, light-mode teal/white 4.86:1,
ice/dark-sidebar 15.05:1, mint/dark-sidebar 10.39:1, muted-dark text/panel 7.21:1.
Form control boundaries use a separate stronger token (3.22:1 against white), while
structural separators remain quiet. These are color-pair checks, not a full WCAG audit.
