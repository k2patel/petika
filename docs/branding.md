# Petika brand

**Your secrets. Your infrastructure.**

Petika's identity connects its small-box name with digital safekeeping. An open
chest with a keyhole represents deliberate access to protected information. The
lotus inlays and geometric borders evoke Indian decorative keepsake boxes. The
ascending binary digits use Devanagari **०** (zero) and **१** (one), connecting the
Indian-inspired box with digital contents becoming available when unlocked.
Use this as a brand metaphor, not an illustration of how encryption works.

## Sponsorship and Android app identity

Petika is sponsored by **Aum Maa Shree LLC**. The Google Play Console app
identity confirmed by the project owner is:

| Field | Value |
| --- | --- |
| App name | Petika |
| Android package name | `com.aummaashree.petika` |
| Console last updated | November 3, 2026 |

Use `com.aummaashree.petika` as the Android `applicationId` when implementing
the native app. The Google Play Console entry is configured; the Android client
and its build configuration are not yet implemented.

## iOS app identity

The project owner chose **Petika Password Manager** as the iOS App Store name
after App Store Connect reported that **Petika** was already in use.

| Field | Value |
| --- | --- |
| App Store name | Petika Password Manager |
| iOS bundle ID | `com.aummaashree.petika` |
| App Store Connect SKU | `petika-ios` |

The project owner confirmed that Apple identifier registration and App Store
Connect app creation are complete. Use this bundle ID when implementing the iOS
app. The iOS client and its build configuration are not yet implemented.

## Mobile development and test builds

Both store registrations are complete, as confirmed by the project owner.
Development and test versions are planned for a later phase. That phase will
configure native projects, signing, development/test identifiers as needed, and
Google Play internal testing and Apple TestFlight distribution. Development/test
identifiers have not yet been chosen; the registered identifiers above are the
production app identities. Store registration does not indicate an uploaded build
or a published app.

## Assets

- [Primary wordmark](../assets/brand/petika-logo.png): transparent horizontal PNG
  for the README, documentation, and website header.
- [Standalone mark](../assets/brand/petika-icon.png): transparent square PNG with
  a shorter binary stream for app artwork and profile images.

These are generated raster masters, not editable vector artwork. Review any small
favicon rendition at its actual display size before shipping it. The icon's detailed
chest is intended for larger placements; a dedicated simplified favicon is still needed.
Assets were created for this project with imagegen and are included under the
repository's MIT license. No trademark clearance is implied.

## Palette

| Role | Color | Hex |
| --- | --- | --- |
| Primary ink | Deep blue | `#102B3F` |
| Accent | Teal | `#138A83` |
| Light canvas | Warm white | `#F7F9F8` |
| Body text | Slate | `#334B59` |

These are the target interface colors; generated image pixels may vary slightly.
Place the navy artwork on white or a very light surface. On dark interfaces, use
the dedicated ice-white/mint dark mark; never place the navy mark directly on dark backgrounds. Never stretch,
rotate, recolor individual letters, or add shadows to the mark. Leave clear space
around the lockup at least as large as the lowercase letter height.

## Typography and voice

Use the native system sans-serif stack for interfaces and system monospace for CLI
examples. The supplied wordmark is artwork, not a font to use for interface text.
Write **Petika** in prose and `petika` in commands and package names.

Be clear, calm, and specific: “Encrypted before sync,” “Hosted by you,” and
“Unlock your store.” Avoid claims such as “unbreakable,” “AI-proof,” or “quantum-proof.”
Describe unfinished features as planned and hybrid encryption as experimental.

## Theme-aware revision

The web UI uses [light artwork](../assets/brand/petika-icon-light.png) in navy and
teal, and [dark artwork](../assets/brand/petika-icon-dark.png) in ice white and mint.
Both theme rasters have transparent backgrounds. The wordmark is live theme-colored text in the UI, avoiding a navy
wordmark on a dark surface. The horizontal PNG uses the same decorated chest for light-background
print/document use. System theme and explicit appearance overrides switch the marks.
Target dark mark colors: ice `#E7F1F5`, teal-mint `#31B5A4`, interior `#101C26`.
