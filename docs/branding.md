# Petika brand

**Your secrets. Your infrastructure.**

Petika's identity connects its small-box name with digital safekeeping. An open
chest with a keyhole represents deliberate access to protected information. The
ascending binary digits represent digital contents becoming available when unlocked.
Use this as a brand metaphor, not an illustration of how encryption works.

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
The dark raster has an ink background matched to the sidebar. The light raster is
transparent. The wordmark is live theme-colored text in the UI, avoiding a navy
wordmark on a dark surface. The original horizontal PNG remains for light-background
print/document use. System theme and explicit appearance overrides switch the marks.
Target dark mark colors: ice `#E7F1F5`, mint `#6EDBC9`, ground `#101C26`.
