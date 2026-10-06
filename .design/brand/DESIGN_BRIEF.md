# Design Brief: Deckard identity

## Problem and audience

Infrastructure operators need to recognise the same product in GitHub and the UI.
The old banner used fictional interface labels, slogans and a different wordmark from the application.

## Primary job and success

Create one recognisable logo, usable in the README, application header, sign-in form and favicon.
Success means identical geometry across surfaces, clear small-size rendering and verified theme contrast.

## Surface mode

Experience for the README identity; operate for the application header.
The logo must not compete with navigation or monitoring data.

## Experience principles

1. Identity, not decoration — use a mark and wordmark without a skyline, HUD or slogans.
2. Cinematic, not cosplay — use upright industrial typography and one machined D silhouette.
3. One source — share the outlined SVG between GitHub and the application.

## Content and data

The visible wordmark is `DECKARD` on every surface.
Use `Deckard` in prose, page titles and accessible names.
Use `deckard` only for commands, paths, packages and resource identifiers.
Do not invent status labels or product claims inside the logo.

## Critical interactions and states

Keep navigation, authentication and theme controls unchanged.
The logo is static, not a new navigation action.
The sign-in heading remains accessible and names the product.

## Existing visual truth

Preserve the application's layout, information density, type and semantic status colours.
Replace only the lowercase text brand, README banner and generic favicon.

## Asset inventory

| Asset | Source | Treatment |
| --- | --- | --- |
| Wordmark | Antonio Medium, Vernon Adams, SIL OFL 1.1 | Outline the original glyphs; no runtime font download |
| Monogram | Custom D with rounded shoulder and angled lower return | Check at 16, 24 and 32 pixels |
| Logo | `web/src/assets/deckard-logo.svg` | Canonical shared mark and wordmark |
| Favicon | `web/src/assets/deckard-mark.svg` | Identical mark geometry; test equality |

## Aesthetic direction

Restrained retro-industrial identity, influenced by Blade Runner's typography and machinery rather than its film logo.
An upright condensed wordmark pairs with a substantial asymmetric D.
Use flat charcoal and warm ivory, with a single copper mark.
No gradients, fake scan lines, terminal prefixes, shields, crosshairs or animation.

## Component inventory

| Component | Change | States |
| --- | --- | --- |
| Brand | New shared component | Light, dark, system |
| Header | Replace text with Brand | Desktop, mobile, zoom |
| Sign-in | Add Brand; correct prose casing | Empty, invalid, authentication failure |
| README heading | Canonical logo image | Light and dark GitHub surrounds; missing-image alt |

## Responsive and inclusive behavior

Keep the full wordmark readable at 320 pixels without horizontal scrolling.
Use one accessible product name per SVG and preserve keyboard focus styles.
Test explicit light/dark themes even when the operating system uses the opposite theme.
Use stable outlined glyphs, no motion, and no network-loaded fonts.

## Constraints and non-goals

Keep assets inside `web/` because the container's frontend build copies only that directory.
Do not change scanning, authentication, routes, data, alert colours or dashboard composition.
This does not establish a new global application body font or palette.

## Open questions

None.
