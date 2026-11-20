---
name: Obsidian Kinetic
colors:
  surface: '#0f131c'
  surface-dim: '#0f131c'
  surface-bright: '#353942'
  surface-container-lowest: '#0a0e16'
  surface-container-low: '#181c24'
  surface-container: '#1c2028'
  surface-container-high: '#262a33'
  surface-container-highest: '#31353e'
  on-surface: '#dfe2ee'
  on-surface-variant: '#bbcabf'
  inverse-surface: '#dfe2ee'
  inverse-on-surface: '#2c3039'
  outline: '#86948a'
  outline-variant: '#3c4a42'
  surface-tint: '#4edea3'
  primary: '#4edea3'
  on-primary: '#003824'
  primary-container: '#10b981'
  on-primary-container: '#00422b'
  inverse-primary: '#006c49'
  secondary: '#4cd7f6'
  on-secondary: '#003640'
  secondary-container: '#03b5d3'
  on-secondary-container: '#00424e'
  tertiary: '#ffb95f'
  on-tertiary: '#472a00'
  tertiary-container: '#e29100'
  on-tertiary-container: '#523200'
  error: '#ffb4ab'
  on-error: '#690005'
  error-container: '#93000a'
  on-error-container: '#ffdad6'
  primary-fixed: '#6ffbbe'
  primary-fixed-dim: '#4edea3'
  on-primary-fixed: '#002113'
  on-primary-fixed-variant: '#005236'
  secondary-fixed: '#acedff'
  secondary-fixed-dim: '#4cd7f6'
  on-secondary-fixed: '#001f26'
  on-secondary-fixed-variant: '#004e5c'
  tertiary-fixed: '#ffddb8'
  tertiary-fixed-dim: '#ffb95f'
  on-tertiary-fixed: '#2a1700'
  on-tertiary-fixed-variant: '#653e00'
  background: '#0f131c'
  on-background: '#dfe2ee'
  surface-variant: '#31353e'
typography:
  headline-xl:
    fontFamily: Space Grotesk
    fontSize: 32px
    fontWeight: '700'
    lineHeight: 38px
    letterSpacing: -0.02em
  headline-lg:
    fontFamily: Space Grotesk
    fontSize: 24px
    fontWeight: '600'
    lineHeight: 30px
    letterSpacing: -0.015em
  headline-md:
    fontFamily: Space Grotesk
    fontSize: 18px
    fontWeight: '600'
    lineHeight: 24px
    letterSpacing: -0.01em
  headline-sm:
    fontFamily: Space Grotesk
    fontSize: 15px
    fontWeight: '600'
    lineHeight: 20px
  body-lg:
    fontFamily: Inter
    fontSize: 14px
    fontWeight: '400'
    lineHeight: 22px
  body-md:
    fontFamily: Inter
    fontSize: 13px
    fontWeight: '400'
    lineHeight: 18px
  body-sm:
    fontFamily: Inter
    fontSize: 12px
    fontWeight: '400'
    lineHeight: 16px
  code-lg:
    fontFamily: JetBrains Mono
    fontSize: 13px
    fontWeight: '500'
    lineHeight: 18px
  code-md:
    fontFamily: JetBrains Mono
    fontSize: 12px
    fontWeight: '400'
    lineHeight: 16px
  code-sm:
    fontFamily: JetBrains Mono
    fontSize: 11px
    fontWeight: '400'
    lineHeight: 14px
  label-md:
    fontFamily: JetBrains Mono
    fontSize: 11px
    fontWeight: '600'
    lineHeight: 14px
    letterSpacing: 0.06em
  label-sm:
    fontFamily: JetBrains Mono
    fontSize: 10px
    fontWeight: '500'
    lineHeight: 12px
    letterSpacing: 0.08em
rounded:
  sm: 0.125rem
  DEFAULT: 0.25rem
  md: 0.375rem
  lg: 0.5rem
  xl: 0.75rem
  full: 9999px
spacing:
  gutter: 0.75rem
  gutter-lg: 1rem
  margin: 1rem
  margin-mobile: 0.75rem
  space-xs: 0.25rem
  space-sm: 0.375rem
  space-md: 0.5rem
  space-lg: 0.75rem
  space-xl: 1rem
  space-2xl: 1.5rem
---

## Brand & Style

This design system embodies high-stakes operational defense, cryptographic rigor, and deterministic precision. Built for elite offensive security engineers, Red Teams, and SecOps commanders executing synchronized operations, it trades decorative ornamentation for absolute signal-to-noise clarity, rapid cognitive processing, and mission certainty.

The aesthetic fuses **Precision Engineering** with **Technical Minimalism**:
- **Tactical Utility:** Dense, compact arrangements that optimize screen real estate for complex multi-pane workspaces, target trees, and continuous event telemetry.
- **Controlled Luminescence:** A layered dark environment where color is strictly semantic—reserved for validation tiers, severity states, telemetry rates, and lethal execution signals.
- **Architectural Rigor:** Sharp delineation, structured 1px framing, low-contrast structural grids, and monospaced data anchors that invoke military-grade console hardware.
- **Uncompromising Determinism:** State changes, terminal buffers, and inspection surfaces behave predictably with instant transitions, zero layout shifts, and absolute type hierarchy.

## Colors

The palette leverages a deep obsidian hierarchy to simulate physical command hardware, establishing a high-density backdrop where operational telemetry stands out with zero optical fatigue.

### Color Hierarchy & Roles
- **Primary (`#10B981` — Cyber Emerald):** Operational safety, verified targets within legal scope, authenticated nodes, passed exploits, and confirmed operational boundaries.
- **Secondary (`#06B6D4` — Cyber Teal):** Active network scanners, data streams, dynamic telemetry, routing links, interactive utility triggers, and telemetry graphs.
- **Tertiary (`#F59E0B` — Tactical Amber):** Candidate findings, unvalidated scope deviations, warnings, human-in-the-loop review queues, and unstable payloads.
- **Critical Severity (`#EF4444` — Tactical Crimson):** Confirmed vulnerabilities (RCE, SQLi, SSRF), operational breaches, out-of-bounds alerts, and abort commands.
- **Neutral Core (`#0B0F17` — Deep Obsidian):** Root canvas ground.
  - Surface Tier 1 (`#111827` — Deep Charcoal): Structural sidebars, rail panels, and bottom dock drawers.
  - Surface Tier 2 (`#1E293B` — Slate Matrix): Cards, modal layers, terminal envelopes, and inspection cells.
  - Borders & Dividers (`#334155` / `rgba(255,255,255,0.08)`): Hairline structural separators.
  - Text Primary (`#F8FAFC`): Absolute legibility for code payloads and telemetry parameters.
  - Text Muted (`#94A3B8`): Contextual headers, metadata keys, and secondary descriptors.

## Typography

The typographic architecture balances technical authority, compact scanning, and zero character ambiguity:
- **Headlines (Space Grotesk):** Provides structured geometric confidence for module titles, CVE matrices, and panel headers.
- **Body & Controls (Inter):** High x-height and neutral geometry allow dense dashboard grids and nested tree nodes to remain readable under extreme density without distraction.
- **Code, Data & Labels (JetBrains Mono):** Dedicated to technical artifacts: raw payloads, regex targets, cURL strings, IP/CIDR notations, hash digests, and status badges. Features distinctive glyph shaping to avoid confusion between `0` / `O` and `1` / `l` / `I`.
- **All-Caps Metrics:** Small status tags and data labels (`label-md`, `label-sm`) default to uppercase with extended letter spacing (`0.06em` to `0.08em`) to establish visual contrast against prose.

## Layout & Spacing

The command center uses a strict, low-overhead fluid grid with fixed utility rails:
- **Spatial Logic:** A base 4px spatial rhythm tuned down for maximum information density. Standard margins are compact (`1rem` / 16px), and panel gutters maintain tight adjacency (`0.75rem` / 12px) to maximize horizontal data span.
- **Desktop Architecture (1440px+):** 
  - Primary persistent left rail: 56px (collapsed) to 220px (expanded) for operational phase switching.
  - Multi-pane workspace: 3-column split layout (Scope Tree: 280px fixed; Attack Surface / Finding Matrix: dynamic flex; Target Detail / Raw Inspector: 440px fixed or collapsible drawer).
- **Reflow Rules:**
  - **Tablet (768px - 1024px):** Target Detail moves to a floating bottom drawer; secondary panels stack into tabs.
  - **Mobile (< 768px):** Collapses to single-pane task focus with bottom-docked command navigation. Grid margins drop to `0.75rem`.

## Elevation & Depth

This system intentionally eliminates soft, diffuse consumer dropshadows. Depth is articulated purely through tonal luminance tiers and precise 1px perimeter framing.

- **Level 0 (Canvas Base — `#0B0F17`):** Non-interactive foundation and grid background.
- **Level 1 (Docked Surfaces — `#111827`):** Structural sidebars, top status HUD, and terminal split panes. Separated by `1px solid rgba(255, 255, 255, 0.07)`.
- **Level 2 (Containers & Cards — `#1E293B`):** Data tables, finding summaries, target nodes, and payload editors. Outlined with `1px solid rgba(255, 255, 255, 0.12)`.
- **Level 3 (Interactive Hover & Flyouts — `#27354A`):** Popover inspectors, command palettes, and context menus. Paired with a concentrated tactical shadow: `0 4px 12px rgba(0, 0, 0, 0.65), 0 0 0 1px rgba(6, 182, 212, 0.25)`.
- **Semantic Backglow:** High-threat cards and critical alert states utilize subtle localized glow accents (`box-shadow: 0 0 12px rgba(239, 68, 68, 0.15)`) to direct immediate visual triage without obstructing neighboring data.

## Shapes

The design system enforces a sharp, engineered geometry (`roundedness: 1`):
- **Base Elements (Buttons, Inputs, Badges, Tabs):** 4px (`0.25rem`) border radius, evoking precision-cut instrumentation panels.
- **Card Containers & Panels (`rounded-lg`):** 8px (`0.5rem`) border radius for modular workspace units.
- **Dialogs & Overlays (`rounded-xl`):** 12px (`0.75rem`) border radius maximum.
- **Zero Pill Shapes:** Circular pills are prohibited; all tags, status flags, and metric badges maintain crisp 4px corners to avoid consumer-app associations and preserve tabular horizontal rhythm.

## Components

### Buttons
- **Primary Tactical:** Solid Emerald background (`#10B981`), charcoal-black text (`#0B0F17`), weight 600, height 32px, padding 0 12px. Hover: `#059669`. Active: `#047857`. Focus: 2px offset ring in `#10B981`.
- **Secondary / Ghost Utility:** Transparent background, 1px border `#334155`, text `#F8FAFC`. Hover: `#1E293B` background, border `#06B6D4`.
- **Destructive / Abort Action:** High-saturation Crimson fill (`#EF4444`) or 1px Crimson border with semi-transparent tint (`rgba(239, 68, 68, 0.12)`). Used for attack cancel, payload detonate, or credential purge.

### Chips & Badges
- Strict monospaced typography (`label-sm`).
- **In-Scope / Verified:** Tinted background `rgba(16, 185, 129, 0.12)`, border `1px solid rgba(16, 185, 129, 0.3)`, text `#10B981`.
- **Review Needed / Ambiguous:** Background `rgba(245, 158, 11, 0.12)`, border `1px solid rgba(245, 158, 11, 0.3)`, text `#F59E0B`.
- **Critical / Exploit Available:** Background `rgba(239, 68, 68, 0.14)`, border `1px solid rgba(239, 68, 68, 0.4)`, text `#F87171`. Includes a pulsing 4px indicator pip.

### Inputs & Terminal Fields
- Background `#0B0F17`, border `1px solid #334155`, text `#F8FAFC`, placeholder `#64748B`. Height 32px.
- Focus: Border shifts instantly to Cyber Teal (`#06B6D4`) with zero transition lag; no blurry glow.
- Monospace variant for payload inputs, target regex, CIDR filters, and auth tokens.

### Data Tables & Tree Grids
- Ultra-dense row height: 32px default, 28px condensed.
- Row zebra striping omitted in favor of thin border separators (`1px solid rgba(255, 255, 255, 0.05)`). Hover state: row tint `#1E293B`.
- Headers: JetBrains Mono `label-sm`, all-caps, text `#94A3B8`, background `#111827`.

### Code Blocks & Raw Inspection Panes
- Background `#080C14` with a persistent top metadata banner (displaying syntax mode, byte size, and copy button).
- Monospace font (`code-sm` / 11px), 16px line height. Active execution lines highlighted with `rgba(6, 182, 212, 0.1)`.
- Distinct syntax tokens: Methods (GET/POST) color-coded, query params in `#06B6D4`, injection payloads in `#F59E0B` or `#EF4444`.

### Specialized Domain Components
- **Scope Verification Banner:** Dual-state header lock indicating operational mandate, legal authorization timeframe, and IP range constraints.
- **CVE / Finding Severity Pill:** Compact micro-indicator displaying CVSS base score alongside metric vectors (`AV:N/AC:L/PR:N`).
- **Telemetry Pulse Indicator:** Constant 6px radar dot in teal/emerald indicating active agent heartbeat and live proxy socket health.