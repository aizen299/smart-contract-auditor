# Design System Master File

> **LOGIC:** When building a specific page, first check `design-system/pages/[page-name].md`.
> If that file exists, its rules **override** this Master file.
> If not, strictly follow the rules below.

---

**Project:** ChainAudit
**Generated:** 2026-08-22 21:46:53
**Category:** Developer Tool / IDE
**Design Dials:** Variance 4/10 (Balanced / Modern) | Motion 4/10 (Standard) | Density 7/10 (Standard)

---

## Global Rules

### Color Palette

| Role | Hex | CSS Variable |
|------|-----|--------------|
| Primary | `#1E293B` | `--color-primary` |
| On Primary | `#FFFFFF` | `--color-on-primary` |
| Secondary | `#334155` | `--color-secondary` |
| On Secondary | `#FFFFFF` | `--color-on-secondary` |
| Accent/CTA | `#22C55E` | `--color-accent` |
| On Accent/CTA | `#0F172A` | `--color-on-accent` |
| Background | `#0F172A` | `--color-background` |
| Foreground | `#F8FAFC` | `--color-foreground` |
| Card | `#1B2336` | `--color-card` |
| Card Foreground | `#F8FAFC` | `--color-card-foreground` |
| Muted | `#272F42` | `--color-muted` |
| Muted Foreground | `#94A3B8` | `--color-muted-foreground` |
| Border | `#475569` | `--color-border` |
| Destructive | `#EF4444` | `--color-destructive` |
| On Destructive | `#000000` | `--color-on-destructive` |
| Ring | `#FFFFFF` | `--color-ring` |

**Color Notes:** Code dark + run green

### Typography

- **Heading Font:** JetBrains Mono
- **Body Font:** IBM Plex Sans
- **Mood:** code, developer, technical, precise, functional, hacker
- **Google Fonts:** [JetBrains Mono + IBM Plex Sans](https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500;600;700&display=swap)

**CSS Import:**
```css
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500;600;700&display=swap');
```

### Spacing Variables

*Density: 7/10 — Standard*

| Token | Value | Usage |
|-------|-------|-------|
| `--space-xs` | `4px` / `0.25rem` | Tight gaps |
| `--space-sm` | `8px` / `0.5rem` | Icon gaps, inline spacing |
| `--space-md` | `16px` / `1rem` | Standard padding |
| `--space-lg` | `24px` / `1.5rem` | Section padding |
| `--space-xl` | `32px` / `2rem` | Large gaps |
| `--space-2xl` | `48px` / `3rem` | Section margins |
| `--space-3xl` | `64px` / `4rem` | Hero padding |

### Shadow Depths

| Level | Value | Usage |
|-------|-------|-------|
| `--shadow-sm` | `0 1px 2px rgba(0,0,0,0.05)` | Subtle lift |
| `--shadow-md` | `0 4px 6px rgba(0,0,0,0.1)` | Cards, buttons |
| `--shadow-lg` | `0 10px 15px rgba(0,0,0,0.1)` | Modals, dropdowns |
| `--shadow-xl` | `0 20px 25px rgba(0,0,0,0.15)` | Hero images, featured cards |

---

## Component Specs

### Buttons

```css
/* Primary Button */
.btn-primary {
  background: #22C55E;
  color: white;
  padding: 12px 24px;
  border-radius: 8px;
  font-weight: 600;
  transition: all 200ms ease;
  cursor: pointer;
}

.btn-primary:hover {
  opacity: 0.9;
  transform: translateY(-1px);
}

/* Secondary Button */
.btn-secondary {
  background: transparent;
  color: #1E293B;
  border: 2px solid #1E293B;
  padding: 12px 24px;
  border-radius: 8px;
  font-weight: 600;
  transition: all 200ms ease;
  cursor: pointer;
}
```

### Cards

```css
.card {
  background: #0F172A;
  border-radius: 12px;
  padding: 24px;
  box-shadow: var(--shadow-md);
  transition: all 200ms ease;
  cursor: pointer;
}

.card:hover {
  box-shadow: var(--shadow-lg);
  transform: translateY(-2px);
}
```

### Inputs

```css
.input {
  padding: 12px 16px;
  border: 1px solid #E2E8F0;
  border-radius: 8px;
  font-size: 16px;
  transition: border-color 200ms ease;
}

.input:focus {
  border-color: #1E293B;
  outline: none;
  box-shadow: 0 0 0 3px #1E293B20;
}
```

### Modals

```css
.modal-overlay {
  background: rgba(0, 0, 0, 0.5);
  backdrop-filter: blur(4px);
}

.modal {
  background: white;
  border-radius: 16px;
  padding: 32px;
  box-shadow: var(--shadow-xl);
  max-width: 500px;
  width: 90%;
}
```

---

## Style Guidelines

**Style:** Dark Mode (OLED)

**Keywords:** Dark theme, low light, high contrast, deep black, midnight blue, eye-friendly, OLED, night mode, power efficient

**Best For:** Night-mode apps, coding platforms, entertainment, eye-strain prevention, OLED devices, low-light

**Key Effects:** Minimal glow (text-shadow: 0 0 10px), dark-to-light transitions, low white emission, high readability, visible focus

### Page Pattern

**Pattern Name:** FAQ/Documentation Landing

- **Conversion Strategy:** Reduce support tickets. Track search analytics. Show related articles. Contact escalation path.
- **CTA Placement:** Search bar prominent + Contact CTA for unresolved questions
- **Section Order:** Hero with search bar > Popular categories > FAQ accordion > Contact/support CTA

---

## Motion

**Stagger List** (Standard) — Trigger: load or scroll | Duration: 300-450ms | Easing: `back.out(1.4)`

```js
gsap.from('.grid-item', { opacity: 0, scale: 0.92, y: 16, duration: 0.4, stagger: { each: 0.06, from: 'start', grid: 'auto' }, ease: 'back.out(1.4)' });
```

**Framework notes:** grid: 'auto' lets GSAP infer rows/columns from a CSS grid layout for a natural wave stagger; Use matchMedia('(prefers-reduced-motion: reduce)') to skip non-essential motion and render the final state immediately

- ✅ Combine with from: 'center' for a bento-grid layout to draw the eye inward first
- ❌ Don't use back.out on dense data tables; the overshoot reads as sloppy on informational UI
- ⚡ Group DOM writes; avoid interleaving layout reads (getBoundingClientRect) between staggered tweens

---

## Anti-Patterns (Do NOT Use)

- ❌ Light mode default
- ❌ Slow performance

### Additional Forbidden Patterns

- ❌ **Emojis as icons** — Use SVG icons (Heroicons, Lucide, Simple Icons)
- ❌ **Missing cursor:pointer** — All clickable elements must have cursor:pointer
- ❌ **Layout-shifting hovers** — Avoid scale transforms that shift layout
- ❌ **Low contrast text** — Maintain 4.5:1 minimum contrast ratio
- ❌ **Instant state changes** — Always use transitions (150-300ms)
- ❌ **Invisible focus states** — Focus states must be visible for a11y

---

## Pre-Delivery Checklist

Before delivering any UI code, verify:

- [ ] No emojis used as icons (use SVG instead)
- [ ] All icons from consistent icon set (Heroicons/Lucide)
- [ ] `cursor-pointer` on all clickable elements
- [ ] Hover states with smooth transitions (150-300ms)
- [ ] Light mode: text contrast 4.5:1 minimum
- [ ] Focus states visible for keyboard navigation
- [ ] `prefers-reduced-motion` respected
- [ ] Responsive: 375px, 768px, 1024px, 1440px
- [ ] No content hidden behind fixed navbars
- [ ] No horizontal scroll on mobile

---

## As built — decisions that override the generated defaults

Recorded 2026-08-22, branch `frontend-brand-refresh`. Where this section and
the generated content above disagree, this section wins: it reflects what is
actually implemented and verified in `frontend/`.

### Corrections to the generated output

- **Pattern.** The generator returned *FAQ/Documentation Landing*. That is a
  query artifact and was discarded — ChainAudit is an upload → scan → report
  tool, not a docs site.
- **Background.** Uses `#020617` (the *API Developer Portal* row) rather than
  the *Developer Tool / IDE* row's `#0F172A`. The deeper base preserves the
  near-black identity the product already had and leaves room for two distinct
  elevation steps above it.

### Source of truth

| Concern | File | Notes |
|---|---|---|
| Colour, type, radius, motion tokens | `frontend/app/globals.css` | Three layers: primitive → semantic → component |
| Tailwind mapping | `frontend/tailwind.config.ts` | `hsl(var(--x) / <alpha-value>)` so opacity modifiers work |
| Severity + risk banding | `frontend/lib/severity.ts` | Replaced 13 scattered definitions |
| Chain display | `frontend/lib/chains.ts` | Replaced 5 scattered definitions |

### Rules that are load-bearing

1. **Green means MINIMAL, never LOW.** Low severity is blue. Banding follows
   `_risk_label` in `backend/src/chainaudit/cli.py`, which is authoritative and
   has five bands (the web UI previously had two components using four, so a
   score of 15 read "Low Risk" on one screen and "Minimal" on another).
2. **Mono is for machine text only** — code, addresses, hashes, scores, the
   wordmark. Prose is IBM Plex Sans. The old build set Courier New on `body`,
   which is what made the app read as a toy.
3. **Every text token clears WCAG AA on `--background`.**
   `--subtle-foreground` at 5.3:1 is the deliberate floor. The old build used
   `white/25` and `white/40`, which measure 2.1:1 and 3.7:1.
4. **Both severity and chain modules expose hex as well as classes.** The
   exported audit report is a standalone HTML document with no stylesheet, so
   it cannot read CSS variables. Keep both representations in one table —
   splitting them is exactly how the previous copies drifted.
5. **Interpolated Tailwind class names need the `safelist`.** `severityClasses()`
   builds names by interpolation, which the JIT scanner cannot see.

### Verified

`npx tsc --noEmit` clean · 32/32 tests pass · `npm run build` succeeds ·
0 contrast failures on `/`, minimum ratio 4.89:1 · no sub-12px text ·
no horizontal scroll at 375px.

### Consolidations

Five domain concepts were each defined many times over and had drifted into
user-visible bugs. All are now single-source:

| Concept | Was | Now | Bug it had caused |
|---|---|---|---|
| Severity + risk banding | 14 definitions | `lib/severity.ts` | A score of 15 read "Low Risk" on results and "Minimal" in history |
| Chain display | 6 definitions | `lib/chains.ts` | Arbitrum and Base rendered in each other's colours |

The fourteenth severity copy was `MLBadge`'s local `colorMap`, hidden inside a
function rather than at module scope — worth knowing that grepping for
top-level `const SEVERITY_*` does not find them all.

### Accessibility fixes worth remembering

- **The dropzone was keyboard-dead.** A `div` with `onClick`, no `role`, no
  `tabindex`, and no button inside — so the app's primary function could not
  be reached without a mouse. Now `role="button"`, focusable, Enter/Space
  activated, with the file input removed from the tab order.
- **History rows were `div onClick`** and the delete control was `opacity-0`
  until hover, i.e. invisible and unreachable by keyboard, and it deleted
  permanently on one click. Rows are buttons; delete is always focusable and
  goes through an AlertDialog.
- **Disclosure buttons lacked `aria-expanded`** — the rotating chevron was the
  only signal a collapse existed.
- A failed history fetch used to render as an empty list, which reads as "you
  have no scans" rather than "this did not load".

### Not yet done

`prefers-reduced-motion` is honoured globally in CSS and explicitly in
`RiskScore`, but the framer-motion entrance animations elsewhere still run —
they are opacity/transform only, so they degrade acceptably, but a
`useReducedMotion()` pass would be more correct.
