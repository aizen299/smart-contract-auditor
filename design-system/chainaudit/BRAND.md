# ChainAudit — brand

Companion to `MASTER.md`, which owns colour, type and spacing. This file owns
identity and language.

## Positioning

**Every finding traces back to a rule.**

ChainAudit is not a black box that emits a score. It names the rule that
fired, shows the CVSS factors behind the number, and prints the fix. That
claim is the whole brand — it decides the logo, the copy, and what the
landing page is allowed to say.

## Mark

A hexagonal block held in square brackets: `[⬡]`. Brackets read as code, the
hexagon reads as a block on chain. Implemented in
`frontend/components/brand/Logo.tsx`, monoline, `currentColor`.

Three alternatives were drawn and compared at 24/32/56px before this was
chosen:

| Candidate | Why it lost |
|---|---|
| Hexagon + checkmark | The standard "verified" badge. Says security product and nothing more — the same problem as the stock ShieldCheck it replaced. |
| Block + scanline | Reads as a hamburger menu inside a hexagon. |
| Block + waveform | Reads as a heart-rate monitor; health monitoring, not security. |

**Rules.** Minimum 16px for the mark alone, 120px for the full lockup. Clear
space equal to the mark's height. Never re-colour it per severity — the mark
is always `--primary` or `currentColor`; severity colour belongs to findings,
and tinting the logo red would read as the product being broken.

## Voice

Three traits, each with the failure mode it guards against.

| Trait | Means | Do | Don't |
|---|---|---|---|
| **Precise** | Name the thing. Numbers are real or absent. | "51 Slither detectors mapped to 30 rules." | "Comprehensive coverage of all major vulnerabilities." |
| **Plain** | Explain the mechanism, not the marketing. | "Ether leaves on line 9 before the balance is written on line 10." | "Advanced AI-powered threat intelligence." |
| **Level** | State severity without theatre. | "This vault compiles, passes its tests, and loses every deposit." | "CATASTROPHIC! Your funds are NOT SAFU!" |

### Tone by context

| Context | Shift |
|---|---|
| Findings | Flat and factual. The severity label carries the alarm; the prose should not add any. |
| Empty states | Helpful, forward-pointing. "No scans yet" then a way to start. |
| Errors | Say what failed and what to do. Never blame the user. |
| Landing | Confident, concrete, evidence-first. Show the vulnerable contract rather than claiming to find vulnerabilities. |

### Specifics

- Sentence case for headings and buttons. Not Title Case, not ALL CAPS —
  except the uppercase micro-labels, which are a typographic device and stay
  short.
- Say "finding", not "issue", "alert" or "threat". The backend says finding.
- Say "contract" for Solidity, "program" for Solana. Getting this wrong marks
  you as an outsider to the audience.
- Never claim the scan is exhaustive. It is static analysis; it finds what
  its rules describe. Overclaiming is both dishonest and, for a security
  product, dangerous.
- Numbers in copy must be traceable to the backend. Every figure on the
  landing page names its source file in a comment.
