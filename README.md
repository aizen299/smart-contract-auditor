# ChainAudit

Production-grade smart contract security scanner. Upload a Solidity file, Solana Rust program, or zip of multiple contracts. Get a real-time audit report with risk scores, ML exploitability predictions, L2/Arbitrum/Optimism-aware findings, and Solana-specific vulnerability detection.

[![PyPI version](https://img.shields.io/pypi/v/chainaudit.svg)](https://pypi.org/project/chainaudit/)
[![CI](https://github.com/aizen299/smart-contract-auditor/actions/workflows/ci.yml/badge.svg)](https://github.com/aizen299/smart-contract-auditor/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
---

## Install

### Mac / Linux / Ubuntu

```bash
pip install chainaudit slither-analyzer solc-select
solc-select install 0.8.24
solc-select use 0.8.24

# Optional — for Solana/Rust scanning
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
cargo install cargo-audit
```

### Windows

> Requires Python 3.9+
```powershell
pip install chainaudit
pip install slither-analyzer
pip install solc-select
solc-select install 0.8.24
solc-select use 0.8.24
```

---

## Stack

| | |
|---|---|
| Frontend | Next.js 14, TypeScript, Tailwind CSS, shadcn/ui + Radix |
| Backend | FastAPI, Python 3.11 |
| Analysis | Slither, solc-select, CVSS-inspired scoring |
| Solana | cargo-audit, regex pattern scanner |
| ML | Random Forest — 88% accuracy (SmartBugs dataset) |
| Auth | Supabase — email, GitHub, Google OAuth |
| Deploy | Vercel + Render |
| CI/CD | GitHub Actions + GitHub Marketplace Action |

---

## GitHub Action

Use ChainAudit in any CI pipeline:

```yaml
- uses: aizen299/smart-contract-auditor@v1
  with:
    target: contracts/
    fail-on-critical: true
```

Outputs: `risk-score`, `total-findings`, `critical-count`, `high-count`, `report-path`

---

## CLI

```bash
chainaudit scan contract.sol               # Solidity file
chainaudit scan program.rs                 # Solana/Rust program
chainaudit scan ./contracts --recursive    # directory
chainaudit scan contracts.zip              # zip — .sol, .rs, or mixed
chainaudit scan contract.sol --json        # JSON output
chainaudit scan contract.sol --ml-only     # retained; no longer changes behaviour
chainaudit --version                       # show version
```

Exit code `1` on CRITICAL findings — blocks deployments in CI.

**Zip support:**
- `sol_only.zip` — EVM pipeline for all `.sol` files
- `rust_only.zip` — Solana scanner for all `.rs` files
- `mixed.zip` — both pipelines, combined results

---

## Local Development

Requires **Python 3.11** and **Node 22**. The Node version is pinned in
`.nvmrc`, `engines.node`, CI and both Dockerfile stages — if you use nvm,
`nvm use` in the repo root picks it up.

```bash
# Backend
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn api:app --reload

# Frontend
cd frontend
npm install && npm run dev
```

The frontend is built on a three-layer design token system — colour,
typography and severity all resolve through CSS variables in
`app/globals.css`. Severity/risk banding lives in `lib/severity.ts` and chain
display in `lib/chains.ts`; both are single sources of truth, so add new
values there rather than in a component. See `design-system/chainaudit/` for
the palette rationale and accessibility measurements.

**`frontend/.env.local`**
```
NEXT_PUBLIC_SUPABASE_URL=your_supabase_url
NEXT_PUBLIC_SUPABASE_ANON_KEY=your_supabase_anon_key
NEXT_PUBLIC_API_URL=http://localhost:8000
```

**`backend/.env`** — the scan endpoints verify a Supabase access token. With
neither variable below set, `/scan*` returns 503 rather than accepting anonymous
requests.

Projects on **JWT signing keys** (Supabase dashboard → Settings → JWT Keys →
*JWT Signing Keys*, showing an ECC or RSA current key) verify against the
project's public keys. Set the project URL and the JWKS endpoint is derived:
```
SUPABASE_URL=https://your-project-ref.supabase.co
```

Projects still on the **legacy shared secret** (JWT Keys → *Legacy JWT Secret*)
set that instead:
```
SUPABASE_JWT_SECRET=your_legacy_jwt_secret
```

> If the dashboard lists an ECC/RSA key as *current* and HS256 only under
> "previously used keys", use `SUPABASE_URL`. The legacy secret no longer signs
> new tokens, so configuring it would reject every current login. When both are
> set, JWKS wins.

```
# Optional
SUPABASE_JWKS_URL=                    # override the derived JWKS endpoint
CHAINAUDIT_REQUIRE_AUTH=true          # false runs an intentionally open instance
CHAINAUDIT_ALLOWED_ORIGINS=https://chainaudit.vercel.app,http://localhost:3000
CHAINAUDIT_RATE_LIMIT_REQUESTS=10     # per client, per window
CHAINAUDIT_RATE_LIMIT_WINDOW=60       # seconds
```

**Docker**
```bash
cp docker-compose.example.yml docker-compose.yml
docker compose up --build
```

---

## API

All three endpoints require an `Authorization: Bearer <supabase-access-token>` header.

`POST /scan` — single `.sol` file
`POST /scan/rust` — Solana/Rust `.rs` file
`POST /scan/zip` — `.sol`, `.rs`, or mixed zip (max 20 files, 5MB)

```json
{
  "risk_score": 86,
  "total_findings": 6,
  "findings": [
    {
      "title": "Reentrancy",
      "severity": "CRITICAL",
      "ml_exploitability": "CRITICAL",
      "ml_confidence": 0.96,
      "occurrences": 7,
      "chain": "arbitrum",
      "l2_detected": true
    },
    {
      "title": "Missing Signer Check",
      "severity": "CRITICAL",
      "chain": "solana",
      "category": "logic"
    }
  ]
}
```

---

## Vulnerability Coverage

**EVM (all chains) — 18 rules**

| Severity | Rules |
|----------|-------|
| CRITICAL | Reentrancy, Reentrancy with Unlimited Gas, Controlled Delegatecall |
| HIGH | Unchecked Token Transfer, Arbitrary ETH Send, Weak Randomness, tx.origin Auth, Selfdestruct Risk, Access Control, Unchecked Low-level Call |
| MEDIUM | Timestamp Dependence, Unchecked Send, Deprecated Standards |
| LOW | Missing Zero Check, Incorrect Equality, Missing Events, Naming Convention |

**L2 / Arbitrum / Optimism — 12 rules**

| Severity | Rules |
|----------|-------|
| CRITICAL | Cross-Chain Replay Attack, Bridge Reentrancy, Proxy Storage Collision, msg.value Misuse |
| HIGH | L2 Block Number Assumption, L2 Timestamp Assumption, Sequencer Dependence, Address Aliasing, Unvalidated Bridge Sender |
| MEDIUM | Force-Include Griefing, Gas Price Assumption, Optimism Deposit Griefing |

L2 rules are **auto-detected** — the scanner reads contract source for Arbitrum/Optimism identifiers (`ArbSys`, `xDomainMessageSender`, `IL2Bridge` etc.) and injects chain-specific findings automatically.

**Solana / Rust — 22 rules**

| Severity | Rules |
|----------|-------|
| CRITICAL | Missing Signer Check, Arbitrary CPI, Missing Owner Check |
| HIGH | Integer Overflow / Underflow, Unsafe Rust Code, Account Confusion, CPI Reentrancy, Insecure Randomness |
| MEDIUM | Missing Rent Exemption, Unvalidated Account Data, Missing Close Account, PDA Seeds Not Validated |
| LOW | Missing Freeze Authority, Deprecated Anchor Patterns |

Detected via `cargo-audit` (CVE scanning in dependencies) + regex pattern scanning on `.rs` source files. Anchor framework projects auto-detected.

---

## ML Pipeline

Trained on the SmartBugs curated dataset (143 contracts, 10 vulnerability classes). A Random Forest classifier predicts exploitability per finding with a confidence score.

On a held-out 20% split it scores 88% accuracy — 95% precision on HIGH, 93% on CRITICAL. Worth reading with the sample size in mind: 143 contracts is a small, curated corpus of known-vulnerable code, so these figures describe performance on SmartBugs rather than a guarantee about arbitrary production contracts. Treat the score as a triage aid for ranking findings, not as a verdict.

---

## Deployment

| | Platform | URL |
|--|---------|-----|
| Frontend | Vercel | chainaudit.vercel.app |
| Backend | Render | smart-contract-auditor-812q.onrender.com |
| Uptime | UptimeRobot | `/health` pinged every 5 min |

