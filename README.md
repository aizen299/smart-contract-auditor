# ChainAudit

Production-grade smart contract security scanner. Upload a Solidity file or zip, get a real-time audit report with risk scores, ML exploitability predictions, and L2/Arbitrum/Optimism-aware findings.


[![PyPI](https://img.shields.io/pypi/v/chainaudit)](https://pypi.org/project/chainaudit/)
[![CI](https://github.com/aizen299/smart-contract-auditor/actions/workflows/ci.yml/badge.svg)](https://github.com/aizen299/smart-contract-auditor/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

---

## Install

### Mac / Linux / Ubuntu

```bash
pip install chainaudit
pip install slither-analyzer
pip install solc-select
solc-select install 0.8.24
solc-select use 0.8.24
```

### Windows

> Requires Python 3.12. Download from [python.org](https://www.python.org/downloads/release/python-3128/) — check "Add Python to PATH" during install. Python 3.13 not yet supported on Windows.

```powershell
pip install chainaudit
pip install slither-analyzer
pip install solc-select
solc-select install 0.8.24
solc-select use 0.8.24
```

> If on a college/office network, use mobile hotspot for installation.

---

## Stack

| | |
|---|---|
| Frontend | Next.js 14, TypeScript, Tailwind CSS |
| Backend | FastAPI, Python 3.11 |
| Analysis | Slither, solc-select, CVSS-inspired scoring |
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
chainaudit scan contract.sol               # single file
chainaudit scan ./contracts --recursive    # directory
chainaudit scan contracts.zip              # zip archive
chainaudit scan contract.sol --json        # JSON output
chainaudit scan contract.sol --ml-only     # skip simulation
chainaudit --version                       # show version
```

Exit code `1` on CRITICAL findings — blocks deployments in CI.

---

## Local Development

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

**`frontend/.env.local`**
```
NEXT_PUBLIC_SUPABASE_URL=your_supabase_url
NEXT_PUBLIC_SUPABASE_ANON_KEY=your_supabase_anon_key
NEXT_PUBLIC_API_URL=http://localhost:8000
```

**Docker**
```bash
cp docker-compose.example.yml docker-compose.yml
docker compose up --build
```

---

## API

`POST /scan` — single `.sol` file
`POST /scan/zip` — multiple contracts (max 20 files, 5MB)

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
    }
  ]
}
```

---

## Vulnerability Coverage

**EVM (all chains) — 16 rules**

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

---

## ML Pipeline

Trained on SmartBugs dataset (143 contracts, 10 vulnerability classes). Random Forest classifier predicts exploitability per finding with a confidence score. 88% accuracy overall — 95% precision on HIGH, 93% on CRITICAL.

---

## Deployment

| | Platform | URL |
|--|---------|-----|
| Frontend | Vercel | chainaudit.vercel.app |
| Backend | Render | smart-contract-auditor-812q.onrender.com |
| Uptime | UptimeRobot | `/health` pinged every 5 min |

---

## Roadmap

- [x] 16 EVM vulnerability rules + CVSS scoring
- [x] 12 L2/Arbitrum/Optimism rules with auto-detection
- [x] ML exploitability prediction
- [x] Multi-contract zip scanning
- [x] Supabase auth + scan history
- [x] CLI tool — `chainaudit scan`
- [x] PyPI — `pip install chainaudit`
- [x] GitHub Marketplace Action
- [x] Docker, Vercel + Render, CI/CD
- [ ] Solana / Rust support
- [ ] Monetize — free/pro tiers, Stripe billing
- [ ] API keys for enterprise