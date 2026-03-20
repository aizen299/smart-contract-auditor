# ChainAudit — Smart Contract Security Platform

A full-stack smart contract auditing platform. Upload a Solidity file or a zip of multiple contracts, get a real-time security report with risk scores, severity-ranked findings, ML exploitability predictions, and actionable fixes — powered by Slither static analysis.

**Live → [chainaudit.vercel.app](https://chainaudit.vercel.app)**

---

## Stack

| | |
|---|---|
| Frontend | Next.js 14, TypeScript, Tailwind CSS |
| Backend | FastAPI, Python 3.11 |
| Analysis | Slither, solc-select, CVSS-inspired scoring |
| ML | Random Forest (SmartBugs dataset, 88% accuracy) |
| Simulation | Foundry (forge) |
| Auth | Supabase — email, GitHub, Google OAuth |
| Deploy | Vercel (frontend) + Render (backend) |
| Monitoring | UptimeRobot |
| CI/CD | GitHub Actions |

---

## Deployment

| Service | Platform | URL |
|---------|----------|-----|
| Frontend | Vercel | chainaudit.vercel.app |
| Backend | Render | smart-contract-auditor-812q.onrender.com |

Both services auto-deploy on every push to `main`. GitHub Actions runs a type check and full frontend build as a CI gate before deployment triggers.

---

## Local Development

### Prerequisites

- Python 3.11+
- Node.js 18+
- Slither: `pip install slither-analyzer`
- solc-select: `pip install solc-select && solc-select install 0.8.24 && solc-select use 0.8.24`
- Foundry: https://getfoundry.sh

**Backend**
```bash
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn api:app --reload
```

**Frontend**
```bash
cd frontend
npm install && npm run dev
```

**Environment variables** — create `frontend/.env.local`:
```
NEXT_PUBLIC_SUPABASE_URL=your_supabase_url
NEXT_PUBLIC_SUPABASE_ANON_KEY=your_supabase_anon_key
NEXT_PUBLIC_API_URL=http://localhost:8000
```

**Docker**
```bash
cp docker-compose.example.yml docker-compose.yml
# Edit docker-compose.yml — fill in your Supabase keys
docker compose up --build
```

---

## CLI

ChainAudit ships with a standalone CLI tool:

```bash
cd backend
pip install -e .

# Single file
chainaudit scan contract.sol

# Directory (recursive)
chainaudit scan ./contracts --recursive

# JSON output
chainaudit scan contract.sol --json

# Skip simulation
chainaudit scan contract.sol --ml-only
```

Exit codes: `1` if CRITICAL vulnerabilities found, `0` otherwise — works in CI pipelines.

---

## How It Works

1. Upload a `.sol` file or `.zip` of multiple contracts via drag & drop
2. Backend detects Solidity versions from pragma statements and switches solc automatically
3. Slither runs static analysis — findings deduplicated by rule ID, highest impact kept
4. Risk score computed using CVSS-inspired scoring (attack vector, complexity, CIA impact)
5. ML model (Random Forest) predicts exploitability per finding with confidence score
6. Foundry runs exploit simulations in parallel
7. Results rendered with animated gauge, severity cards, expandable findings, ML badges
8. Signed-in users get scan history saved to Supabase
9. Export full report as PDF

---

## API

`POST /scan` — single `.sol` file
`POST /scan/zip` — zip of multiple `.sol` files (max 20 files, 5MB)

```json
{
  "scan_id": "uuid",
  "risk_score": 86,
  "total_findings": 6,
  "findings": [
    {
      "title": "Reentrancy",
      "severity": "CRITICAL",
      "description": "...",
      "fix": "...",
      "check": "reentrancy-no-eth",
      "impact": "High",
      "confidence": "Medium",
      "occurrences": 7,
      "ml_exploitability": "CRITICAL",
      "ml_confidence": 0.96
    }
  ],
  "exploit_simulation": {
    "success": true,
    "stdout": "...",
    "stderr": ""
  }
}
```

---

## Vulnerability Coverage

| Slither Detector | Severity | Rule |
|-----------------|----------|------|
| reentrancy-eth / no-eth / benign / events | CRITICAL | Reentrancy |
| reentrancy-unlimited-gas | CRITICAL | Reentrancy with Unlimited Gas |
| controlled-delegatecall | CRITICAL | Controlled Delegatecall |
| unchecked-transfer | HIGH | Unchecked Token Transfer |
| arbitrary-send-eth | HIGH | Arbitrary ETH Send |
| weak-prng | HIGH | Weak Randomness |
| tx-origin | HIGH | tx.origin Authentication |
| suicidal | HIGH | Selfdestruct Risk |
| timestamp | MEDIUM | Timestamp Dependence |
| unchecked-send | MEDIUM | Unchecked Send |
| deprecated-standards | MEDIUM | Deprecated Solidity Standards |
| events-access | LOW | Missing Access Control Event |
| events-maths | LOW | Missing Arithmetic Event |
| incorrect-equality | LOW | Incorrect Equality Check |
| missing-zero-check | LOW | Missing Zero Address Check |
| naming-convention | LOW | Naming Convention Violation |

---

## CVSS-Inspired Risk Scoring

Each rule has CVSS factors (attack vector, complexity, privileges required, CIA impact). Score is computed per finding and normalized logarithmically to 0–100.

| Severity | Multiplier |
|----------|-----------|
| CRITICAL | 10.0 |
| HIGH | 7.5 |
| MEDIUM | 4.0 |
| LOW | 1.5 |

| Confidence | Weight |
|-----------|--------|
| High | 1.0 |
| Medium | 0.7 |
| Low | 0.4 |

---

## ML Pipeline

- **Dataset:** SmartBugs — 143 contracts across 10 vulnerability categories
- **Features:** check ID, impact, confidence, contract size, occurrence count
- **Model:** Random Forest Classifier
- **Accuracy:** 88% overall (95% precision on HIGH, 93% on CRITICAL)
- **Output:** exploitability label + confidence score per finding

---

## Test Contracts

Sample contracts in `contracts/test/`:

| File | Expected Risk |
|------|--------------|
| `01_empty.sol` | 0 — nothing to find |
| `06_low_risk.sol` | 5–20 — LOW findings only |
| `05_medium_risk.sol` | 25–50 — MEDIUM findings |
| `SimpleStaking.sol` | 70–85 — HIGH + CRITICAL |
| `02_high_risk.sol` | 85–100 — multiple CRITICAL |
| `test_multi.zip` | multi-contract scan |

---

