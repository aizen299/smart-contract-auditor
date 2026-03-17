# ChainAudit — Smart Contract Security Platform

A full-stack smart contract auditing platform. Upload a Solidity file, get a real-time security report with risk scores, severity-ranked findings, and actionable fixes — powered by Slither static analysis.

**Live:** [chainaudit.vercel.app](https://chainaudit.vercel.app)  
**API:** [smart-contract-auditor-production.up.railway.app](https://smart-contract-auditor-production.up.railway.app)

---

## Stack

| Layer | Tech |
|-------|------|
| Frontend | Next.js 14 (App Router), TypeScript, Tailwind CSS v3 |
| Backend | FastAPI, Python 3.11 |
| Analysis | Slither 0.11.5, solc-select (solc 0.8.24) |
| Simulation | Foundry (forge) |
| Deployment | Vercel (frontend) + Railway (backend) |
| CI/CD | GitHub Actions |
| Containerization | Docker + docker-compose |

---

## Project Structure
```
smart-contract-auditor/
├── .github/
│   └── workflows/
│       └── ci.yml             # CI — type check + build on every push
├── frontend/                  # Next.js app
│   ├── app/
│   │   ├── page.tsx           # Main page (upload → scan → results)
│   │   ├── layout.tsx
│   │   └── globals.css
│   ├── components/
│   │   ├── NavBar.tsx
│   │   ├── UploadZone.tsx     # Drag & drop file upload
│   │   ├── ScanLoader.tsx     # Animated scan progress
│   │   ├── ScanResults.tsx    # Results page + PDF export
│   │   ├── FindingCard.tsx    # Expandable finding card
│   │   ├── SeverityBadge.tsx  # CRITICAL / HIGH / MEDIUM / LOW badge
│   │   └── RiskScore.tsx      # Animated circular gauge
│   ├── types/
│   │   └── index.ts
│   ├── lib/
│   │   └── api.ts             # fetch wrapper for /scan endpoint
│   ├── Dockerfile
│   └── package.json
├── backend/                   # FastAPI server
│   ├── api.py                 # POST /scan endpoint
│   ├── src/
│   │   ├── main.py            # CLI entrypoint
│   │   ├── scanner.py         # Slither runner + dedup parser
│   │   ├── rules.py           # Vulnerability rules + scoring engine
│   │   ├── report_gen.py      # JSON + HTML report writer
│   │   └── exploit_simulator.py  # Foundry test runner
│   ├── reports/               # Generated scan reports (gitignored)
│   ├── Dockerfile
│   ├── Procfile               # Railway start command
│   ├── runtime.txt            # Python version for Railway
│   ├── railway.json           # Railway deployment config
│   └── requirements.txt
├── docker-compose.yml         # Local full-stack Docker setup
└── README.md
```

---

## Getting Started

### Prerequisites

- Python 3.11+
- Node.js 18+
- Slither: `pip install slither-analyzer`
- solc-select: `pip install solc-select`
- Foundry: https://getfoundry.sh

### 1. Install solc
```bash
solc-select install 0.8.24
solc-select use 0.8.24
```

### 2. Backend
```bash
cd backend
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
uvicorn api:app --reload
```

Backend runs at `http://localhost:8000`.

### 3. Frontend
```bash
cd frontend
npm install
npm run dev
```

Frontend runs at `http://localhost:3000`.

### 4. Docker (full stack)
```bash
docker-compose up --build
```

---

## How It Works

1. User uploads a `.sol` file via the drag & drop frontend
2. Frontend POSTs the file to `POST /scan` via `/api/scan` proxy
3. Backend saves the file to a temp directory and runs Slither
4. Slither findings are parsed and mapped to structured rules via `rules.py`
5. Findings are **deduplicated by rule ID** — multiple occurrences collapsed into one, highest impact kept
6. Risk score computed using severity × confidence weighting, capped at 100
7. Foundry exploit simulation runs in parallel
8. JSON report saved and returned to the frontend
9. Frontend renders animated risk gauge, severity breakdown, and expandable finding cards
10. User can export the full report as a dark-themed PDF

---

## API

### `POST /scan`

Accepts a Solidity file upload, returns a JSON audit report.

**Request:** `multipart/form-data` with a `.sol` file field named `file`

**Response:**
```json
{
  "scan_id": "uuid",
  "target": "path/to/contract.sol",
  "generated": "2026-03-17T18:23:49Z",
  "risk_score": 77,
  "total_findings": 6,
  "findings": [
    {
      "title": "Reentrancy",
      "severity": "CRITICAL",
      "description": "...",
      "fix": "...",
      "check": "reentrancy-no-eth",
      "impact": "Medium",
      "confidence": "Medium",
      "occurrences": 7
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
| controlled-delegatecall | CRITICAL | Controlled Delegatecall |
| unchecked-transfer | HIGH | Unchecked Token Transfer |
| arbitrary-send-eth | HIGH | Arbitrary ETH Send |
| weak-prng | HIGH | Weak Randomness |
| tx-origin | HIGH | tx.origin Authentication |
| suicidal | HIGH | Selfdestruct Risk |
| timestamp | MEDIUM | Timestamp Dependence |
| unchecked-send | MEDIUM | Unchecked Send |
| events-access | LOW | Missing Access Control Event |
| events-maths | LOW | Missing Arithmetic Event |
| incorrect-equality | LOW | Incorrect Equality Check |
| missing-zero-check | LOW | Missing Zero Address Check |

---

## Risk Scoring
```
score = Σ (severity_base × confidence_weight) × 0.7
```

| Severity | Base Score |
|----------|-----------|
| CRITICAL | 40 |
| HIGH | 25 |
| MEDIUM | 15 |
| LOW | 5 |

| Confidence | Weight |
|-----------|--------|
| High | 1.0 |
| Medium | 0.7 |
| Low | 0.4 |

Final score is capped at 100. Findings are deduplicated by rule ID — multiple Slither detectors mapping to the same rule are collapsed into one finding, keeping the highest impact instance and tracking occurrence count.

---

## Deployment

| Service | Platform | URL |
|---------|----------|-----|
| Frontend | Vercel | chainaudit.vercel.app |
| Backend | Railway | smart-contract-auditor-production.up.railway.app |

Both services auto-deploy on every push to `main`. GitHub Actions runs a type check and full frontend build as a CI gate before deployment triggers.

---

