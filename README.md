# ChainAudit — Smart Contract Security Platform

A full-stack smart contract auditing platform. Upload a Solidity file, get a real-time security report with risk scores, severity-ranked findings, and actionable fixes — powered by Slither static analysis.

---

## Stack

| Layer | Tech |
|-------|------|
| Frontend | Next.js 14 (App Router), TypeScript, Tailwind CSS |
| Backend | FastAPI, Python 3.11 |
| Analysis | Slither, solc-select |
| Simulation | Foundry (forge) |

---

## Project Structure

```
smart-contract-auditor/
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
│   └── package.json
│
├── backend/                   # FastAPI server
│   ├── api.py                 # POST /scan endpoint
│   ├── src/
│   │   ├── main.py            # CLI entrypoint
│   │   ├── scanner.py         # Slither runner + report parser
│   │   ├── rules.py           # Vulnerability rules + scoring engine
│   │   ├── report_gen.py      # JSON + HTML report writer
│   │   └── exploit_simulator.py  # Foundry test runner
│   ├── reports/               # Generated scan reports (gitignored)
│   ├── requirements.txt
│   └── .env
│
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

---

## How It Works

1. User uploads a `.sol` file via the frontend
2. Frontend POSTs the file to `POST /scan`
3. Backend saves the file and runs Slither on it
4. Slither findings are parsed and mapped to structured rules
5. Risk score is computed (severity × confidence weighting)
6. Foundry exploit simulation runs in parallel
7. JSON report is saved and returned to the frontend
8. Frontend renders the risk gauge, severity breakdown, and finding cards
9. User can export the full report as PDF

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
  "risk_score": 86,
  "total_findings": 8,
  "findings": [
    {
      "title": "Reentrancy",
      "severity": "CRITICAL",
      "description": "...",
      "fix": "...",
      "check": "reentrancy-no-eth",
      "impact": "High",
      "confidence": "Medium"
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
| reentrancy-eth / no-eth / benign | CRITICAL | Reentrancy |
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

Final score is capped at 100.

---

## Roadmap

- [ ] Deduplicate findings by rule ID, keep highest impact
- [ ] Auth + scan history (Supabase)
- [ ] Dockerize full stack
- [ ] Deploy: Vercel (frontend) + Railway (backend)
- [ ] GitHub Actions CI — auto-scan on push
- [ ] Multi-contract / repo scanning
- [ ] CVSS-style scoring refinement