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

1. User uploads a `.sol` file or a `.zip` archive containing Solidity contracts via the frontend  
2. Frontend sends the file to `POST /scan`  
3. Backend extracts files (if ZIP) and detects Solidity versions from pragma statements  
4. `solc-select` automatically switches to the required compiler version per contract  
5. Slither runs static analysis on the contracts  
6. Raw Slither output is parsed and mapped to structured vulnerability rules  
7. Risk score is computed using severity × confidence weighting  
8. Extracted features are passed into the ML model (Random Forest)  
9. ML model predicts exploitability and assigns a confidence score  
10. Foundry executes exploit simulations in parallel to validate vulnerabilities  
11. All results (static findings + ML predictions + simulation output) are aggregated  
12. Final JSON report is generated and stored  
13. Frontend renders:
    - Risk score gauge  
    - Severity distribution  
    - Detailed findings  
    - ML exploitability badge  
    - Simulation results  
14. User can export a complete audit report as PDF  
---

## API

### `POST /scan`

Accepts a Solidity file upload as well as a zip compressed of solidity files returns a JSON audit report.

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

## Machine Learning Pipeline
```
	•	Dataset: SmartBugs (143 contracts, 10 vulnerability classes)
	•	Feature Extraction: Slither JSON outputs
	•	Model: Random Forest Classifier
	•	Accuracy: 88%
```  

## ML Capabilities
```
    •	Predicts exploitability likelihood
	•	Provides confidence score
	•	Enhances prioritization of vulnerabilities
	•	Integrated directly into scan pipeline
```