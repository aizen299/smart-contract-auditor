# ChainAudit

Smart contract security analysis powered by Slither. Upload a Solidity file, get a real-time audit report with risk scores, severity-ranked findings, and fix recommendations.

**Live → [chainaudit.vercel.app](https://chainaudit.vercel.app)**

---

## Stack

| | |
|---|---|
| Frontend | Next.js 14, TypeScript, Tailwind CSS |
| Backend | FastAPI, Python 3.11 |
| Analysis | Slither, solc-select |
| Deploy | Vercel + Railway |
| CI/CD | GitHub Actions |

---

## Local Development

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

**Docker**
```bash
docker compose up --build
```

> Requires Docker with `linux/amd64` platform support (Apple Silicon compatible)

---

## How It Works

1. Upload a `.sol` file via drag & drop
2. Backend runs Slither static analysis
3. Findings mapped to structured rules, deduplicated by rule ID
4. Risk score computed via severity × confidence weighting (capped at 100)
5. Results rendered with animated gauge, severity cards, and expandable findings
6. Export full report as PDF

---



