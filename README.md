# 🛡️ Smart Contract Auditor + Exploit Simulator (Slither + Foundry)

A practical smart contract security project that scans Solidity contracts for vulnerabilities using **Slither**, runs **Foundry exploit simulations**, and generates **JSON + HTML audit reports**.

> Built on WSL (Ubuntu) + Python + Slither + Foundry  
> Output: vulnerability findings + severity + risk score + reports

---

## ✨ Features

✅ Static analysis using **Slither**  
✅ Detects common issues like:
- Reentrancy
- Low-level call risks
- Access control patterns
- tx.origin authentication issues  
✅ **Risk Score (0–100)** based on severity  
✅ **Exploit Simulation** using Foundry tests (`forge test`)  
✅ Generates reports:
- `reports/*.json`
- `reports/*.html`

---
## 📂 Project Structure
```
smart-contract-auditor/
│
├── contracts/ # Solidity contracts to scan
│ └── ReentrancyBank.sol
│
├── reports/ # Generated reports (HTML + JSON)
│
├── src/ # Python scanner + report generator
│ ├── main.py
│ ├── scanner.py
│ ├── report_gen.py
│ ├── exploit_simulator.py
│ └── rules.py
│
├── requirements.txt
└── README.md
```
---

## ⚙️ Requirements

- WSL Ubuntu (recommended)
- Python 3.10+
- Slither
- solc (via `solc-select`)
- Foundry (`forge`)

---

## 🚀 Installation (WSL Ubuntu)

### 1) Install dependencies
```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y git curl python3 python3-pip python3-venv pipx

pipx ensurepath
source ~/.bashrc

pipx install slither-analyzer
pipx install solc-select

solc-select install 0.8.20
solc-select use 0.8.20
pipx ensurepath
source ~/.bashrc

pipx install slither-analyzer
pipx install solc-select

solc-select install 0.8.20
solc-select use 0.8.20

cd ~/smart-contract-auditor
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

Scan default folder (contracts/)
python3 src/main.py

Scan a specific contract
python3 src/main.py --target contracts/ReentrancyBank.sol

Auto-open generated HTML report
python3 src/main.py --target contracts/ReentrancyBank.sol --open

explorer.exe "$(wslpath -w reports)"
forge test -vv
```
🔥 Example Findings

Typical Slither findings include:

reentrancy-eth

low-level-calls

solc-version

🛠️ Future Improvements

Planned upgrades:

Multi-contract scanning + combined report

CVSS-style scoring

Add more vulnerability templates (tx.origin, access control, etc.)

GitHub Actions CI for automated scans

PDF report export



