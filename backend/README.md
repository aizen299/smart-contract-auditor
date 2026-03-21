# ChainAudit

Smart contract security scanner powered by Slither + ML exploitability prediction.

[![PyPI](https://img.shields.io/pypi/v/chainaudit)](https://pypi.org/project/chainaudit/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://github.com/aizen299/smart-contract-auditor/blob/main/LICENSE)

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

## Usage

```bash
chainaudit scan contract.sol               # single file
chainaudit scan ./contracts --recursive    # directory
chainaudit scan contracts.zip              # zip archive
chainaudit scan contract.sol --json        # JSON output
chainaudit scan contract.sol --ml-only     # skip simulation
chainaudit --version                       # show version
```

Exit code `1` if CRITICAL vulnerabilities found — blocks deployments in CI.

---

## GitHub Action

```yaml
- uses: aizen299/smart-contract-auditor@v1
  with:
    target: contracts/
    fail-on-critical: true
```

---

## What It Detects

**EVM (Ethereum, Polygon, BNB Chain...)**

| Severity | Examples |
|----------|---------|
| CRITICAL | Reentrancy, Controlled Delegatecall |
| HIGH | Unchecked Token Transfer, Weak Randomness, tx.origin Auth |
| MEDIUM | Timestamp Dependence, Unchecked Send |
| LOW | Missing Zero Check, Missing Events |

**L2 / Arbitrum / Optimism — auto-detected**

| Severity | Examples |
|----------|---------|
| CRITICAL | Cross-Chain Replay Attack, Bridge Reentrancy |
| HIGH | L2 Block Number Assumption, Sequencer Dependence, Address Aliasing |
| MEDIUM | Force-Include Griefing, Gas Price Assumption |

L2 rules activate automatically when the scanner detects Arbitrum/Optimism identifiers (`ArbSys`, `xDomainMessageSender` etc.) in the contract source.

---

## ML Predictions

Each finding includes an ML-predicted exploitability score trained on the SmartBugs dataset (143 contracts, 88% accuracy).

```json
{
  "title": "Reentrancy",
  "severity": "CRITICAL",
  "ml_exploitability": "CRITICAL",
  "ml_confidence": 0.96
}
```

---

## Links

- GitHub: [aizen299/smart-contract-auditor](https://github.com/aizen299/smart-contract-auditor)
- Web app: [chainaudit.vercel.app](https://chainaudit.vercel.app)
- Issues: [GitHub Issues](https://github.com/aizen299/smart-contract-auditor/issues)