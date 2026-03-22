"""
ChainAudit — Test suite for CLI and backend modules.

Run with:
    cd backend
    pytest tests/ -v
"""

import json
import os
import sys
import zipfile
import tempfile
import shutil
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

# Ensure backend/ is on path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def empty_sol(tmp_path):
    f = tmp_path / "Empty.sol"
    f.write_text("pragma solidity ^0.8.24;\ncontract Empty {}\n")
    return f


@pytest.fixture
def valid_sol(tmp_path):
    f = tmp_path / "SimpleStaking.sol"
    f.write_text("""
pragma solidity ^0.8.24;
interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}
contract SimpleStaking {
    IERC20 public stakingToken;
    mapping(address => uint256) public stakedBalance;
    uint256 public rewardRate = 100;
    address public owner;

    constructor(address _token) { stakingToken = IERC20(_token); owner = msg.sender; }

    function stake(uint256 amount) external {
        require(amount > 0, "Cannot stake 0");
        stakingToken.transferFrom(msg.sender, address(this), amount);
        stakedBalance[msg.sender] += amount;
    }

    function withdraw(uint256 amount) external {
        require(stakedBalance[msg.sender] >= amount, "Insufficient balance");
        stakedBalance[msg.sender] -= amount;
        stakingToken.transfer(msg.sender, amount);
    }
}
""")
    return f


@pytest.fixture
def broken_sol(tmp_path):
    f = tmp_path / "Broken.sol"
    f.write_text("pragma solidity ^0.8.24;\ncontract Broken { function foo( {} }\n")
    return f


@pytest.fixture
def sol_directory(tmp_path):
    # Create files directly — don't copy from other fixtures that share tmp_path
    d = tmp_path / "contracts"
    d.mkdir()
    (d / "Empty.sol").write_text("pragma solidity ^0.8.24;\ncontract Empty {}\n")
    (d / "SimpleStaking.sol").write_text(
        "pragma solidity ^0.8.24;\ncontract SimpleStaking { address public owner; }\n"
    )
    return d
@pytest.fixture
def sol_zip(tmp_path, valid_sol, empty_sol):
    zip_path = tmp_path / "contracts.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.write(valid_sol, "SimpleStaking.sol")
        zf.write(empty_sol, "Empty.sol")
    return zip_path


@pytest.fixture
def mock_slither_findings():
    return [
        {
            "title": "Reentrancy",
            "severity": "CRITICAL",
            "description": "External call before updating state.",
            "fix": "Use CEI pattern.",
            "check": "reentrancy-no-eth",
            "impact": "Medium",
            "confidence": "Medium",
            "occurrences": 3,
        },
        {
            "title": "Unchecked Token Transfer",
            "severity": "HIGH",
            "description": "Return value not checked.",
            "fix": "Use SafeERC20.",
            "check": "unchecked-transfer",
            "impact": "High",
            "confidence": "Medium",
            "occurrences": 2,
        },
        {
            "title": "Timestamp Dependence",
            "severity": "MEDIUM",
            "description": "block.timestamp can be manipulated.",
            "fix": "Avoid timestamp for critical logic.",
            "check": "timestamp",
            "impact": "Low",
            "confidence": "Medium",
            "occurrences": 1,
        },
    ]


# ---------------------------------------------------------------------------
# rules.py tests
# ---------------------------------------------------------------------------

class TestRules:
    def test_map_finding_known_check(self):
        from src.rules import map_finding
        rule = map_finding("reentrancy-eth")
        assert rule.id == "reentrancy"
        assert rule.severity == "CRITICAL"

    def test_map_finding_unknown_returns_default(self):
        from src.rules import map_finding
        rule = map_finding("totally-unknown-check-xyz")
        assert rule.id == "unknown"

    def test_map_finding_fuzzy_match(self):
        from src.rules import map_finding
        rule = map_finding("reentrancy-benign")
        assert rule.id == "reentrancy"

    def test_compute_risk_score_empty(self):
        from src.rules import compute_risk_score
        assert compute_risk_score([]) == 0

    def test_compute_risk_score_critical(self, mock_slither_findings):
        from src.rules import compute_risk_score
        score = compute_risk_score(mock_slither_findings)
        assert score > 0
        assert score <= 100

    def test_compute_risk_score_low_only(self):
        from src.rules import compute_risk_score
        findings = [
            {"severity": "LOW", "confidence": "Low", "check": "events-maths", "occurrences": 1}
        ]
        score = compute_risk_score(findings)
        assert score >= 0
        assert score < 50

    def test_compute_risk_score_capped_at_100(self):
        from src.rules import compute_risk_score
        # Lots of critical findings shouldn't exceed 100
        findings = [
            {"severity": "CRITICAL", "confidence": "High", "check": "reentrancy-eth", "occurrences": 10}
        ] * 20
        score = compute_risk_score(findings)
        assert score <= 100

    def test_all_severity_rules_have_cvss(self):
        from src.rules import RULES
        for rule_id, rule in RULES.items():
            assert hasattr(rule, "cvss"), f"Rule {rule_id} missing CVSS factors"
            assert rule.severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW")

    def test_slither_to_rule_mapping_complete(self):
        from src.rules import SLITHER_TO_RULE, RULES
        for check, rule_id in SLITHER_TO_RULE.items():
            assert rule_id in RULES, f"SLITHER_TO_RULE maps '{check}' to '{rule_id}' which is not in RULES"


# ---------------------------------------------------------------------------
# scanner.py tests
# ---------------------------------------------------------------------------

class TestScanner:
    def test_parse_slither_report_missing_file(self, tmp_path):
        from src.scanner import parse_slither_report, SLITHER_JSON
        # Ensure slither.json doesn't exist
        if SLITHER_JSON.exists():
            SLITHER_JSON.unlink()
        result = parse_slither_report()
        assert result == []

    def test_parse_slither_report_empty_detectors(self, tmp_path):
        from src.scanner import parse_slither_report, SLITHER_JSON, REPORTS_DIR
        REPORTS_DIR.mkdir(exist_ok=True)
        SLITHER_JSON.write_text('{"success": true, "results": {"detectors": []}}')
        result = parse_slither_report()
        assert result == []

    def test_parse_slither_report_with_findings(self, tmp_path):
        from src.scanner import parse_slither_report, SLITHER_JSON, REPORTS_DIR
        REPORTS_DIR.mkdir(exist_ok=True)
        data = {
            "success": True,
            "results": {
                "detectors": [
                    {
                        "check": "reentrancy-eth",
                        "impact": "High",
                        "confidence": "Medium",
                        "elements": [],
                    }
                ]
            }
        }
        SLITHER_JSON.write_text(json.dumps(data))
        result = parse_slither_report()
        assert len(result) >= 1
        assert result[0]["severity"] == "CRITICAL"

    def test_parse_slither_report_deduplicates(self):
        from src.scanner import parse_slither_report, SLITHER_JSON, REPORTS_DIR
        REPORTS_DIR.mkdir(exist_ok=True)
        # Two reentrancy variants should deduplicate to one
        data = {
            "success": True,
            "results": {
                "detectors": [
                    {"check": "reentrancy-eth", "impact": "High", "confidence": "High", "elements": []},
                    {"check": "reentrancy-benign", "impact": "Low", "confidence": "Low", "elements": []},
                    {"check": "reentrancy-events", "impact": "Low", "confidence": "Medium", "elements": []},
                ]
            }
        }
        SLITHER_JSON.write_text(json.dumps(data))
        result = parse_slither_report()
        titles = [f["title"] for f in result]
        assert titles.count("Reentrancy") == 1

    def test_parse_slither_report_invalid_json(self):
        from src.scanner import parse_slither_report, SLITHER_JSON, REPORTS_DIR
        REPORTS_DIR.mkdir(exist_ok=True)
        SLITHER_JSON.write_text("not valid json {{{")
        result = parse_slither_report()
        assert result == []

    def test_parse_slither_report_unknown_checks_skipped(self):
        from src.scanner import parse_slither_report, SLITHER_JSON, REPORTS_DIR
        REPORTS_DIR.mkdir(exist_ok=True)
        data = {
            "success": True,
            "results": {
                "detectors": [
                    {"check": "solc-version", "impact": "Informational", "confidence": "High", "elements": []},
                ]
            }
        }
        SLITHER_JSON.write_text(json.dumps(data))
        result = parse_slither_report()
        # solc-version maps to unknown and should be dropped
        assert all(f["title"] != "Unclassified Vulnerability" or f["severity"] != "unknown" for f in result)


# ---------------------------------------------------------------------------
# api.py tests
# ---------------------------------------------------------------------------

class TestAPI:
    @pytest.fixture
    def client(self):
        from fastapi.testclient import TestClient
        from api import app
        return TestClient(app)

    def test_root_returns_ok(self, client):
        resp = client.get("/")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"

    def test_health_get(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "healthy"

    def test_health_head(self, client):
        resp = client.head("/health")
        assert resp.status_code == 200

    def test_scan_rejects_non_sol(self, client, tmp_path):
        f = tmp_path / "test.txt"
        f.write_text("not solidity")
        with open(f, "rb") as fh:
            resp = client.post("/scan", files={"file": ("test.txt", fh, "text/plain")})
        assert resp.status_code == 400
        assert "sol" in resp.json()["detail"].lower()

    def test_scan_rejects_empty_file(self, client, tmp_path):
        f = tmp_path / "empty.sol"
        f.write_text("")
        with open(f, "rb") as fh:
            resp = client.post("/scan", files={"file": ("empty.sol", fh, "text/plain")})
        assert resp.status_code == 400

    def test_scan_rejects_fake_solidity(self, client, tmp_path):
        f = tmp_path / "fake.sol"
        f.write_text("this is not solidity at all")
        with open(f, "rb") as fh:
            resp = client.post("/scan", files={"file": ("fake.sol", fh, "text/plain")})
        assert resp.status_code == 400

    def test_scan_zip_rejects_non_zip(self, client, tmp_path):
        f = tmp_path / "test.zip"
        f.write_text("not a zip")
        with open(f, "rb") as fh:
            resp = client.post("/scan/zip", files={"file": ("test.zip", fh, "application/zip")})
        assert resp.status_code == 400

    def test_scan_zip_rejects_wrong_extension(self, client, tmp_path):
        f = tmp_path / "contracts.tar"
        f.write_text("something")
        with open(f, "rb") as fh:
            resp = client.post("/scan/zip", files={"file": ("contracts.tar", fh, "application/octet-stream")})
        assert resp.status_code == 400

    def test_scan_zip_rejects_empty_zip(self, client, tmp_path):
        zip_path = tmp_path / "empty.zip"
        with zipfile.ZipFile(zip_path, "w"):
            pass
        with open(zip_path, "rb") as fh:
            resp = client.post("/scan/zip", files={"file": ("empty.zip", fh, "application/zip")})
        assert resp.status_code == 400
        assert "No Solidity" in resp.json()["detail"]

    def test_scan_zip_rejects_oversized(self, client, tmp_path):
        zip_path = tmp_path / "big.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("big.sol", "x" * (6 * 1024 * 1024))
        with open(zip_path, "rb") as fh:
            resp = client.post("/scan/zip", files={"file": ("big.zip", fh, "application/zip")})
        assert resp.status_code == 400
        assert "large" in resp.json()["detail"].lower()


# ---------------------------------------------------------------------------
# CLI tests
# ---------------------------------------------------------------------------

class TestCLI:
    def _run(self, args: list[str]):
        """Run CLI and return (exit_code, stdout)."""
        from io import StringIO
        from src.cli import build_parser, cmd_scan
        import contextlib

        parser = build_parser()
        parsed = parser.parse_args(args)

        out = StringIO()
        exit_code = 0
        try:
            with contextlib.redirect_stdout(out):
                exit_code = cmd_scan(parsed)
        except SystemExit as e:
            exit_code = e.code or 0

        return exit_code, out.getvalue()

    def test_help(self):
        from src.cli import build_parser
        parser = build_parser()
        with pytest.raises(SystemExit) as exc:
            parser.parse_args(["--help"])
        assert exc.value.code == 0

    def test_scan_help(self):
        from src.cli import build_parser
        parser = build_parser()
        with pytest.raises(SystemExit) as exc:
            parser.parse_args(["scan", "--help"])
        assert exc.value.code == 0

    def test_collect_sol_files_single(self, valid_sol):
        from src.cli import _collect_sol_files
        files = _collect_sol_files(valid_sol, recursive=False)
        assert len(files) == 1
        assert files[0] == valid_sol

    def test_collect_sol_files_directory(self, sol_directory):
        from src.cli import _collect_sol_files
        files = _collect_sol_files(sol_directory, recursive=False)
        assert len(files) >= 1
        assert all(f.suffix == ".sol" for f in files)

    def test_collect_sol_files_recursive(self, tmp_path):
        from src.cli import _collect_sol_files
        subdir = tmp_path / "sub"
        subdir.mkdir()
        (tmp_path / "Root.sol").write_text("pragma solidity ^0.8.0; contract Root {}")
        (subdir / "Sub.sol").write_text("pragma solidity ^0.8.0; contract Sub {}")
        files = _collect_sol_files(tmp_path, recursive=True)
        names = [f.name for f in files]
        assert "Root.sol" in names
        assert "Sub.sol" in names

    def test_collect_sol_files_zip(self, sol_zip):
        from src.cli import _collect_sol_files
        files = _collect_sol_files(sol_zip, recursive=False)
        assert len(files) >= 1
        assert all(f.suffix == ".sol" for f in files)

    def test_collect_sol_files_nonexistent(self, tmp_path):
        from src.cli import _collect_sol_files
        with pytest.raises(SystemExit) as exc:
            _collect_sol_files(tmp_path / "nonexistent.sol", recursive=False)
        assert exc.value.code == 2

    def test_collect_sol_files_wrong_extension(self, tmp_path):
        from src.cli import _collect_sol_files
        f = tmp_path / "contract.txt"
        f.write_text("something")
        with pytest.raises(SystemExit) as exc:
            _collect_sol_files(f, recursive=False)
        assert exc.value.code == 2

    def test_collect_sol_files_empty_directory(self, tmp_path):
        from src.cli import _collect_sol_files
        with pytest.raises(SystemExit) as exc:
            _collect_sol_files(tmp_path, recursive=False)
        assert exc.value.code == 0

    def test_collect_excludes_node_modules(self, tmp_path):
        from src.cli import _collect_sol_files
        node_dir = tmp_path / "node_modules"
        node_dir.mkdir()
        (node_dir / "Dep.sol").write_text("pragma solidity ^0.8.0; contract Dep {}")
        (tmp_path / "MyContract.sol").write_text("pragma solidity ^0.8.0; contract My {}")
        files = _collect_sol_files(tmp_path, recursive=True)
        names = [f.name for f in files]
        assert "MyContract.sol" in names
        assert "Dep.sol" not in names

    @patch("src.cli.run_slither", return_value=True)
    @patch("src.cli.parse_slither_report")
    @patch("src.cli.run_foundry_tests", return_value={"success": True, "stdout": "", "stderr": ""})
    def test_scan_file_success(self, mock_foundry, mock_parse, mock_slither, valid_sol, mock_slither_findings):
        from src.cli import _scan_file
        mock_parse.return_value = mock_slither_findings
        result = _scan_file(valid_sol, ml_only=False)
        assert result["status"] == "success"
        assert result["risk_score"] > 0
        assert len(result["findings"]) == 3

    @patch("src.cli.run_slither", return_value=False)
    def test_scan_file_slither_failure(self, mock_slither, broken_sol):
        from src.cli import _scan_file
        result = _scan_file(broken_sol, ml_only=False)
        assert result["status"] == "error"
        assert result["risk_score"] == 0
        assert result["findings"] == []

    @patch("src.cli.run_slither", return_value=True)
    @patch("src.cli.parse_slither_report")
    @patch("src.cli.run_foundry_tests")
    def test_ml_only_skips_simulation(self, mock_foundry, mock_parse, mock_slither, valid_sol, mock_slither_findings):
        from src.cli import _scan_file
        mock_parse.return_value = mock_slither_findings
        result = _scan_file(valid_sol, ml_only=True)
        mock_foundry.assert_not_called()
        assert result["exploit_simulation"]["stderr"] == "skipped"

    @patch("src.cli.run_slither", return_value=True)
    @patch("src.cli.parse_slither_report")
    @patch("src.cli.run_foundry_tests", return_value={"success": True, "stdout": "", "stderr": ""})
    def test_json_output_valid(self, mock_foundry, mock_parse, mock_slither, valid_sol, mock_slither_findings, capsys):
        from src.cli import build_parser, cmd_scan
        mock_parse.return_value = mock_slither_findings
        parser = build_parser()
        args = parser.parse_args(["scan", str(valid_sol), "--json"])
        cmd_scan(args)
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert "risk_score" in data
        assert "findings" in data

    @patch("src.cli.run_slither", return_value=True)
    @patch("src.cli.parse_slither_report")
    @patch("src.cli.run_foundry_tests", return_value={"success": True, "stdout": "", "stderr": ""})
    def test_exit_code_critical(self, mock_foundry, mock_parse, mock_slither, valid_sol, mock_slither_findings):
        from src.cli import build_parser, cmd_scan
        mock_parse.return_value = mock_slither_findings  # contains CRITICAL
        parser = build_parser()
        args = parser.parse_args(["scan", str(valid_sol)])
        exit_code = cmd_scan(args)
        assert exit_code == 1  # CRITICAL findings → exit 1

    @patch("src.cli.run_slither", return_value=True)
    @patch("src.cli.parse_slither_report")
    @patch("src.cli.run_foundry_tests", return_value={"success": True, "stdout": "", "stderr": ""})
    def test_exit_code_no_critical(self, mock_foundry, mock_parse, mock_slither, valid_sol):
        from src.cli import build_parser, cmd_scan
        mock_parse.return_value = [
            {"title": "Low Issue", "severity": "LOW", "description": "...",
             "fix": "...", "check": "events-maths", "impact": "Low",
             "confidence": "Medium", "occurrences": 1}
        ]
        parser = build_parser()
        args = parser.parse_args(["scan", str(valid_sol)])
        exit_code = cmd_scan(args)
        assert exit_code == 0  # no CRITICAL → exit 0


# ---------------------------------------------------------------------------
# ML predictor tests
# ---------------------------------------------------------------------------

class TestMLPredictor:
    def test_predictor_loads(self):
        try:
            from ml.predictor import predictor
            assert predictor is not None
        except ImportError:
            pytest.skip("ML module not available")

    def test_predictor_returns_dict(self):
        try:
            from ml.predictor import predictor
            finding = {
                "check": "reentrancy-eth",
                "impact": "High",
                "confidence": "Medium",
                "occurrences": 3,
            }
            result = predictor.predict(finding, contract_size=1000)
            assert "exploitability" in result
            assert "confidence" in result
            assert 0.0 <= result["confidence"] <= 1.0
        except ImportError:
            pytest.skip("ML module not available")

    def test_predictor_handles_unknown_check(self):
        try:
            from ml.predictor import predictor
            finding = {
                "check": "totally-unknown-xyz",
                "impact": "Low",
                "confidence": "Low",
                "occurrences": 1,
            }
            result = predictor.predict(finding, contract_size=500)
            assert "exploitability" in result
        except ImportError:
            pytest.skip("ML module not available")

    def test_predictor_no_model_file(self, tmp_path, monkeypatch):
        try:
            import ml.predictor as pred_module
            monkeypatch.setattr(pred_module, "MODEL_PATH", tmp_path / "nonexistent.joblib")
            from ml.predictor import ExploitabilityPredictor
            p = ExploitabilityPredictor()
            result = p.predict({"check": "reentrancy", "impact": "High", "confidence": "High", "occurrences": 1}, 1000)
            assert result["exploitability"] == "unknown"
        except ImportError:
            pytest.skip("ML module not available")

# ---------------------------------------------------------------------------
# Solana scanner tests
# ---------------------------------------------------------------------------

class TestSolanaRules:
    def test_all_rules_have_required_fields(self):
        from src.solana_rules import SOLANA_RULES
        for rule_id, rule in SOLANA_RULES.items():
            assert rule.id == rule_id
            assert rule.severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
            assert rule.title
            assert rule.description
            assert rule.fix
            assert rule.chain == "solana"

    def test_get_rule_known(self):
        from src.solana_rules import get_rule
        rule = get_rule("missing-signer-check")
        assert rule.severity == "CRITICAL"
        assert rule.id == "missing-signer-check"

    def test_get_rule_unknown_returns_default(self):
        from src.solana_rules import get_rule
        rule = get_rule("totally-unknown-xyz")
        assert rule.id == "unknown"

    def test_compute_solana_risk_score_empty(self):
        from src.solana_rules import compute_solana_risk_score
        assert compute_solana_risk_score([]) == 0

    def test_compute_solana_risk_score_critical(self):
        from src.solana_rules import compute_solana_risk_score
        findings = [
            {"severity": "CRITICAL", "confidence": "High"},
            {"severity": "HIGH", "confidence": "Medium"},
        ]
        score = compute_solana_risk_score(findings)
        assert score > 0
        assert score <= 100

    def test_compute_solana_risk_score_capped(self):
        from src.solana_rules import compute_solana_risk_score
        findings = [{"severity": "CRITICAL", "confidence": "High"}] * 50
        score = compute_solana_risk_score(findings)
        assert score <= 100

    def test_patterns_have_required_fields(self):
        from src.solana_rules import SOLANA_PATTERNS, SOLANA_RULES
        for p in SOLANA_PATTERNS:
            assert "rule_id" in p
            assert "patterns" in p
            assert "anti_patterns" in p
            assert p["rule_id"] in SOLANA_RULES, f"Pattern rule_id '{p['rule_id']}' not in SOLANA_RULES"


class TestSolanaScanner:
    @pytest.fixture
    def vulnerable_rs(self, tmp_path):
        f = tmp_path / "lib.rs"
        f.write_text("""
use anchor_lang::prelude::*;

#[program]
pub mod vault {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        vault.balance = vault.balance + 100;
        Ok(())
    }
}

unsafe fn raw_op(ptr: *mut u8) {
    std::ptr::write_bytes(ptr, 0, 1);
}

pub fn pick_winner() -> u64 {
    let clock = Clock::get().unwrap();
    clock.unix_timestamp as u64 % 10
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    pub vault: Account<'info, Vault>,
    pub authority: AccountInfo<'info>,
}

#[account]
pub struct Vault {
    pub balance: u64,
}
""")
        return f

    @pytest.fixture
    def safe_rs(self, tmp_path):
        f = tmp_path / "safe.rs"
        f.write_text("""
use anchor_lang::prelude::*;

#[program]
pub mod safe_vault {
    use super::*;

    pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        vault.balance = vault.balance
            .checked_add(amount)
            .ok_or(ErrorCode::Overflow)?;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Deposit<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    pub authority: Signer<'info>,
}

#[account]
pub struct Vault {
    pub balance: u64,
}
""")
        return f

    def test_is_solana_project_rs_file(self, vulnerable_rs):
        from src.solana_scanner import is_solana_project
        assert is_solana_project(vulnerable_rs) is True

    def test_is_solana_project_sol_file(self, empty_sol):
        from src.solana_scanner import is_solana_project
        assert is_solana_project(empty_sol) is False

    def test_is_solana_project_directory_with_rs(self, tmp_path):
        from src.solana_scanner import is_solana_project
        (tmp_path / "lib.rs").write_text("fn main() {}")
        assert is_solana_project(tmp_path) is True

    def test_is_solana_project_empty_directory(self, tmp_path):
        from src.solana_scanner import is_solana_project
        assert is_solana_project(tmp_path) is False

    def test_collect_rs_files_single(self, vulnerable_rs):
        from src.solana_scanner import _collect_rs_files
        files = _collect_rs_files(vulnerable_rs)
        assert len(files) == 1
        assert files[0] == vulnerable_rs

    def test_collect_rs_files_directory(self, tmp_path):
        from src.solana_scanner import _collect_rs_files
        (tmp_path / "a.rs").write_text("fn a() {}")
        (tmp_path / "b.rs").write_text("fn b() {}")
        files = _collect_rs_files(tmp_path)
        assert len(files) == 2

    def test_collect_rs_files_excludes_target(self, tmp_path):
        from src.solana_scanner import _collect_rs_files
        target_dir = tmp_path / "target" / "debug"
        target_dir.mkdir(parents=True)
        (target_dir / "build.rs").write_text("fn main() {}")
        (tmp_path / "lib.rs").write_text("fn lib() {}")
        files = _collect_rs_files(tmp_path)
        names = [f.name for f in files]
        assert "lib.rs" in names
        assert "build.rs" not in names

    def test_pattern_scan_detects_unsafe(self, vulnerable_rs):
        from src.solana_scanner import run_pattern_scan
        findings = run_pattern_scan(vulnerable_rs)
        checks = [f["check"] for f in findings]
        assert "unsafe-code" in checks

    def test_pattern_scan_detects_insecure_randomness(self, vulnerable_rs):
        from src.solana_scanner import run_pattern_scan
        findings = run_pattern_scan(vulnerable_rs)
        checks = [f["check"] for f in findings]
        assert "insecure-randomness" in checks

    def test_pattern_scan_detects_integer_overflow(self, vulnerable_rs):
        from src.solana_scanner import run_pattern_scan
        findings = run_pattern_scan(vulnerable_rs)
        checks = [f["check"] for f in findings]
        assert "integer-overflow" in checks

    def test_pattern_scan_safe_contract_no_overflow(self, safe_rs):
        from src.solana_scanner import run_pattern_scan
        findings = run_pattern_scan(safe_rs)
        checks = [f["check"] for f in findings]
        assert "integer-overflow" not in checks

    def test_pattern_scan_safe_contract_no_unsafe(self, safe_rs):
        from src.solana_scanner import run_pattern_scan
        findings = run_pattern_scan(safe_rs)
        checks = [f["check"] for f in findings]
        assert "unsafe-code" not in checks

    def test_scan_solana_returns_success(self, vulnerable_rs):
        from src.solana_scanner import scan_solana
        result = scan_solana(vulnerable_rs)
        assert result["status"] == "success"
        assert result["chain"] == "solana"
        assert result["total_findings"] > 0
        assert result["risk_score"] > 0

    def test_scan_solana_non_rust_returns_error(self, empty_sol):
        from src.solana_scanner import scan_solana
        result = scan_solana(empty_sol)
        assert result["status"] == "error"

    def test_scan_solana_findings_have_required_fields(self, vulnerable_rs):
        from src.solana_scanner import scan_solana
        result = scan_solana(vulnerable_rs)
        for f in result["findings"]:
            assert "title" in f
            assert "severity" in f
            assert "description" in f
            assert "fix" in f
            assert "check" in f
            assert f["severity"] in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
            assert f["chain"] == "solana"

    def test_scan_solana_risk_score_bounded(self, vulnerable_rs):
        from src.solana_scanner import scan_solana
        result = scan_solana(vulnerable_rs)
        assert 0 <= result["risk_score"] <= 100

    def test_detect_anchor_project(self, tmp_path):
        from src.solana_scanner import detect_anchor_project
        cargo_toml = tmp_path / "Cargo.toml"
        cargo_toml.write_text('[dependencies]\nanchor-lang = "0.29.0"\n')
        assert detect_anchor_project(tmp_path) is True

    def test_detect_non_anchor_project(self, tmp_path):
        from src.solana_scanner import detect_anchor_project
        cargo_toml = tmp_path / "Cargo.toml"
        cargo_toml.write_text('[dependencies]\nserde = "1.0"\n')
        assert detect_anchor_project(tmp_path) is False


class TestSolanaAPI:
    @pytest.fixture
    def client(self):
        from fastapi.testclient import TestClient
        from api import app
        return TestClient(app)

    @pytest.fixture
    def rust_file_content(self):
        return b"""
use anchor_lang::prelude::*;

#[program]
pub mod vault {
    use super::*;
    pub fn init(ctx: Context<Init>) -> Result<()> {
        let v = &mut ctx.accounts.vault;
        v.balance = v.balance + 100;
        Ok(())
    }
}

unsafe fn raw(ptr: *mut u8) { std::ptr::write_bytes(ptr, 0, 1); }

#[derive(Accounts)]
pub struct Init<'info> {
    pub vault: Account<'info, Vault>,
    pub authority: AccountInfo<'info>,
}

#[account]
pub struct Vault { pub balance: u64 }
"""

    def test_scan_rust_rejects_non_rs(self, client, tmp_path):
        f = tmp_path / "test.sol"
        f.write_text("pragma solidity ^0.8.0; contract Test {}")
        with open(f, "rb") as fh:
            resp = client.post("/scan/rust", files={"file": ("test.sol", fh, "text/plain")})
        assert resp.status_code == 400
        assert ".rs" in resp.json()["detail"]

    def test_scan_rust_rejects_empty_file(self, client, tmp_path):
        f = tmp_path / "empty.rs"
        f.write_text("")
        with open(f, "rb") as fh:
            resp = client.post("/scan/rust", files={"file": ("empty.rs", fh, "text/plain")})
        assert resp.status_code == 400

    def test_scan_rust_rejects_invalid_rust(self, client, tmp_path):
        f = tmp_path / "fake.rs"
        f.write_text("this is not rust code at all blah blah")
        with open(f, "rb") as fh:
            resp = client.post("/scan/rust", files={"file": ("fake.rs", fh, "text/plain")})
        assert resp.status_code == 400

    def test_scan_rust_valid_file(self, client, tmp_path, rust_file_content):
        f = tmp_path / "lib.rs"
        f.write_bytes(rust_file_content)
        with open(f, "rb") as fh:
            resp = client.post("/scan/rust", files={"file": ("lib.rs", fh, "text/plain")})
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "success"
        assert data["chain"] == "solana"
        assert "findings" in data
        assert "risk_score" in data
        assert "scan_id" in data

    def test_scan_rust_findings_chain_tag(self, client, tmp_path, rust_file_content):
        f = tmp_path / "lib.rs"
        f.write_bytes(rust_file_content)
        with open(f, "rb") as fh:
            resp = client.post("/scan/rust", files={"file": ("lib.rs", fh, "text/plain")})
        data = resp.json()
        for finding in data["findings"]:
            assert finding["chain"] == "solana"

    def test_scan_rust_scanners_used(self, client, tmp_path, rust_file_content):
        f = tmp_path / "lib.rs"
        f.write_bytes(rust_file_content)
        with open(f, "rb") as fh:
            resp = client.post("/scan/rust", files={"file": ("lib.rs", fh, "text/plain")})
        data = resp.json()
        assert "scanners_used" in data
        assert data["scanners_used"]["pattern_scan"] is True
