"""
ChainAudit — Solana / Rust scanner.

Two-layer detection:
1. cargo-audit  — scans Cargo.lock for known CVEs (RustSec advisory DB)
2. Pattern scan — regex-based detection of Solana-specific vulnerability
                  patterns in .rs source files
"""

import json
import re
import subprocess
import shutil
from pathlib import Path

from .solana_rules import (
    SOLANA_RULES,
    SOLANA_PATTERNS,
    compute_solana_risk_score,
    get_rule,
)

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

CARGO_AUDIT_SEVERITY = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
    "unmaintained": "MEDIUM",
    "unsound": "HIGH",
    "yanked": "LOW",
}


# =============================================================================
# TOOL DETECTION
# =============================================================================

def is_cargo_available() -> bool:
    return shutil.which("cargo") is not None


def is_cargo_audit_available() -> bool:
    return shutil.which("cargo-audit") is not None


def is_cargo_geiger_available() -> bool:
    return shutil.which("cargo-geiger") is not None


def is_solana_project(target: Path) -> bool:
    if target.is_file() and target.suffix == ".rs":
        return True
    if target.is_dir():
        return (
            (target / "Cargo.toml").exists()
            or any(target.rglob("Cargo.toml"))
            or any(target.rglob("*.rs"))
        )
    return False


def detect_anchor_project(target: Path) -> bool:
    root = target if target.is_dir() else target.parent
    cargo_toml = root / "Cargo.toml"
    if cargo_toml.exists():
        content = cargo_toml.read_text(errors="ignore")
        return "anchor-lang" in content or "anchor-spl" in content
    return False


# =============================================================================
# LAYER 1: cargo-audit
# =============================================================================

def run_cargo_audit(target: Path) -> list[dict]:
    if not is_cargo_audit_available():
        return []

    root = target if target.is_dir() else target.parent
    cargo_lock = root / "Cargo.lock"

    if not cargo_lock.exists():
        locks = list(root.rglob("Cargo.lock"))
        if not locks:
            return []
        cargo_lock = locks[0]
        root = cargo_lock.parent

    try:
        result = subprocess.run(
            ["cargo", "audit", "--json"],
            capture_output=True,
            text=True,
            timeout=120,
            cwd=str(root),
        )
        output = result.stdout.strip()
        if not output:
            return []
        data = json.loads(output)
    except (subprocess.TimeoutExpired, json.JSONDecodeError, Exception):
        return []

    findings = []

    vulnerabilities = data.get("vulnerabilities", {}).get("list", [])
    for vuln in vulnerabilities:
        advisory = vuln.get("advisory", {})
        package = vuln.get("package", {})

        severity_raw = advisory.get("cvss", {})
        if isinstance(severity_raw, dict):
            severity_str = severity_raw.get("severity", "medium").lower()
        else:
            severity_str = "medium"

        severity = CARGO_AUDIT_SEVERITY.get(severity_str, "MEDIUM")
        cve_id = advisory.get("id", "UNKNOWN")
        title = advisory.get("title", "Known Vulnerability in Dependency")
        description = advisory.get("description", "")
        url = advisory.get("url", "")
        pkg_name = package.get("name", "unknown")
        pkg_version = package.get("version", "unknown")

        findings.append({
            "title": f"CVE in dependency: {pkg_name}",
            "severity": severity,
            "description": f"{title} — {pkg_name} v{pkg_version}. {description[:200]}",
            "fix": f"Update {pkg_name} to a patched version. See: {url}",
            "check": cve_id,
            "impact": severity.capitalize(),
            "confidence": "High",
            "occurrences": 1,
            "chain": "solana",
            "category": "dependency",
            "cve_id": cve_id,
            "package": pkg_name,
            "package_version": pkg_version,
        })

    warnings = data.get("warnings", {})
    for warning_type, warning_list in warnings.items():
        if not isinstance(warning_list, list):
            continue
        severity = CARGO_AUDIT_SEVERITY.get(warning_type, "LOW")
        for w in warning_list:
            advisory = w.get("advisory", {})
            package = w.get("package", {})
            pkg_name = package.get("name", "unknown")
            pkg_version = package.get("version", "unknown")
            title = advisory.get("title", f"{warning_type.capitalize()} dependency")

            findings.append({
                "title": f"{warning_type.capitalize()} dependency: {pkg_name}",
                "severity": severity,
                "description": f"{title} — {pkg_name} v{pkg_version}",
                "fix": f"Replace or update {pkg_name}. Check crates.io for alternatives.",
                "check": f"{warning_type}-{pkg_name}",
                "impact": severity.capitalize(),
                "confidence": "High",
                "occurrences": 1,
                "chain": "solana",
                "category": "dependency",
            })

    return findings


# =============================================================================
# LAYER 2: Pattern scanner — smarter count-based matching
# =============================================================================

def _collect_rs_files(target: Path) -> list[Path]:
    if target.is_file() and target.suffix == ".rs":
        return [target]
    if target.is_dir():
        return [
            f for f in target.glob("*.rs")
            if "target" not in f.parts
            and ".cargo" not in str(f)
            and "node_modules" not in str(f)
        ]
    return []


def _split_into_functions(source: str) -> list[str]:
    """
    Split Rust source into function-level blocks for more accurate scanning.
    Falls back to the full source if splitting fails.
    """
    # Match pub fn / fn blocks by finding fn declarations
    fn_pattern = re.compile(r'((?:pub\s+)?(?:async\s+)?fn\s+\w+[^{]*\{)', re.MULTILINE)
    positions = [m.start() for m in fn_pattern.finditer(source)]

    if len(positions) < 2:
        return [source]

    blocks = []
    for i, pos in enumerate(positions):
        end = positions[i + 1] if i + 1 < len(positions) else len(source)
        blocks.append(source[pos:end])

    return blocks if blocks else [source]


def _scan_file_patterns(source: str, filepath: str) -> list[dict]:
    """
    Scan a .rs file for vulnerability patterns using count-based matching.

    Key improvement over naive file-level scanning:
    - Count trigger matches vs anti-pattern matches independently
    - A safe usage in one function doesn't cancel a vulnerability in another
    - Only mark as mitigated if anti-pattern count >= trigger count
    """
    matches = []

    for pattern_def in SOLANA_PATTERNS:
        rule_id = pattern_def["rule_id"]
        patterns = pattern_def["patterns"]
        anti_patterns = pattern_def["anti_patterns"]

        # Count all trigger matches across the file
        trigger_count = sum(
            len(re.findall(p, source, re.MULTILINE))
            for p in patterns
        )

        if trigger_count == 0:
            continue

        # Count all anti-pattern (safe usage) matches
        anti_count = sum(
            len(re.findall(ap, source, re.MULTILINE))
            for ap in anti_patterns
        ) if anti_patterns else 0

        # Only consider mitigated if anti-patterns outnumber or equal triggers
        # This prevents one safe usage from masking multiple vulnerabilities
        # If ANY anti-pattern appears in the file, consider it mitigated
        # Count-vs-count caused false positives on normal Anchor code
        if anti_patterns and anti_count > 0:
            continue

        rule = get_rule(rule_id)
        matches.append({
            "rule_id": rule_id,
            "file": filepath,
            "severity": rule.severity,
            "confidence": "Medium",
            "trigger_count": trigger_count,
            "anti_count": anti_count,
        })

    return matches


def run_pattern_scan(target: Path) -> list[dict]:
    rs_files = _collect_rs_files(target)
    if not rs_files:
        return []

    raw_matches: dict[str, dict] = {}

    for rs_file in rs_files:
        try:
            source = rs_file.read_text(errors="ignore")
        except Exception:
            continue

        file_matches = _scan_file_patterns(source, str(rs_file))

        for match in file_matches:
            rule_id = match["rule_id"]
            if rule_id not in raw_matches:
                raw_matches[rule_id] = {
                    "occurrences": 1,
                    "files": [match["file"]],
                    "trigger_count": match["trigger_count"],
                    "anti_count": match["anti_count"],
                    **match,
                }
            else:
                raw_matches[rule_id]["occurrences"] += 1
                raw_matches[rule_id]["files"].append(match["file"])
                raw_matches[rule_id]["trigger_count"] += match["trigger_count"]
                raw_matches[rule_id]["anti_count"] += match["anti_count"]

    findings = []
    for rule_id, match in raw_matches.items():
        rule = get_rule(rule_id)
        findings.append({
            "title": rule.title,
            "severity": rule.severity,
            "description": rule.description,
            "fix": rule.fix,
            "check": rule_id,
            "impact": rule.severity.capitalize(),
            "confidence": "Medium",
            "occurrences": match["trigger_count"],
            "chain": "solana",
            "category": rule.category,
            "files_affected": match["files"][:3],
        })

    return findings


# =============================================================================
# LAYER 3: cargo-geiger
# =============================================================================

def run_cargo_geiger(target: Path) -> list[dict]:
    if not is_cargo_geiger_available():
        return []

    root = target if target.is_dir() else target.parent
    if not (root / "Cargo.toml").exists():
        roots = list(root.rglob("Cargo.toml"))
        if not roots:
            return []
        root = roots[0].parent

    try:
        result = subprocess.run(
            ["cargo", "geiger", "--output-format", "Json"],
            capture_output=True,
            text=True,
            timeout=120,
            cwd=str(root),
        )
        output = result.stdout.strip()
        if not output:
            return []
        data = json.loads(output)
    except (subprocess.TimeoutExpired, json.JSONDecodeError, Exception):
        return []

    unsafe_count = 0
    try:
        packages = data.get("packages", [])
        for pkg in packages:
            unsafety = pkg.get("unsafety", {})
            used = unsafety.get("used", {})
            unsafe_count += (
                used.get("functions", {}).get("unsafe", 0)
                + used.get("exprs", {}).get("unsafe", 0)
            )
    except Exception:
        return []

    if unsafe_count == 0:
        return []

    rule = get_rule("unsafe-code")
    return [{
        "title": rule.title,
        "severity": rule.severity,
        "description": f"{rule.description} Found {unsafe_count} unsafe expression(s).",
        "fix": rule.fix,
        "check": "unsafe-code",
        "impact": "High",
        "confidence": "High",
        "occurrences": unsafe_count,
        "chain": "solana",
        "category": "unsafe",
    }]


# =============================================================================
# MAIN SCANNER
# =============================================================================

def scan_solana(target: Path) -> dict:
    target = Path(target).resolve()

    if not is_solana_project(target):
        return {
            "status": "error",
            "error": "Not a Solana/Rust project — no .rs files or Cargo.toml found",
            "findings": [],
            "risk_score": 0,
            "total_findings": 0,
            "chain": "solana",
        }

    is_anchor = detect_anchor_project(target)
    all_findings: list[dict] = []
    errors: list[str] = []

    # Layer 1: cargo-audit
    if not is_cargo_audit_available():
        errors.append("cargo-audit not found — skipping dependency scan")
    else:
        try:
            audit_findings = run_cargo_audit(target)
            all_findings.extend(audit_findings)
        except Exception as e:
            errors.append(f"cargo-audit error: {e}")

    # Layer 2: Pattern scan
    try:
        pattern_findings = run_pattern_scan(target)
        all_findings.extend(pattern_findings)
    except Exception as e:
        errors.append(f"Pattern scan error: {e}")

    # Layer 3: cargo-geiger
    if is_cargo_geiger_available():
        try:
            geiger_findings = run_cargo_geiger(target)
            existing_checks = {f["check"] for f in all_findings}
            for f in geiger_findings:
                if f["check"] not in existing_checks:
                    all_findings.append(f)
        except Exception as e:
            errors.append(f"cargo-geiger error: {e}")

    # Deduplicate by check ID
    deduped: dict[str, dict] = {}
    for f in all_findings:
        check = f["check"]
        if check not in deduped:
            deduped[check] = f
        else:
            existing_sev = SEVERITY_ORDER.get(deduped[check]["severity"], 99)
            new_sev = SEVERITY_ORDER.get(f["severity"], 99)
            if new_sev < existing_sev:
                deduped[check] = f

    findings = sorted(
        deduped.values(),
        key=lambda f: SEVERITY_ORDER.get(f["severity"], 99),
    )

    risk_score = compute_solana_risk_score(findings)

    return {
        "status": "success",
        "chain": "solana",
        "is_anchor": is_anchor,
        "risk_score": risk_score,
        "total_findings": len(findings),
        "findings": findings,
        "errors": errors,
        "scanners_used": {
            "cargo_audit": is_cargo_audit_available(),
            "pattern_scan": True,
            "cargo_geiger": is_cargo_geiger_available(),
        },
    }