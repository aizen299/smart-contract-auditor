from fastapi import FastAPI, UploadFile, File, HTTPException, Response
from fastapi.middleware.cors import CORSMiddleware
import json
import os
import uuid
import shutil
import zipfile
import io
import tempfile
from pathlib import Path

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEMP_DIR = os.path.join(BASE_DIR, "tmp_scans")
os.makedirs(TEMP_DIR, exist_ok=True)

MAX_FILE_SIZE = 500 * 1024        # 500KB per .sol
MAX_ZIP_SIZE  = 5 * 1024 * 1024   # 5MB zip
MAX_SOL_FILES = 20
MAX_RS_FILES  = 20
MAX_RS_SIZE   = 1024 * 1024       # 1MB per .rs file



def is_valid_solidity(content: bytes) -> bool:
    try:
        text = content.decode("utf-8")
        return any(kw in text for kw in
                   ["pragma solidity", "contract ", "interface ", "library "])
    except UnicodeDecodeError:
        return False


def is_valid_rust(content: bytes) -> bool:
    try:
        text = content.decode("utf-8")
        return any(kw in text for kw in
                   ["fn ", "use anchor_lang", "use solana_program",
                    "pub mod", "#[program]"])
    except UnicodeDecodeError:
        return False


# ─────────────────────────────────────────────────────────────────────────────
# Core scan function — uses scanner_router for all EVM scans
# ─────────────────────────────────────────────────────────────────────────────

def run_scan(contract_path: str, scan_id: str) -> dict | None:
    """
    EVM scan via scanner_router.
    Returns result dict or None on failure.
    """
    try:
        import sys
        sys.path.insert(0, BASE_DIR)
        from src.chainaudit.scanner_router import route_scan
        result = route_scan(Path(contract_path))
        if result.get("status") == "error":
            return None
        result["scan_id"] = scan_id
        return result
    except Exception:
        return None


def run_solana_scan(rs_path: Path) -> dict:
    """Solana scan via scanner_router."""
    import sys
    sys.path.insert(0, BASE_DIR)
    from src.chainaudit.scanner_router import route_scan
    return route_scan(rs_path)


# ─────────────────────────────────────────────────────────────────────────────
# Health + info endpoints
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/")
async def root():
    return {"status": "ok", "service": "ChainAudit API"}


@app.head("/")
async def root_head():
    return Response(status_code=200)


@app.get("/health")
async def health():
    return {"status": "healthy"}


@app.head("/health")
async def health_head():
    return Response(status_code=200)


@app.get("/chains")
async def list_chains():
    """Return all supported chains."""
    from src.chainaudit.chain_registry import list_chains
    return {"chains": list_chains()}


# ─────────────────────────────────────────────────────────────────────────────
# /scan — single Solidity file
# ─────────────────────────────────────────────────────────────────────────────

@app.post("/scan")
async def scan_contract(file: UploadFile = File(...)):
    if not file.filename or not file.filename.endswith(".sol"):
        raise HTTPException(400, "Invalid file type. Only .sol files are accepted.")

    content = await file.read()

    if not content:
        raise HTTPException(400, "File is empty.")
    if len(content) > MAX_FILE_SIZE:
        raise HTTPException(400, f"File too large. Maximum is {MAX_FILE_SIZE // 1024}KB.")
    if not is_valid_solidity(content):
        raise HTTPException(400, "File does not appear to be valid Solidity.")

    scan_id  = str(uuid.uuid4())
    scan_dir = Path(TEMP_DIR) / scan_id
    scan_dir.mkdir(parents=True, exist_ok=True)
    contract_path = scan_dir / "input.sol"

    try:
        contract_path.write_bytes(content)
        report = run_scan(str(contract_path), scan_id)

        if report is None:
            raise HTTPException(
                422,
                "Could not analyse contract. It may contain syntax errors or "
                "use an unsupported Solidity version.",
            )

        report["file_name"] = file.filename
        return report

    except HTTPException:
        raise
    except Exception:
        raise HTTPException(500, "Unexpected error during scan.")
    finally:
        shutil.rmtree(scan_dir, ignore_errors=True)


# ─────────────────────────────────────────────────────────────────────────────
# /scan/rust — single Rust/Solana file
# ─────────────────────────────────────────────────────────────────────────────

@app.post("/scan/rust")
async def scan_rust(file: UploadFile = File(...)):
    if not file.filename or not file.filename.endswith(".rs"):
        raise HTTPException(400, "Invalid file type. Only .rs files are accepted.")

    content = await file.read()

    if not content:
        raise HTTPException(400, "File is empty.")
    if len(content) > MAX_RS_SIZE:
        raise HTTPException(400, f"File too large. Maximum is {MAX_RS_SIZE // 1024}KB.")
    if not is_valid_rust(content):
        raise HTTPException(400, "File does not appear to be valid Rust/Solana code.")

    scan_id  = str(uuid.uuid4())
    scan_dir = Path(TEMP_DIR) / scan_id
    scan_dir.mkdir(parents=True, exist_ok=True)
    rs_path  = scan_dir / file.filename

    try:
        rs_path.write_bytes(content)
        report = run_solana_scan(rs_path)

        if report.get("status") == "error":
            raise HTTPException(422, report.get("error", "Could not analyse Rust file."))

        report["scan_id"]   = scan_id
        report["file_name"] = file.filename
        return report

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, f"Unexpected error during scan: {e}")
    finally:
        shutil.rmtree(scan_dir, ignore_errors=True)


# ─────────────────────────────────────────────────────────────────────────────
# /scan/zip — zip of .sol and/or .rs files
# ─────────────────────────────────────────────────────────────────────────────

@app.post("/scan/zip")
async def scan_zip(file: UploadFile = File(...)):
    if not file.filename or not file.filename.endswith(".zip"):
        raise HTTPException(400, "Invalid file type. Only .zip files are accepted.")

    content = await file.read()

    if not content:
        raise HTTPException(400, "File is empty.")
    if len(content) > MAX_ZIP_SIZE:
        raise HTTPException(400, f"Zip too large. Maximum is {MAX_ZIP_SIZE // (1024*1024)}MB.")

    try:
        zf = zipfile.ZipFile(io.BytesIO(content))
    except zipfile.BadZipFile:
        raise HTTPException(400, "Invalid zip file.")

    sol_names = [
        n for n in zf.namelist()
        if n.endswith(".sol")
        and not n.startswith("__MACOSX")
        and "node_modules" not in n
        and "/lib/" not in n
        and "/test/" not in n
        and "/mock/" not in n
        and "/mocks/" not in n
        and not os.path.basename(n).startswith(".")
    ]
    rs_names = [
        n for n in zf.namelist()
        if n.endswith(".rs")
        and not n.startswith("__MACOSX")
        and "target/" not in n
        and not os.path.basename(n).startswith(".")
    ]

    if not sol_names and not rs_names:
        raise HTTPException(400, "No Solidity or Rust files found in the zip.")
    if len(sol_names) > MAX_SOL_FILES:
        raise HTTPException(400, f"Too many Solidity files. Maximum is {MAX_SOL_FILES}.")
    if len(rs_names) > MAX_RS_FILES:
        raise HTTPException(400, f"Too many Rust files. Maximum is {MAX_RS_FILES}.")

    scan_id  = str(uuid.uuid4())
    scan_dir = Path(TEMP_DIR) / scan_id
    scan_dir.mkdir(parents=True, exist_ok=True)

    results      = []
    all_findings = []
    total_risk   = 0

    try:
        # ── Solidity files ────────────────────────────────────────────────────
        for idx, sol_name in enumerate(sol_names):
            file_content = zf.read(sol_name)
            basename     = os.path.basename(sol_name)

            if not is_valid_solidity(file_content):
                results.append({
                    "file": basename, "status": "skipped",
                    "reason": "Not valid Solidity",
                    "risk_score": 0, "findings": [],
                })
                continue

            file_scan_id  = f"{scan_id}_{idx}"
            file_dir      = scan_dir / f"sol_{idx}"
            file_dir.mkdir(exist_ok=True)

            # FIX: save with original basename (not "input.sol") so that
            # detect_chain_from_file() can read the source content and
            # correctly identify the chain (Arbitrum, Optimism, etc.)
            contract_path = file_dir / basename
            contract_path.write_bytes(file_content)

            try:
                report = run_scan(str(contract_path), file_scan_id)
                if report is None:
                    results.append({
                        "file": basename, "status": "error",
                        "reason": "Slither could not analyse this file",
                        "risk_score": 0, "findings": [],
                    })
                else:
                    chain = report.get("chain", "ethereum")
                    entry = {
                        "file":           basename,
                        "status":         "success",
                        "chain":          chain,
                        "risk_score":     report["risk_score"],
                        "total_findings": report["total_findings"],
                        "findings":       report["findings"],
                    }
                    results.append(entry)
                    all_findings.extend(report["findings"])
                    total_risk = max(total_risk, report["risk_score"])

            except Exception:
                results.append({
                    "file": basename, "status": "timeout",
                    "reason": "Scan timed out",
                    "risk_score": 0, "findings": [],
                })

        # ── Rust files ────────────────────────────────────────────────────────
        if rs_names:
            rs_dir = scan_dir / "rust_files"
            rs_dir.mkdir(exist_ok=True)

            for rs_name in rs_names:
                rs_content  = zf.read(rs_name)
                rs_basename = os.path.basename(rs_name)
                rs_path     = rs_dir / rs_basename
                rs_path.write_bytes(rs_content)

                if not is_valid_rust(rs_content):
                    results.append({
                        "file": rs_basename, "status": "skipped",
                        "reason": "Not valid Rust/Solana code",
                        "chain": "solana", "risk_score": 0, "findings": [],
                    })
                    continue

                try:
                    isolated_dir = rs_dir / rs_basename.replace('.rs', '_scan')
                    isolated_dir.mkdir(exist_ok=True)
                    isolated_file = isolated_dir / rs_basename
                    isolated_file.write_bytes(rs_content)
                    rs_report = run_solana_scan(isolated_file)
                    results.append({
                        "file":           rs_basename,
                        "status":         rs_report.get("status", "success"),
                        "chain":          "solana",
                        "is_anchor":      rs_report.get("is_anchor", False),
                        "risk_score":     rs_report.get("risk_score", 0),
                        "total_findings": rs_report.get("total_findings", 0),
                        "findings":       rs_report.get("findings", []),
                    })
                    all_findings.extend(rs_report.get("findings", []))
                    total_risk = max(total_risk, rs_report.get("risk_score", 0))
                except Exception as e:
                    results.append({
                        "file": rs_basename, "status": "error",
                        "reason": f"Solana scanner error: {e}",
                        "chain": "solana", "risk_score": 0, "findings": [],
                    })

        return {
            "scan_id":            scan_id,
            "type":               "multi",
            "total_files":        len(sol_names) + len(rs_names),
            "scanned":            sum(1 for r in results if r["status"] == "success"),
            "overall_risk_score": total_risk,
            "total_findings":     len(all_findings),
            "has_solana":         bool(rs_names),
            "has_evm":            bool(sol_names),
            "files":              results,
        }

    finally:
        shutil.rmtree(scan_dir, ignore_errors=True)