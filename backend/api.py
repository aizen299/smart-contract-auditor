from fastapi import FastAPI, UploadFile, File, HTTPException, Response
from fastapi.middleware.cors import CORSMiddleware
import subprocess
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
REPORTS_DIR = os.path.join(BASE_DIR, "reports")

os.makedirs(TEMP_DIR, exist_ok=True)

MAX_FILE_SIZE = 500 * 1024       # 500KB per .sol
MAX_ZIP_SIZE = 5 * 1024 * 1024   # 5MB zip
MAX_SOL_FILES = 20               # max contracts per zip
MAX_RS_FILES = 20                # max Rust files per zip
MAX_RS_SIZE = 1024 * 1024        # 1MB per .rs file


def is_valid_solidity(content: bytes) -> bool:
    try:
        text = content.decode("utf-8")
        return "pragma solidity" in text or "contract " in text or "interface " in text or "library " in text
    except UnicodeDecodeError:
        return False


def is_valid_rust(content: bytes) -> bool:
    try:
        text = content.decode("utf-8")
        return (
            "fn " in text
            or "use anchor_lang" in text
            or "use solana_program" in text
            or "pub mod" in text
            or "#[program]" in text
        )
    except UnicodeDecodeError:
        return False


def run_scan(contract_path: str, scan_id: str) -> dict:
    result = subprocess.run(
        ["python", "-m", "src.chainaudit.main", "--target", contract_path, "--scan-id", scan_id],
        cwd=BASE_DIR,
        capture_output=True,
        text=True,
        timeout=120,
    )
    if result.returncode != 0:
        return None

    report_path = os.path.join(REPORTS_DIR, f"{scan_id}.json")
    if not os.path.exists(report_path):
        return None

    with open(report_path) as f:
        return json.load(f)


@app.get("/")
async def root():
    return {"status": "ok", "service": "ChainAudit API"}


@app.get("/health")
async def health():
    return {"status": "healthy"}


@app.head("/health")
async def health_head():
    return Response(status_code=200)


@app.post("/scan")
async def scan_contract(file: UploadFile = File(...)):
    if not file.filename or not file.filename.endswith(".sol"):
        raise HTTPException(
            status_code=400,
            detail="Invalid file type. Only .sol (Solidity) files are accepted."
        )

    content = await file.read()

    if len(content) == 0:
        raise HTTPException(status_code=400, detail="File is empty.")

    if len(content) > MAX_FILE_SIZE:
        raise HTTPException(
            status_code=400,
            detail=f"File too large. Maximum size is {MAX_FILE_SIZE // 1024}KB."
        )

    if not is_valid_solidity(content):
        raise HTTPException(
            status_code=400,
            detail="File does not appear to be valid Solidity."
        )

    scan_id = str(uuid.uuid4())
    scan_dir = os.path.join(TEMP_DIR, scan_id)
    os.makedirs(scan_dir, exist_ok=True)
    contract_path = os.path.join(scan_dir, "input.sol")

    try:
        with open(contract_path, "wb") as f:
            f.write(content)

        report = run_scan(contract_path, scan_id)
        if report is None:
            raise HTTPException(
                status_code=422,
                detail="Could not analyse contract. It may contain syntax errors or use an unsupported Solidity version."
            )
        return report

    except subprocess.TimeoutExpired:
        raise HTTPException(
            status_code=408,
            detail="Scan timed out. Contract may be too large or complex."
        )
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=500, detail="Unexpected error during scan.")
    finally:
        if os.path.exists(scan_dir):
            shutil.rmtree(scan_dir)


@app.post("/scan/rust")
async def scan_rust(file: UploadFile = File(...)):
    if not file.filename or not file.filename.endswith(".rs"):
        raise HTTPException(
            status_code=400,
            detail="Invalid file type. Only .rs (Rust) files are accepted."
        )

    content = await file.read()

    if len(content) == 0:
        raise HTTPException(status_code=400, detail="File is empty.")

    if len(content) > MAX_RS_SIZE:
        raise HTTPException(
            status_code=400,
            detail=f"File too large. Maximum size is {MAX_RS_SIZE // 1024}KB."
        )

    if not is_valid_rust(content):
        raise HTTPException(
            status_code=400,
            detail="File does not appear to be valid Rust/Solana code."
        )

    scan_id = str(uuid.uuid4())
    scan_dir = os.path.join(TEMP_DIR, scan_id)
    os.makedirs(scan_dir, exist_ok=True)
    rs_path = Path(scan_dir) / file.filename

    try:
        rs_path.write_bytes(content)

        from src.chainaudit.solana_scanner import scan_solana
        report = scan_solana(rs_path)

        if report.get("status") == "error":
            raise HTTPException(
                status_code=422,
                detail=report.get("error", "Could not analyse Rust file.")
            )

        report["scan_id"] = scan_id
        report["file_name"] = file.filename
        return report

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Unexpected error during scan: {str(e)}")
    finally:
        if os.path.exists(scan_dir):
            shutil.rmtree(scan_dir)


@app.post("/scan/zip")
async def scan_zip(file: UploadFile = File(...)):
    if not file.filename or not file.filename.endswith(".zip"):
        raise HTTPException(
            status_code=400,
            detail="Invalid file type. Only .zip files are accepted."
        )

    content = await file.read()

    if len(content) == 0:
        raise HTTPException(status_code=400, detail="File is empty.")

    if len(content) > MAX_ZIP_SIZE:
        raise HTTPException(
            status_code=400,
            detail=f"Zip too large. Maximum size is {MAX_ZIP_SIZE // (1024*1024)}MB."
        )

    try:
        zf = zipfile.ZipFile(io.BytesIO(content))
    except zipfile.BadZipFile:
        raise HTTPException(status_code=400, detail="Invalid zip file.")

    # Detect file types in zip
    sol_names = [
        name for name in zf.namelist()
        if name.endswith(".sol")
        and not name.startswith("__MACOSX")
        and "node_modules" not in name
        and "/lib/" not in name
        and "/test/" not in name
        and "/mock/" not in name
        and "/mocks/" not in name
        and not os.path.basename(name).startswith(".")
    ]
    rs_names = [
        name for name in zf.namelist()
        if name.endswith(".rs")
        and not name.startswith("__MACOSX")
        and "target/" not in name
        and not os.path.basename(name).startswith(".")
    ]

    has_sol = len(sol_names) > 0
    has_rs = len(rs_names) > 0

    if not has_sol and not has_rs:
        raise HTTPException(
            status_code=400,
            detail="No Solidity or Rust files found in the zip."
        )

    if len(sol_names) > MAX_SOL_FILES:
        raise HTTPException(
            status_code=400,
            detail=f"Too many Solidity files. Maximum is {MAX_SOL_FILES} .sol files per zip."
        )

    if len(rs_names) > MAX_RS_FILES:
        raise HTTPException(
            status_code=400,
            detail=f"Too many Rust files. Maximum is {MAX_RS_FILES} .rs files per zip."
        )

    scan_id = str(uuid.uuid4())
    scan_dir = os.path.join(TEMP_DIR, scan_id)
    os.makedirs(scan_dir, exist_ok=True)

    results = []
    all_findings = []
    total_risk = 0

    try:
        # --- Solidity files ---
        for sol_name in sol_names:
            file_content = zf.read(sol_name)

            if not is_valid_solidity(file_content):
                results.append({
                    "file": os.path.basename(sol_name),
                    "status": "skipped",
                    "reason": "Not valid Solidity",
                    "risk_score": 0,
                    "findings": [],
                })
                continue

            file_scan_id = f"{scan_id}_{len(results)}"
            file_scan_dir = os.path.join(scan_dir, f"file_{len(results)}")
            os.makedirs(file_scan_dir, exist_ok=True)
            contract_path = os.path.join(file_scan_dir, "input.sol")

            with open(contract_path, "wb") as f:
                f.write(file_content)

            try:
                report = run_scan(contract_path, file_scan_id)
                if report is None:
                    results.append({
                        "file": os.path.basename(sol_name),
                        "status": "error",
                        "reason": "Slither could not analyse this file",
                        "risk_score": 0,
                        "findings": [],
                    })
                else:
                    results.append({
                        "file": os.path.basename(sol_name),
                        "status": "success",
                        "risk_score": report["risk_score"],
                        "total_findings": report["total_findings"],
                        "findings": report["findings"],
                    })
                    all_findings.extend(report["findings"])
                    total_risk = max(total_risk, report["risk_score"])

            except subprocess.TimeoutExpired:
                results.append({
                    "file": os.path.basename(sol_name),
                    "status": "timeout",
                    "reason": "Scan timed out",
                    "risk_score": 0,
                    "findings": [],
                })

        # --- Rust files — scan each file individually ---
        if has_rs:
            from src.chainaudit.solana_scanner import scan_solana

            rs_extract_dir = os.path.join(scan_dir, "rust_files")
            os.makedirs(rs_extract_dir, exist_ok=True)

            for rs_name in rs_names:
                rs_content = zf.read(rs_name)
                rs_basename = os.path.basename(rs_name)
                rs_file_path = Path(rs_extract_dir) / rs_basename
                rs_file_path.write_bytes(rs_content)

                if not is_valid_rust(rs_content):
                    results.append({
                        "file": rs_basename,
                        "status": "skipped",
                        "reason": "Not valid Rust/Solana code",
                        "chain": "solana",
                        "risk_score": 0,
                        "findings": [],
                    })
                    continue

                try:
                    rs_report = scan_solana(rs_file_path)
                    results.append({
                        "file": rs_basename,
                        "status": rs_report.get("status", "success"),
                        "chain": "solana",
                        "is_anchor": rs_report.get("is_anchor", False),
                        "risk_score": rs_report.get("risk_score", 0),
                        "total_findings": rs_report.get("total_findings", 0),
                        "findings": rs_report.get("findings", []),
                    })
                    all_findings.extend(rs_report.get("findings", []))
                    total_risk = max(total_risk, rs_report.get("risk_score", 0))
                except Exception as e:
                    results.append({
                        "file": rs_basename,
                        "status": "error",
                        "reason": f"Solana scanner error: {str(e)}",
                        "chain": "solana",
                        "risk_score": 0,
                        "findings": [],
                    })

        return {
            "scan_id": scan_id,
            "type": "multi",
            "total_files": len(sol_names) + len(rs_names),
            "scanned": len([r for r in results if r["status"] == "success"]),
            "overall_risk_score": total_risk,
            "total_findings": len(all_findings),
            "has_solana": has_rs,
            "has_evm": has_sol,
            "files": results,
        }

    finally:
        if os.path.exists(scan_dir):
            shutil.rmtree(scan_dir)