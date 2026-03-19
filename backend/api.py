from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import subprocess
import json
import os
import uuid
import shutil
import zipfile
import io

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


def is_valid_solidity(content: bytes) -> bool:
    try:
        text = content.decode("utf-8")
        return "pragma solidity" in text or "contract " in text or "interface " in text or "library " in text
    except UnicodeDecodeError:
        return False


def run_scan(contract_path: str, scan_id: str) -> dict:
    result = subprocess.run(
        ["python", "-m", "src.main", "--target", contract_path, "--scan-id", scan_id],
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

    # Extract .sol files from zip
    try:
        zf = zipfile.ZipFile(io.BytesIO(content))
    except zipfile.BadZipFile:
        raise HTTPException(status_code=400, detail="Invalid zip file.")

    sol_files = [
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

    if len(sol_files) == 0:
        raise HTTPException(
            status_code=400,
            detail="No Solidity files found in the zip."
        )

    if len(sol_files) > MAX_SOL_FILES:
        raise HTTPException(
            status_code=400,
            detail=f"Too many files. Maximum is {MAX_SOL_FILES} .sol files per zip."
        )

    scan_id = str(uuid.uuid4())
    scan_dir = os.path.join(TEMP_DIR, scan_id)
    os.makedirs(scan_dir, exist_ok=True)

    results = []
    all_findings = []
    total_risk = 0

    try:
        for sol_name in sol_files:
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

        return {
            "scan_id": scan_id,
            "type": "multi",
            "total_files": len(sol_files),
            "scanned": len([r for r in results if r["status"] == "success"]),
            "overall_risk_score": total_risk,
            "total_findings": len(all_findings),
            "files": results,
        }

    finally:
        if os.path.exists(scan_dir):
            shutil.rmtree(scan_dir)