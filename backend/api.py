from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import subprocess
import json
import os
import uuid
import shutil

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

MAX_FILE_SIZE = 500 * 1024  # 500KB


def is_valid_solidity(content: bytes) -> bool:
    try:
        text = content.decode("utf-8")
        return "pragma solidity" in text or "contract " in text or "interface " in text or "library " in text
    except UnicodeDecodeError:
        return False


@app.get("/")
async def root():
    return {"status": "ok", "service": "ChainAudit API"}


@app.get("/health")
async def health():
    return {"status": "healthy"}


@app.post("/scan")
async def scan_contract(file: UploadFile = File(...)):
    # Validate file extension
    if not file.filename or not file.filename.endswith(".sol"):
        raise HTTPException(
            status_code=400,
            detail="Invalid file type. Only .sol (Solidity) files are accepted."
        )

    content = await file.read()

    # Validate file size
    if len(content) == 0:
        raise HTTPException(status_code=400, detail="File is empty.")

    if len(content) > MAX_FILE_SIZE:
        raise HTTPException(
            status_code=400,
            detail=f"File too large. Maximum size is {MAX_FILE_SIZE // 1024}KB."
        )

    # Validate content looks like Solidity
    if not is_valid_solidity(content):
        raise HTTPException(
            status_code=400,
            detail="File does not appear to be valid Solidity. Make sure it contains a contract, interface, or library definition."
        )

    scan_id = str(uuid.uuid4())
    scan_dir = os.path.join(TEMP_DIR, scan_id)
    os.makedirs(scan_dir, exist_ok=True)
    contract_path = os.path.join(scan_dir, "input.sol")

    try:
        with open(contract_path, "wb") as f:
            f.write(content)

        result = subprocess.run(
            ["python", "-m", "src.main", "--target", contract_path, "--scan-id", scan_id],
            cwd=BASE_DIR,
            capture_output=True,
            text=True,
            timeout=120,  # 2 min timeout
        )

        if result.returncode != 0:
            # Slither failed — return clean error not raw stderr
            raise HTTPException(
                status_code=422,
                detail="Could not analyse contract. It may contain syntax errors or use an unsupported Solidity version."
            )

        report_path = os.path.join(REPORTS_DIR, f"{scan_id}.json")

        if not os.path.exists(report_path):
            raise HTTPException(
                status_code=500,
                detail="Scan completed but report was not generated. Please try again."
            )

        with open(report_path) as f:
            return json.load(f)

    except subprocess.TimeoutExpired:
        raise HTTPException(
            status_code=408,
            detail="Scan timed out. Contract may be too large or complex. Try splitting it into smaller files."
        )

    except HTTPException:
        raise

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Unexpected error during scan. Please try again."
        )

    finally:
        if os.path.exists(scan_dir):
            shutil.rmtree(scan_dir)