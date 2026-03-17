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


@app.post("/scan")
async def scan_contract(file: UploadFile = File(...)):
    scan_id = str(uuid.uuid4())

    scan_dir = os.path.join(TEMP_DIR, scan_id)
    os.makedirs(scan_dir, exist_ok=True)

    contract_path = os.path.join(scan_dir, "input.sol")

    try:
        with open(contract_path, "wb") as f:
            f.write(await file.read())

        result = subprocess.run(
            ["python", "-m", "src.main", "--target", contract_path, "--scan-id", scan_id],
            cwd=BASE_DIR,
            capture_output=True,
            text=True,
        )

        if result.returncode != 0:
            raise HTTPException(status_code=500, detail=result.stderr)

        report_path = os.path.join(REPORTS_DIR, f"{scan_id}.json")

        if not os.path.exists(report_path):
            raise HTTPException(status_code=500, detail="Report missing")

        with open(report_path) as f:
            return json.load(f)

    finally:
        if os.path.exists(scan_dir):
            shutil.rmtree(scan_dir)