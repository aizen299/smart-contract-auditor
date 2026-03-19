# backend/ml/train.py
import json
import re
import subprocess
import os
from pathlib import Path
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import joblib

BASE_DIR = Path(__file__).resolve().parent.parent
SMARTBUGS_DIR = Path(__file__).resolve().parent.parent.parent / "ml" / "smartbugs" / "dataset"
REPORTS_DIR = BASE_DIR / "reports" / "ml_training"
MODEL_DIR = BASE_DIR / "ml"
SLITHER_JSON = REPORTS_DIR / "slither_tmp.json"

CATEGORY_TO_SEVERITY = {
    "reentrancy": "CRITICAL",
    "access_control": "HIGH",
    "arithmetic": "HIGH",
    "bad_randomness": "HIGH",
    "unchecked_low_level_calls": "HIGH",
    "time_manipulation": "MEDIUM",
    "denial_of_service": "MEDIUM",
    "front_running": "MEDIUM",
    "short_addresses": "LOW",
    "other": "LOW",
}

CHECK_TO_INT = {
    "reentrancy-eth": 0,
    "reentrancy-no-eth": 1,
    "reentrancy-benign": 2,
    "reentrancy-events": 3,
    "arbitrary-send-eth": 4,
    "controlled-delegatecall": 5,
    "suicidal": 6,
    "tx-origin": 7,
    "unchecked-transfer": 8,
    "unchecked-lowlevel": 9,
    "low-level-calls": 10,
    "weak-prng": 11,
    "timestamp": 12,
    "unchecked-send": 13,
    "incorrect-equality": 14,
    "missing-zero-check": 15,
    "events-access": 16,
    "events-maths": 17,
    "access-control": 18,
    "deprecated-standards": 19,
    "naming-convention": 20,
    "reentrancy-unlimited-gas": 21,
}

IMPACT_TO_INT = {"High": 3, "Medium": 2, "Low": 1, "Informational": 0, "Optimization": 0}
CONFIDENCE_TO_INT = {"High": 3, "Medium": 2, "Low": 1}
SEVERITY_TO_INT = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "LOW": 0}

INSTALLED_VERSIONS = set()


def get_pragma_version(contract_path: str) -> str:
    try:
        content = Path(contract_path).read_text(errors="ignore")
        match = re.search(r'pragma solidity\s+[\^>=<]*(\d+\.\d+\.\d+)', content)
        if match:
            return match.group(1)
    except Exception:
        pass
    return "0.8.24"


def switch_solc(version: str):
    if version in INSTALLED_VERSIONS:
        subprocess.run(["solc-select", "use", version], capture_output=True)
        return

    # Try to install if not available
    result = subprocess.run(
        ["solc-select", "use", version],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        subprocess.run(["solc-select", "install", version], capture_output=True)
        subprocess.run(["solc-select", "use", version], capture_output=True)

    INSTALLED_VERSIONS.add(version)


def run_slither(contract_path: str) -> list:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    if SLITHER_JSON.exists():
        SLITHER_JSON.unlink()

    # Switch to correct solc version
    version = get_pragma_version(contract_path)
    switch_solc(version)

    result = subprocess.run(
        ["slither", contract_path, "--json", str(SLITHER_JSON), "--detect", "all"],
        capture_output=True, text=True, timeout=60
    )

    if not SLITHER_JSON.exists():
        return []

    try:
        data = json.loads(SLITHER_JSON.read_text())
        return data.get("results", {}).get("detectors", [])
    except json.JSONDecodeError:
        return []


def extract_features(detector: dict, contract_size: int) -> dict:
    check = (detector.get("check") or "").lower().strip()
    return {
        "check_id": CHECK_TO_INT.get(check, -1),
        "impact": IMPACT_TO_INT.get(detector.get("impact", "Low"), 0),
        "confidence": CONFIDENCE_TO_INT.get(detector.get("confidence", "Medium"), 1),
        "contract_size": contract_size,
        "num_elements": len(detector.get("elements", [])),
    }


def build_dataset():
    rows = []

    for category_dir in SMARTBUGS_DIR.iterdir():
        if not category_dir.is_dir():
            continue

        category = category_dir.name
        true_severity = CATEGORY_TO_SEVERITY.get(category, "LOW")
        true_severity_int = SEVERITY_TO_INT[true_severity]

        sol_files = list(category_dir.rglob("*.sol"))
        print(f"Processing {category} — {len(sol_files)} contracts...")

        for sol_file in sol_files:
            contract_size = len(sol_file.read_text(encoding="utf-8", errors="ignore"))

            try:
                detectors = run_slither(str(sol_file))
            except Exception as e:
                print(f"  Skipping {sol_file.name}: {e}")
                continue

            if not detectors:
                rows.append({
                    "check_id": -1,
                    "impact": 0,
                    "confidence": 0,
                    "contract_size": contract_size,
                    "num_elements": 0,
                    "true_severity": 0,
                    "category": category,
                })
                continue

            for d in detectors:
                features = extract_features(d, contract_size)
                features["true_severity"] = true_severity_int
                features["category"] = category
                rows.append(features)

    return pd.DataFrame(rows)


def train():
    print("Building dataset from SmartBugs...")
    df = build_dataset()
    print(f"\nDataset size: {len(df)} samples")
    print(df["true_severity"].value_counts())

    if df["true_severity"].nunique() < 2:
        print("\nNot enough class diversity — check solc version switching")
        return None

    feature_cols = ["check_id", "impact", "confidence", "contract_size", "num_elements"]
    X = df[feature_cols].fillna(0)
    y = df["true_severity"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    print("\nTraining Random Forest...")
    clf = RandomForestClassifier(
        n_estimators=100,
        max_depth=10,
        random_state=42,
        class_weight="balanced",
    )
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    unique_classes = sorted(y_test.unique())
    label_names = {0: "LOW", 1: "MEDIUM", 2: "HIGH", 3: "CRITICAL"}
    target_names = [label_names[c] for c in unique_classes]

    print("\nClassification Report:")
    print(classification_report(y_test, y_pred,
        labels=unique_classes, target_names=target_names))

    print("\nFeature Importance:")
    for feat, imp in zip(feature_cols, clf.feature_importances_):
        print(f"  {feat}: {imp:.3f}")

    MODEL_DIR.mkdir(exist_ok=True)
    model_path = MODEL_DIR / "exploitability_model.joblib"
    joblib.dump(clf, model_path)
    print(f"\nModel saved to {model_path}")

    # Switch back to 0.8.24 for normal operation
    subprocess.run(["solc-select", "use", "0.8.24"], capture_output=True)
    print("Switched solc back to 0.8.24")

    return clf


if __name__ == "__main__":
    train()