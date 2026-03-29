# backend/ml/predictor.py
import re
from pathlib import Path
import joblib
import pandas as pd
import numpy as np

MODEL_PATH = Path(__file__).resolve().parent / "exploitability_model.joblib"

CHECK_TO_INT = {
    "reentrancy-eth": 0, "reentrancy-no-eth": 1, "reentrancy-benign": 2,
    "reentrancy-events": 3, "arbitrary-send-eth": 4, "controlled-delegatecall": 5,
    "suicidal": 6, "tx-origin": 7, "unchecked-transfer": 8, "unchecked-lowlevel": 9,
    "low-level-calls": 10, "weak-prng": 11, "timestamp": 12, "unchecked-send": 13,
    "incorrect-equality": 14, "missing-zero-check": 15, "events-access": 16,
    "events-maths": 17, "access-control": 18, "deprecated-standards": 19,
    "naming-convention": 20, "reentrancy-unlimited-gas": 21,
}

IMPACT_TO_INT = {"High": 3, "Medium": 2, "Low": 1, "Informational": 0, "Optimization": 0}
CONFIDENCE_TO_INT = {"High": 3, "Medium": 2, "Low": 1}
SEVERITY_TO_INT = {0: "LOW", 1: "MEDIUM", 2: "HIGH", 3: "CRITICAL"}


class ExploitabilityPredictor:
    def __init__(self):
        self._model = None

    def _load(self):
        if self._model is None and MODEL_PATH.exists():
            self._model = joblib.load(MODEL_PATH)

    def predict(self, finding: dict, contract_size: int) -> dict:
        self._load()

        if self._model is None:
            return {"exploitability": "unknown", "confidence": 0.0}

        check = (finding.get("check") or "").lower().strip()
        features = pd.DataFrame([{
    "check_id": CHECK_TO_INT.get(check, -1),
    "impact": IMPACT_TO_INT.get(finding.get("impact", "Low"), 0),
    "confidence": CONFIDENCE_TO_INT.get(finding.get("confidence", "Medium"), 1),
    "contract_size": contract_size,
    "num_elements": finding.get("occurrences", 1),
}])

        pred = self._model.predict(features)[0]
        proba = self._model.predict_proba(features)[0]
        confidence = float(np.max(proba))

        return {
            "exploitability": SEVERITY_TO_INT.get(pred, "LOW"),
            "confidence": round(confidence, 2),
        }


# Singleton
predictor = ExploitabilityPredictor()
