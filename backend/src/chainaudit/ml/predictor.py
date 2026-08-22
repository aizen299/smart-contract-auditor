# backend/ml/predictor.py
import logging
from pathlib import Path
import joblib
import pandas as pd
import numpy as np

MODEL_PATH = Path(__file__).resolve().parent / "exploitability_model.joblib"

from .mapping import (  # noqa: E402
    CHECK_TO_INT,
    CONFIDENCE_TO_INT,
    IMPACT_TO_INT,
    SEVERITY_FROM_INT,
)


log = logging.getLogger("chainaudit.ml")


class ExploitabilityPredictor:
    def __init__(self):
        self._model = None
        self._load_failed = False

    def _load(self):
        """
        Load the model once, reporting failure rather than hiding it.

        Callers wrap prediction in a bare `except`, so an unloadable model would
        otherwise turn every finding's exploitability into "unknown" with no
        signal anywhere — the advertised ML feature silently absent. The most
        likely cause is a scikit-learn version that cannot unpickle an artifact
        trained under a different one, which is why the installed version is
        included in the message.
        """
        if self._model is not None or self._load_failed:
            return

        if not MODEL_PATH.exists():
            self._load_failed = True
            log.warning(
                "Exploitability model missing at %s — ML predictions disabled.",
                MODEL_PATH,
            )
            return

        try:
            self._model = joblib.load(MODEL_PATH)
        except Exception as exc:
            self._load_failed = True
            try:
                import sklearn
                sklearn_version = sklearn.__version__
            except Exception:
                sklearn_version = "unknown"
            log.warning(
                "Could not load exploitability model (%s: %s). ML predictions "
                "disabled. Installed scikit-learn is %s; the model artifact may "
                "have been trained under a different version.",
                type(exc).__name__, exc, sklearn_version,
            )

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
            "exploitability": SEVERITY_FROM_INT.get(pred, "LOW"),
            "confidence": round(confidence, 2),
        }


# Singleton
predictor = ExploitabilityPredictor()
