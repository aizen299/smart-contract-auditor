"""
Feature encodings and rule mappings shared by the ML model and its callers.

These tables were previously duplicated verbatim: the feature encodings in both
`predictor.py` and `train.py`, and the Solana mappings in both `cli.py` and
`scanner_router.py`. Divergence was silent and costly — a check missing from the
predictor's copy encodes as -1, so the model scores a feature vector it was never
trained on and every prediction quietly degrades. One definition, imported
everywhere, removes that failure mode.

Pure data with no imports, so both training and inference can depend on it.
"""

# Slither check name -> integer feature. Training and inference must agree
# exactly; an unknown check encodes as -1 (see predictor.CHECK_UNKNOWN).
CHECK_TO_INT: dict[str, int] = {
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

# The model was trained on title-case Slither levels ("High", not "HIGH").
IMPACT_TO_INT = {"High": 3, "Medium": 2, "Low": 1, "Informational": 0, "Optimization": 0}
CONFIDENCE_TO_INT = {"High": 3, "Medium": 2, "Low": 1}

# Inference direction: model class index -> severity label.
SEVERITY_FROM_INT = {0: "LOW", 1: "MEDIUM", 2: "HIGH", 3: "CRITICAL"}
# Training direction: severity label -> model class index.
SEVERITY_TO_INT = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}

# The model is EVM-only. Solana findings are scored by mapping each rule to the
# EVM check whose exploitability profile is closest; rules with no sensible
# analogue fall back to SEVERITY_CONFIDENCE below.
SOLANA_TO_EVM_CHECK: dict[str, str] = {
    "missing-signer-check":     "suicidal",
    "missing-owner-check":      "suicidal",
    "arbitrary-cpi":            "reentrancy-eth",
    "integer-overflow":         "integer-overflow",
    "unchecked-arithmetic":     "integer-overflow",
    "unsafe-code":              "assembly",
    "account-confusion":        "incorrect-equality",
    "reentrancy-cpi":           "reentrancy-eth",
    "insecure-randomness":      "weak-prng",
    "missing-rent-exemption":   "missing-zero-check",
    "unvalidated-account-data": "missing-zero-check",
    "missing-close-account":    "locked-ether",
    "pdas-not-validated":       "incorrect-equality",
    "missing-freeze-authority": "suicidal",
    "deprecated-anchor":        "naming-convention",
}

# Static confidence for Solana findings the model cannot score.
SEVERITY_CONFIDENCE = {
    "CRITICAL": 0.87,
    "HIGH":     0.74,
    "MEDIUM":   0.58,
    "LOW":      0.42,
}

__all__ = [
    "CHECK_TO_INT",
    "IMPACT_TO_INT",
    "CONFIDENCE_TO_INT",
    "SEVERITY_FROM_INT",
    "SEVERITY_TO_INT",
    "SOLANA_TO_EVM_CHECK",
    "SEVERITY_CONFIDENCE",
]
