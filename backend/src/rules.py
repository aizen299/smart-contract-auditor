from dataclasses import dataclass
from typing import Dict


@dataclass
class Rule:
    id: str
    title: str
    severity: str
    description: str
    fix: str


# =========================
# RULE DEFINITIONS (BRAIN)
# =========================
RULES: Dict[str, Rule] = {
    "reentrancy": Rule(
        id="reentrancy",
        title="Reentrancy",
        severity="CRITICAL",
        description="External call before updating state can allow attacker to re-enter and drain funds.",
        fix="Use Checks-Effects-Interactions pattern, add reentrancy guard, and update state before external calls."
    ),
    "tx-origin": Rule(
        id="tx-origin",
        title="tx.origin Authentication",
        severity="HIGH",
        description="Using tx.origin for authentication is insecure.",
        fix="Use msg.sender instead of tx.origin."
    ),
    "unchecked-lowlevel": Rule(
        id="unchecked-lowlevel",
        title="Unchecked Low-level Call",
        severity="HIGH",
        description="Low-level call return value is not checked.",
        fix="Always check return value or use safe abstractions."
    ),
    "access-control": Rule(
        id="access-control",
        title="Access Control Issue",
        severity="HIGH",
        description="Critical functions lack proper access control.",
        fix="Use onlyOwner or role-based access control."
    ),
    "arbitrary-send-eth": Rule(
        id="arbitrary-send-eth",
        title="Arbitrary ETH Send",
        severity="HIGH",
        description="Contract allows sending ETH to arbitrary addresses.",
        fix="Restrict destination addresses and validate inputs."
    ),
    "weak-prng": Rule(
        id="weak-prng",
        title="Weak Randomness",
        severity="HIGH",
        description="Using block variables for randomness is predictable.",
        fix="Use Chainlink VRF or commit-reveal."
    ),
    "controlled-delegatecall": Rule(
        id="controlled-delegatecall",
        title="Controlled Delegatecall",
        severity="CRITICAL",
        description="User-controlled delegatecall enables arbitrary execution.",
        fix="Avoid delegatecall or strictly validate target."
    ),
    "unchecked-transfer": Rule(
        id="unchecked-transfer",
        title="Unchecked Token Transfer",
        severity="HIGH",
        description="Return value of ERC-20 transfer/transferFrom is not checked. Non-standard tokens can silently fail.",
        fix="Use OpenZeppelin's SafeERC20 library (safeTransfer, safeTransferFrom)."
    ),
    "timestamp": Rule(
        id="timestamp",
        title="Timestamp Dependence",
        severity="MEDIUM",
        description="block.timestamp can be manipulated by miners.",
        fix="Avoid relying on timestamp for critical logic."
    ),
    "unchecked-send": Rule(
        id="unchecked-send",
        title="Unchecked Send",
        severity="MEDIUM",
        description="send() return value not checked.",
        fix="Check return value or use call()."
    ),
    "missing-zero-check": Rule(
        id="missing-zero-check",
        title="Missing Zero Address Check",
        severity="LOW",
        description="Missing validation for zero address.",
        fix="Add require(address != address(0))."
    ),
    "suicidal": Rule(
        id="suicidal",
        title="Selfdestruct Risk",
        severity="HIGH",
        description="Contract can be destroyed by arbitrary user.",
        fix="Restrict selfdestruct access."
    ),
    "incorrect-equality": Rule(
        id="incorrect-equality",
        title="Incorrect Equality Check",
        severity="LOW",
        description="Improper equality comparison.",
        fix="Review comparison logic."
    ),
    "events-access": Rule(
        id="events-access",
        title="Missing Access Control Event",
        severity="LOW",
        description="State-changing access control functions do not emit events, making off-chain monitoring blind.",
        fix="Emit events on all ownership transfers and role changes."
    ),
    "events-maths": Rule(
        id="events-maths",
        title="Missing Arithmetic Event",
        severity="LOW",
        description="Functions that change critical numeric state (rates, limits) emit no events.",
        fix="Add events for all state-changing math operations like setRewardRate()."
    ),
}


# =========================
# SLITHER → RULE MAPPING
# =========================
SLITHER_TO_RULE = {
    # Core reentrancy
    "reentrancy": "reentrancy",
    "reentrancy-eth": "reentrancy",
    "reentrancy-no-eth": "reentrancy",
    "reentrancy-benign": "reentrancy",
    "reentrancy-events": "reentrancy",

    # tx.origin
    "tx-origin": "tx-origin",
    "tx-origin-usage": "tx-origin",

    # Low-level / unchecked calls
    "unchecked-call": "unchecked-lowlevel",
    "low-level-call": "unchecked-lowlevel",
    "low-level-calls": "unchecked-lowlevel",
    "unchecked-lowlevel": "unchecked-lowlevel",
    "calls-loop": "unchecked-lowlevel",

    # Token transfers
    "unchecked-transfer": "unchecked-transfer",

    # Access control
    "missing-auth": "access-control",
    "unprotected-function": "access-control",
    "msg-value-loop": "access-control",
    "constable-states": "access-control",

    # Extended
    "arbitrary-send-eth": "arbitrary-send-eth",
    "weak-prng": "weak-prng",
    "controlled-delegatecall": "controlled-delegatecall",
    "timestamp": "timestamp",
    "unchecked-send": "unchecked-send",
    "missing-zero-check": "missing-zero-check",
    "suicidal": "suicidal",
    "incorrect-equality": "incorrect-equality",

    # Events
    "events-access": "events-access",
    "events-maths": "events-maths",
}


# =========================
# SCORING ENGINE
# =========================
SEVERITY_SCORES = {
    "CRITICAL": 40,
    "HIGH": 25,
    "MEDIUM": 15,
    "LOW": 5,
}

CONFIDENCE_WEIGHT = {
    "High": 1.0,
    "Medium": 0.7,
    "Low": 0.4,
}


# =========================
# DEFAULT FALLBACK
# =========================
DEFAULT_RULE = Rule(
    id="unknown",
    title="Unclassified Vulnerability",
    severity="LOW",
    description="This issue is not yet mapped to a known rule.",
    fix="Investigate manually and extend rules if needed."
)


def normalize_check(check: str) -> str:
    return check.lower().strip() if check else ""


def map_finding(check: str) -> Rule:
    check = normalize_check(check)

    # 1. Exact match
    if check in SLITHER_TO_RULE:
        return RULES.get(SLITHER_TO_RULE[check], DEFAULT_RULE)

    # 2. Fuzzy match
    for key in SLITHER_TO_RULE:
        if key in check:
            return RULES.get(SLITHER_TO_RULE[key], DEFAULT_RULE)

    return DEFAULT_RULE


def compute_risk_score(findings: list[dict]) -> int:
    score = 0

    for f in findings:
        sev = f.get("severity", "LOW").upper()
        conf = f.get("confidence", "Medium")

        base = SEVERITY_SCORES.get(sev, 0)
        weight = CONFIDENCE_WEIGHT.get(conf, 0.7)

        score += base * weight

    return min(int(score * 0.7), 100)