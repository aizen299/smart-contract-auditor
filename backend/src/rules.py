from dataclasses import dataclass, field
from typing import Dict


@dataclass
class CvssFactors:
    attack_vector: str        # "network" | "local"
    attack_complexity: str    # "low" | "high"
    privileges_required: str  # "none" | "low" | "high"
    user_interaction: str     # "none" | "required"
    confidentiality: str      # "high" | "low" | "none"
    integrity: str            # "high" | "low" | "none"
    availability: str         # "high" | "low" | "none"


@dataclass
class Rule:
    id: str
    title: str
    severity: str
    description: str
    fix: str
    cvss: CvssFactors = field(default_factory=lambda: CvssFactors(
        attack_vector="network",
        attack_complexity="low",
        privileges_required="none",
        user_interaction="none",
        confidentiality="low",
        integrity="low",
        availability="low",
    ))


# =========================
# CVSS WEIGHT TABLES
# =========================
AV_WEIGHT  = {"network": 1.0,  "local": 0.55}
AC_WEIGHT  = {"low": 1.0,      "high": 0.44}
PR_WEIGHT  = {"none": 1.0,     "low": 0.62,  "high": 0.27}
UI_WEIGHT  = {"none": 1.0,     "required": 0.62}
IMP_WEIGHT = {"high": 1.0,     "low": 0.5,   "none": 0.0}


def cvss_base_score(cvss: CvssFactors) -> float:
    exploitability = (
        8.22
        * AV_WEIGHT[cvss.attack_vector]
        * AC_WEIGHT[cvss.attack_complexity]
        * PR_WEIGHT[cvss.privileges_required]
        * UI_WEIGHT[cvss.user_interaction]
    )
    impact = 1 - (
        (1 - IMP_WEIGHT[cvss.confidentiality])
        * (1 - IMP_WEIGHT[cvss.integrity])
        * (1 - IMP_WEIGHT[cvss.availability])
    )
    if impact <= 0:
        return 0.0
    return round(min(1.4 * impact + exploitability, 10.0), 1)


# =========================
# RULE DEFINITIONS
# =========================
RULES: Dict[str, Rule] = {
    "reentrancy": Rule(
        id="reentrancy",
        title="Reentrancy",
        severity="CRITICAL",
        description="External call before updating state can allow attacker to re-enter and drain funds.",
        fix="Use Checks-Effects-Interactions pattern, add reentrancy guard, and update state before external calls.",
        cvss=CvssFactors(
            attack_vector="network", attack_complexity="low",
            privileges_required="none", user_interaction="none",
            confidentiality="high", integrity="high", availability="high",
        )
    ),
    "reentrancy-unlimited-gas": Rule(
        id="reentrancy-unlimited-gas",
        title="Reentrancy with Unlimited Gas",
        severity="CRITICAL",
        description="External call forwards unlimited gas, allowing a malicious contract to re-enter and execute complex logic.",
        fix="Use transfer() or send() which forward only 2300 gas, or add a reentrancy guard and follow the CEI pattern.",
        cvss=CvssFactors(
            attack_vector="network", attack_complexity="low",
            privileges_required="none", user_interaction="none",
            confidentiality="high", integrity="high", availability="high",
        )
    ),
    "controlled-delegatecall": Rule(
        id="controlled-delegatecall",
        title="Controlled Delegatecall",
        severity="CRITICAL",
        description="User-controlled delegatecall enables arbitrary execution.",
        fix="Avoid delegatecall or strictly validate target.",
        cvss=CvssFactors(
            attack_vector="network", attack_complexity="low",
            privileges_required="none", user_interaction="none",
            confidentiality="high", integrity="high", availability="high",
        )
    ),
    "arbitrary-send-eth": Rule(
        id="arbitrary-send-eth",
        title="Arbitrary ETH Send",
        severity="HIGH",
        description="Contract allows sending ETH to arbitrary addresses.",
        fix="Restrict destination addresses and validate inputs.",
        cvss=CvssFactors(
            attack_vector="network", attack_complexity="low",
            privileges_required="none", user_interaction="none",
            confidentiality="none", integrity="high", availability="high",
        )
    ),
    "suicidal": Rule(
        id="suicidal",
        title="Selfdestruct Risk",
        severity="HIGH",
        description="Contract can be destroyed by arbitrary user.",
        fix="Restrict selfdestruct access.",
        cvss=CvssFactors(
            attack_vector="network", attack_complexity="low",
            privileges_required="none", user_interaction="none",
            confidentiality="none", integrity="high", availability="high",
        )
    ),
    "tx-origin": Rule(
        id="tx-origin",
        title="tx.origin Authentication",
        severity="HIGH",
        description="Using tx.origin for authentication is insecure.",
        fix="Use msg.sender instead of tx.origin.",
        cvss=CvssFactors(
            attack_vector="network", attack_complexity="high",
            privileges_required="none", user_interaction="required",
            confidentiality="high", integrity="high", availability="none",
        )
    ),
    "unchecked-transfer": Rule(
        id="unchecked-transfer",
        title="Unchecked Token Transfer",
        severity="HIGH",
        description="Return value of ERC-20 transfer/transferFrom is not checked. Non-standard tokens can silently fail.",
        fix="Use OpenZeppelin's SafeERC20 library (safeTransfer, safeTransferFrom).",
        cvss=CvssFactors(
            attack_vector="network", attack_complexity="low",
            privileges_required="none", user_interaction="none",
            confidentiality="none", integrity="high", availability="low",
        )
    ),
    "unchecked-lowlevel": Rule(
        id="unchecked-lowlevel",
        title="Unchecked Low-level Call",
        severity="HIGH",
        description="Low-level call return value is not checked.",
        fix="Always check return value or use safe abstractions.",
        cvss=CvssFactors(
            attack_vector="network", attack_complexity="low",
            privileges_required="none", user_interaction="none",
            confidentiality="none", integrity="low", availability="low",
        )
    ),
    "weak-prng": Rule(
        id="weak-prng",
        title="Weak Randomness",
        severity="HIGH",
        description="Using block variables for randomness is predictable.",
        fix="Use Chainlink VRF or commit-reveal.",
        cvss=CvssFactors(
            attack_vector="network", attack_complexity="high",
            privileges_required="none", user_interaction="none",
            confidentiality="none", integrity="high", availability="none",
        )
    ),
    "access-control": Rule(
        id="access-control",
        title="Access Control Issue",
        severity="HIGH",
        description="Critical functions lack proper access control.",
        fix="Use onlyOwner or role-based access control.",
        cvss=CvssFactors(
            attack_vector="network", attack_complexity="low",
            privileges_required="none", user_interaction="none",
            confidentiality="low", integrity="high", availability="low",
        )
    ),
    "timestamp": Rule(
        id="timestamp",
        title="Timestamp Dependence",
        severity="MEDIUM",
        description="block.timestamp can be manipulated by miners.",
        fix="Avoid relying on timestamp for critical logic.",
        cvss=CvssFactors(
            attack_vector="network", attack_complexity="high",
            privileges_required="none", user_interaction="none",
            confidentiality="none", integrity="low", availability="none",
        )
    ),
    "unchecked-send": Rule(
        id="unchecked-send",
        title="Unchecked Send",
        severity="MEDIUM",
        description="send() return value not checked.",
        fix="Check return value or use call().",
        cvss=CvssFactors(
            attack_vector="network", attack_complexity="low",
            privileges_required="none", user_interaction="none",
            confidentiality="none", integrity="low", availability="low",
        )
    ),
    "deprecated-standards": Rule(
        id="deprecated-standards",
        title="Deprecated Solidity Standards",
        severity="MEDIUM",
        description="Contract uses deprecated Solidity features like throw, suicide, or block.blockhash.",
        fix="Replace deprecated functions with their modern equivalents.",
        cvss=CvssFactors(
            attack_vector="local", attack_complexity="low",
            privileges_required="none", user_interaction="none",
            confidentiality="none", integrity="low", availability="none",
        )
    ),
    "missing-zero-check": Rule(
        id="missing-zero-check",
        title="Missing Zero Address Check",
        severity="LOW",
        description="Missing validation for zero address.",
        fix="Add require(address != address(0)).",
        cvss=CvssFactors(
            attack_vector="network", attack_complexity="low",
            privileges_required="low", user_interaction="none",
            confidentiality="none", integrity="low", availability="none",
        )
    ),
    "incorrect-equality": Rule(
        id="incorrect-equality",
        title="Incorrect Equality Check",
        severity="LOW",
        description="Improper equality comparison.",
        fix="Review comparison logic.",
        cvss=CvssFactors(
            attack_vector="network", attack_complexity="high",
            privileges_required="none", user_interaction="none",
            confidentiality="none", integrity="low", availability="none",
        )
    ),
    "events-access": Rule(
        id="events-access",
        title="Missing Access Control Event",
        severity="LOW",
        description="State-changing access control functions do not emit events.",
        fix="Emit events on all ownership transfers and role changes.",
        cvss=CvssFactors(
            attack_vector="network", attack_complexity="low",
            privileges_required="none", user_interaction="none",
            confidentiality="none", integrity="none", availability="none",
        )
    ),
    "events-maths": Rule(
        id="events-maths",
        title="Missing Arithmetic Event",
        severity="LOW",
        description="Functions that change critical numeric state emit no events.",
        fix="Add events for all state-changing math operations.",
        cvss=CvssFactors(
            attack_vector="network", attack_complexity="low",
            privileges_required="none", user_interaction="none",
            confidentiality="none", integrity="none", availability="none",
        )
    ),
    "naming-convention": Rule(
        id="naming-convention",
        title="Naming Convention Violation",
        severity="LOW",
        description="Contract does not follow Solidity naming conventions.",
        fix="Follow Solidity style guide: PascalCase for contracts, camelCase for functions.",
        cvss=CvssFactors(
            attack_vector="local", attack_complexity="low",
            privileges_required="none", user_interaction="none",
            confidentiality="none", integrity="none", availability="none",
        )
    ),
}


# =========================
# SLITHER → RULE MAPPING
# =========================
SLITHER_TO_RULE = {
    "reentrancy": "reentrancy",
    "reentrancy-eth": "reentrancy",
    "reentrancy-no-eth": "reentrancy",
    "reentrancy-benign": "reentrancy",
    "reentrancy-events": "reentrancy",
    "tx-origin": "tx-origin",
    "tx-origin-usage": "tx-origin",
    "unchecked-call": "unchecked-lowlevel",
    "low-level-call": "unchecked-lowlevel",
    "low-level-calls": "unchecked-lowlevel",
    "unchecked-lowlevel": "unchecked-lowlevel",
    "calls-loop": "unchecked-lowlevel",
    "unchecked-transfer": "unchecked-transfer",
    "missing-auth": "access-control",
    "unprotected-function": "access-control",
    "msg-value-loop": "access-control",
    "constable-states": "access-control",
    "arbitrary-send-eth": "arbitrary-send-eth",
    "weak-prng": "weak-prng",
    "controlled-delegatecall": "controlled-delegatecall",
    "timestamp": "timestamp",
    "unchecked-send": "unchecked-send",
    "missing-zero-check": "missing-zero-check",
    "suicidal": "suicidal",
    "incorrect-equality": "incorrect-equality",
    "events-access": "events-access",
    "events-maths": "events-maths",
    "deprecated-standards": "deprecated-standards",
    "naming-convention": "naming-convention",
    "reentrancy-unlimited-gas": "reentrancy-unlimited-gas",
}


# =========================
# DEFAULT FALLBACK
# =========================
DEFAULT_RULE = Rule(
    id="unknown",
    title="Unclassified Vulnerability",
    severity="LOW",
    description="This issue is not yet mapped to a known rule.",
    fix="Investigate manually and extend rules if needed.",
)


def normalize_check(check: str) -> str:
    return check.lower().strip() if check else ""


def map_finding(check: str) -> Rule:
    check = normalize_check(check)
    if check in SLITHER_TO_RULE:
        return RULES.get(SLITHER_TO_RULE[check], DEFAULT_RULE)
    for key in SLITHER_TO_RULE:
        if key in check:
            return RULES.get(SLITHER_TO_RULE[key], DEFAULT_RULE)
    return DEFAULT_RULE


# =========================
# CVSS-INSPIRED SCORING
# =========================
CONFIDENCE_WEIGHT = {
    "High": 1.0,
    "Medium": 0.7,
    "Low": 0.4,
}

SEVERITY_MULTIPLIER = {
    "CRITICAL": 10.0,
    "HIGH": 7.5,
    "MEDIUM": 4.0,
    "LOW": 1.5,
}


def compute_risk_score(findings: list[dict]) -> int:
    if not findings:
        return 0

    total = 0.0

    for f in findings:
        rule_id = f.get("check", "")
        rule = map_finding(rule_id)

        # CVSS base score (0-10)
        cvss_score = cvss_base_score(rule.cvss)

        # Confidence weight from Slither
        conf = f.get("confidence", "Medium")
        conf_weight = CONFIDENCE_WEIGHT.get(conf, 0.7)

        # Severity multiplier ensures severity label aligns with score
        sev = f.get("severity", "LOW").upper()
        sev_mult = SEVERITY_MULTIPLIER.get(sev, 1.5)

        # Final per-finding score
        finding_score = cvss_score * conf_weight * sev_mult
        total += finding_score

    # Normalize to 0-100 with logarithmic dampening to prevent explosion
    import math
    normalized = 100 * (1 - math.exp(-total / 80))
    return min(int(normalized), 100)