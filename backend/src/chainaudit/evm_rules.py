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
    chain: str = "evm"        # "evm" | "arbitrum" | "optimism" | "l2" | "all"
    cvss: CvssFactors = field(default_factory=lambda: CvssFactors(
        attack_vector="network",
        attack_complexity="low",
        privileges_required="none",
        user_interaction="none",
        confidentiality="low",
        integrity="low",
        availability="low",
    ))
    @property
    def rule_id(self):
        return self.id


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

    # -------------------------------------------------------
    # EVM / General rules (all chains)
    # -------------------------------------------------------
    "reentrancy": Rule(
        id="reentrancy",
        title="Reentrancy",
        severity="CRITICAL",
        description="External call before updating state can allow attacker to re-enter and drain funds.",
        fix="Use Checks-Effects-Interactions pattern, add reentrancy guard, and update state before external calls.",
        chain="all",
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
        chain="all",
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
        chain="all",
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
        chain="all",
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
        chain="all",
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
        chain="all",
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
        chain="all",
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
        chain="all",
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
        chain="all",
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
        chain="all",
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
        chain="all",
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
        chain="all",
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
        chain="all",
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
        chain="all",
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
        chain="all",
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
        chain="all",
        cvss=CvssFactors(
            attack_vector="network", attack_complexity="low",
            privileges_required="none", user_interaction="none",
            confidentiality="none", integrity="low", availability="none",
        )
    ),
    "events-maths": Rule(
        id="events-maths",
        title="Missing Arithmetic Event",
        severity="LOW",
        description="Functions that change critical numeric state emit no events.",
        fix="Add events for all state-changing math operations.",
        chain="all",
        cvss=CvssFactors(
            attack_vector="network", attack_complexity="low",
            privileges_required="none", user_interaction="none",
            confidentiality="none", integrity="low", availability="none",
        )
    ),
    "naming-convention": Rule(
        id="naming-convention",
        title="Naming Convention Violation",
        severity="LOW",
        description="Contract does not follow Solidity naming conventions.",
        fix="Follow Solidity style guide: PascalCase for contracts, camelCase for functions.",
        chain="all",
        cvss=CvssFactors(
            attack_vector="local", attack_complexity="low",
            privileges_required="none", user_interaction="none",
            confidentiality="none", integrity="low", availability="none",
        )
    ),

    # -------------------------------------------------------
    # L2 / Arbitrum / Optimism specific rules
    # -------------------------------------------------------

    "l2-msg-value-misuse": Rule(
        id="l2-msg-value-misuse",
        title="L2 msg.value Misuse",
        severity="CRITICAL",
        description="On L2 networks (Arbitrum, Optimism), msg.value in a delegatecall context does not behave the same as on L1. "
                    "ETH sent via msg.value may be lost or cause unexpected reverts if the contract assumes L1 semantics.",
        fix="Avoid relying on msg.value inside delegatecall on L2. Use explicit ETH accounting and test on the target L2 network.",
        chain="l2",
        cvss=CvssFactors(
            attack_vector="network", attack_complexity="low",
            privileges_required="none", user_interaction="none",
            confidentiality="none", integrity="high", availability="high",
        )
    ),

    "l2-block-number-assumption": Rule(
        id="l2-block-number-assumption",
        title="L2 Block Number Assumption",
        severity="HIGH",
        description="On Arbitrum, block.number returns the L1 block number, not the L2 block number. "
                    "On Optimism, block.number returns the L2 block number but block times differ significantly from L1. "
                    "Contracts assuming L1 block timing will behave incorrectly.",
        fix="Use ArbSys.arbBlockNumber() on Arbitrum for L2 block numbers. "
            "On Optimism use block.number but account for ~2s block times. "
            "Avoid using block.number for time-sensitive logic on any L2.",
        chain="l2",
        cvss=CvssFactors(
            attack_vector="network", attack_complexity="high",
            privileges_required="none", user_interaction="none",
            confidentiality="none", integrity="high", availability="low",
        )
    ),

    "l2-timestamp-assumption": Rule(
        id="l2-timestamp-assumption",
        title="L2 Timestamp Assumption",
        severity="HIGH",
        description="L2 block timestamps are set by the sequencer and can differ significantly from L1. "
                    "On Arbitrum, timestamps are derived from L1 but can lag. "
                    "Time-locked logic (vesting, expiry, auctions) may behave unexpectedly.",
        fix="Add tolerance margins to time-based checks. "
            "For critical time logic, consider reading L1 block timestamp via an oracle rather than block.timestamp.",
        chain="l2",
        cvss=CvssFactors(
            attack_vector="network", attack_complexity="high",
            privileges_required="none", user_interaction="none",
            confidentiality="none", integrity="high", availability="low",
        )
    ),

    "l2-cross-chain-replay": Rule(
        id="l2-cross-chain-replay",
        title="Cross-Chain Replay Attack",
        severity="CRITICAL",
        description="Transactions or signed messages valid on one chain (L1 or L2) can be replayed on another chain "
                    "if the contract does not include chain ID in its domain separator or signature verification.",
        fix="Always include block.chainid in EIP-712 domain separators. "
            "Verify chain ID in all signature validation logic. "
            "Use OpenZeppelin's EIP712 base contract which handles this correctly.",
        chain="l2",
        cvss=CvssFactors(
            attack_vector="network", attack_complexity="low",
            privileges_required="none", user_interaction="none",
            confidentiality="none", integrity="high", availability="high",
        )
    ),

    "l2-sequencer-dependence": Rule(
        id="l2-sequencer-dependence",
        title="Sequencer Centralization Risk",
        severity="HIGH",
        description="L2 networks rely on a centralized sequencer to order transactions. "
                    "A sequencer outage or censorship can prevent transactions from being processed, "
                    "blocking time-sensitive operations like liquidations or auction settlements.",
        fix="Add a sequencer uptime check using Chainlink's L2 Sequencer Uptime Feed before executing "
            "time-sensitive operations. Implement fallback mechanisms for sequencer downtime.",
        chain="l2",
        cvss=CvssFactors(
            attack_vector="network", attack_complexity="high",
            privileges_required="none", user_interaction="none",
            confidentiality="none", integrity="low", availability="high",
        )
    ),

    "l2-force-include-griefing": Rule(
        id="l2-force-include-griefing",
        title="Force-Include Griefing",
        severity="MEDIUM",
        description="On Arbitrum, users can force-include transactions via the delayed inbox after a timeout. "
                    "Contracts that rely on sequential ordering or assume no external interference between "
                    "transactions may be griefed by force-included transactions.",
        fix="Design contracts to be order-independent where possible. "
            "Use commit-reveal or time-locks for sensitive multi-step operations.",
        chain="arbitrum",
        cvss=CvssFactors(
            attack_vector="network", attack_complexity="high",
            privileges_required="none", user_interaction="none",
            confidentiality="none", integrity="low", availability="low",
        )
    ),

    "l2-aliased-address": Rule(
        id="l2-aliased-address",
        title="L1 to L2 Address Aliasing",
        severity="HIGH",
        description="On Arbitrum, when a contract on L1 sends a message to L2, the sender address is aliased "
                    "(offset by 0x1111000000000000000000000000000000001111). "
                    "Contracts that check msg.sender for L1 contract addresses will fail because the aliased "
                    "address does not match the original L1 address.",
        fix="Use Arbitrum's AddressAliasHelper.undoL1ToL2Alias() to recover the original L1 address. "
            "Always account for address aliasing in cross-chain message handlers.",
        chain="arbitrum",
        cvss=CvssFactors(
            attack_vector="network", attack_complexity="low",
            privileges_required="none", user_interaction="none",
            confidentiality="none", integrity="high", availability="low",
        )
    ),

    "l2-gas-price-assumption": Rule(
        id="l2-gas-price-assumption",
        title="L2 Gas Price Assumption",
        severity="MEDIUM",
        description="On L2 networks, gas prices can be extremely low (fractions of gwei) but spike unpredictably "
                    "when L1 data costs increase. Contracts that hardcode gas limits or assume low gas costs "
                    "for external calls may fail or become unusable during L1 gas spikes.",
        fix="Avoid hardcoded gas limits for external calls on L2. "
            "Use dynamic gas estimation and ensure critical paths do not assume a fixed gas cost.",
        chain="l2",
        cvss=CvssFactors(
            attack_vector="network", attack_complexity="high",
            privileges_required="none", user_interaction="none",
            confidentiality="none", integrity="low", availability="high",
        )
    ),

    "l2-bridge-reentrancy": Rule(
        id="l2-bridge-reentrancy",
        title="Cross-Chain Bridge Reentrancy",
        severity="CRITICAL",
        description="Contracts that interact with L2 bridges (Arbitrum inbox, Optimism CrossDomainMessenger) "
                    "can be vulnerable to reentrancy through bridge callbacks. "
                    "A malicious L1 contract can re-enter the L2 contract through the bridge before state is updated.",
        fix="Apply reentrancy guards to all functions that receive bridge callbacks. "
            "Follow CEI pattern strictly in bridge message handlers. "
            "Validate that msg.sender is the trusted bridge contract.",
        chain="l2",
        cvss=CvssFactors(
            attack_vector="network", attack_complexity="low",
            privileges_required="none", user_interaction="none",
            confidentiality="high", integrity="high", availability="high",
        )
    ),

    "l2-storage-collision": Rule(
        id="l2-storage-collision",
        title="Proxy Storage Collision on L2",
        severity="CRITICAL",
        description="Upgradeable proxy contracts deployed on L2 are especially risky because storage slot "
                    "collisions between proxy and implementation contracts can be exploited cheaply due to low gas costs. "
                    "An attacker can repeatedly probe storage slots to find collisions.",
        fix="Use EIP-1967 standardised storage slots for proxy variables. "
            "Use OpenZeppelin's TransparentUpgradeableProxy or UUPS pattern. "
            "Run storage layout checks with hardhat-storage-layout before upgrades.",
        chain="l2",
        cvss=CvssFactors(
            attack_vector="network", attack_complexity="high",
            privileges_required="none", user_interaction="none",
            confidentiality="high", integrity="high", availability="high",
        )
    ),

    "optimism-deposit-griefing": Rule(
        id="optimism-deposit-griefing",
        title="Optimism Deposit Griefing",
        severity="MEDIUM",
        description="On Optimism, anyone can trigger a deposit transaction to any address on L2 by sending ETH "
                    "to the OptimismPortal. A griefer can send tiny deposits to contract addresses, "
                    "triggering their receive() or fallback() functions unexpectedly.",
        fix="Ensure receive() and fallback() functions on L2 are stateless and gas-efficient. "
            "Do not rely on ETH balance checks being stable between transactions.",
        chain="optimism",
        cvss=CvssFactors(
            attack_vector="network", attack_complexity="low",
            privileges_required="none", user_interaction="none",
            confidentiality="none", integrity="low", availability="low",
        )
    ),

    "l2-msg-sender-bridge": Rule(
        id="l2-msg-sender-bridge",
        title="Unvalidated Bridge Message Sender",
        severity="HIGH",
        description="Contracts receiving messages from L1 via a bridge do not validate that msg.sender "
                    "is the trusted bridge contract (e.g. L2CrossDomainMessenger on Optimism, "
                    "Bridge on Arbitrum). Any address could spoof cross-chain messages.",
        fix="Always validate msg.sender == trustedBridgeAddress in cross-chain message receivers. "
            "On Optimism additionally validate xDomainMessageSender() == trustedL1Contract.",
        chain="l2",
        cvss=CvssFactors(
            attack_vector="network", attack_complexity="low",
            privileges_required="none", user_interaction="none",
            confidentiality="none", integrity="high", availability="high",
        )
    ),
}


# =========================
# SLITHER → RULE MAPPING
# =========================
SLITHER_TO_RULE = {
    # Core EVM
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

    # L2 / Arbitrum / Optimism — Slither detector names
    "msg-value-in-delegate": "l2-msg-value-misuse",
    "delegatecall-loop": "l2-msg-value-misuse",
    "arbsys-block-number": "l2-block-number-assumption",
    "block-number-dependency": "l2-block-number-assumption",
    "timestamp-l2": "l2-timestamp-assumption",
    "missing-chain-id": "l2-cross-chain-replay",
    "domain-separator-collision": "l2-cross-chain-replay",
    "l2-sequencer": "l2-sequencer-dependence",
    "sequencer-uptime": "l2-sequencer-dependence",
    "force-include": "l2-force-include-griefing",
    "l1-address-alias": "l2-aliased-address",
    "address-aliasing": "l2-aliased-address",
    "gas-price-oracle": "l2-gas-price-assumption",
    "hardcoded-gas-limit": "l2-gas-price-assumption",
    "bridge-reentrancy": "l2-bridge-reentrancy",
    "cross-chain-reentrancy": "l2-bridge-reentrancy",
    "proxy-storage-collision": "l2-storage-collision",
    "storage-collision": "l2-storage-collision",
    "optimism-deposit": "optimism-deposit-griefing",
    "unvalidated-bridge-sender": "l2-msg-sender-bridge",
    "cross-domain-sender": "l2-msg-sender-bridge",
}

# =========================
# L2 PATTERN DETECTION
# =========================
# Keywords in contract source that suggest L2 deployment
# Used by the scanner to auto-detect L2 contracts and apply L2 rules
L2_INDICATORS = {
    # Arbitrum
    "ArbSys", "ArbGasInfo", "ArbRetryableTx", "NodeInterface",
    "IInbox", "IBridge", "IOutbox", "L1GatewayRouter", "L2GatewayRouter",
    "arbBlockNumber", "arbBlockHash", "AddressAliasHelper",
    # Optimism
    "OVM_ETH", "L2CrossDomainMessenger", "L1CrossDomainMessenger",
    "OptimismPortal", "L2ToL1MessagePasser", "CrossDomainOwnable",
    "xDomainMessageSender", "IL2CrossDomainMessenger",
    # Generic L2 / bridge
    "IL1Bridge", "IL2Bridge", "ILayerZero", "IOFT",
    "CrossChainEnabled", "CrossChainEnabledArbitrumL2",
    "CrossChainEnabledOptimism",
}


def detect_l2_chain(source: str) -> str | None:
    arb_hits = sum(1 for kw in L2_INDICATORS if "Arb" in kw and kw in source)
    opt_hits = sum(1 for kw in L2_INDICATORS if ("Optimism" in kw or "OVM" in kw or "xDomain" in kw) and kw in source)
    generic_hits = sum(1 for kw in L2_INDICATORS if kw in source)

    # Require at least 2 hits to avoid false positives on empty/simple contracts
    if arb_hits >= 2:
        return "arbitrum"
    if opt_hits >= 2:
        return "optimism"
    if generic_hits >= 2:
        return "l2"
    return None


def get_l2_rules(chain: str) -> list[Rule]:
    """Return all rules applicable to a given L2 chain."""
    applicable = []
    for rule in RULES.values():
        if rule.chain == "all":
            continue  # EVM rules already applied by Slither
        if rule.chain == chain or rule.chain == "l2":
            applicable.append(rule)
    return applicable


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
        cvss_score = cvss_base_score(rule.cvss)
        conf = f.get("confidence", "Medium")
        conf_weight = CONFIDENCE_WEIGHT.get(conf, 0.7)
        sev = f.get("severity", "LOW").upper()
        sev_mult = SEVERITY_MULTIPLIER.get(sev, 1.5)
        finding_score = cvss_score * conf_weight * sev_mult
        total += finding_score

    import math
    normalized = 100 * (1 - math.exp(-total / 80))
    final = int(normalized)

    if findings and final == 0:
        final = 5

    return min(final, 100)