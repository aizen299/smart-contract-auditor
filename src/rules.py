from dataclasses import dataclass

@dataclass
class Rule:
    id: str
    title: str
    severity: str
    description: str
    fix: str


RULES = {
    "reentrancy": Rule(
        id="reentrancy",
        title="Reentrancy",
        severity="CRITICAL",
        description="External call before updating state can allow attacker to re-enter and drain funds.",
        fix="Use Checks-Effects-Interactions, reentrancy guard, update state before external call."
    ),
    "tx-origin": Rule(
        id="tx-origin",
        title="tx.origin Authentication",
        severity="HIGH",
        description="Using tx.origin for auth is insecure and can be bypassed using phishing contracts.",
        fix="Use msg.sender instead of tx.origin."
    ),
    "unchecked-lowlevel": Rule(
        id="unchecked-lowlevel",
        title="Unchecked Low-level Call",
        severity="HIGH",
        description="Low-level call return value not checked, execution may silently fail.",
        fix="Always check returned boolean or use safer abstractions."
    ),
    "access-control": Rule(
        id="access-control",
        title="Access Control Issue",
        severity="HIGH",
        description="Critical functions are missing proper access checks.",
        fix="Add onlyOwner/role-based access checks."
    ),
}
