"""
ChainAudit — Solana / Rust vulnerability rules.

Two detection layers:
1. cargo-audit  — known CVEs in Cargo.lock dependencies (RustSec advisory DB)
2. Pattern scan — regex-based detection of Solana-specific vulnerability patterns
                  in .rs source files (missing signer checks, unsafe CPI, etc.)
"""

from dataclasses import dataclass, field
from typing import Dict, List


@dataclass
class SolanaRule:
    id: str
    title: str
    severity: str          # CRITICAL | HIGH | MEDIUM | LOW
    description: str
    fix: str
    chain: str = "solana"
    category: str = "logic"  # logic | dependency | unsafe


# =============================================================================
# SOLANA PROGRAM LOGIC RULES
# Detected via regex pattern matching on .rs source files
# =============================================================================

SOLANA_RULES: Dict[str, SolanaRule] = {

    "missing-signer-check": SolanaRule(
        id="missing-signer-check",
        title="Missing Signer Check",
        severity="CRITICAL",
        description="Account instructions do not verify that the required account is a signer. "
                    "An attacker can pass any account as the signer without authorization, "
                    "allowing unauthorized access to privileged instructions.",
        fix="Add `ctx.accounts.authority.is_signer` check or use Anchor's `Signer<'info>` type "
            "which enforces signer verification automatically.",
        category="logic",
    ),

    "missing-owner-check": SolanaRule(
        id="missing-owner-check",
        title="Missing Owner Check",
        severity="CRITICAL",
        description="Program does not verify the owner of an account before reading or writing data. "
                    "An attacker can substitute a malicious account owned by a different program, "
                    "leading to account confusion attacks.",
        fix="Verify account ownership with `account.owner == program_id` or use Anchor's "
            "`Account<'info, T>` which automatically checks the owner.",
        category="logic",
    ),

    "arbitrary-cpi": SolanaRule(
        id="arbitrary-cpi",
        title="Arbitrary CPI",
        severity="CRITICAL",
        description="Program invokes a cross-program invocation (CPI) using an account-provided "
                    "program ID without validating it. An attacker can substitute a malicious program "
                    "to execute arbitrary code in the context of your program.",
        fix="Validate the program ID before CPI: `require_keys_eq!(ctx.accounts.token_program.key(), "
            "anchor_spl::token::ID)`. Never use unchecked program IDs from instruction accounts.",
        category="logic",
    ),

    "integer-overflow": SolanaRule(
        id="integer-overflow",
        title="Integer Overflow / Underflow",
        severity="HIGH",
        description="Arithmetic operations use unchecked addition, subtraction, or multiplication "
                    "that can overflow or underflow. In Rust release builds, integer overflow causes "
                    "wrapping which leads to incorrect calculations and fund loss.",
        fix="Use checked arithmetic: `amount.checked_add(fee).ok_or(ErrorCode::Overflow)?` "
            "or enable overflow checks in Cargo.toml: `[profile.release] overflow-checks = true`.",
        category="logic",
    ),

    "unchecked-arithmetic": SolanaRule(
        id="unchecked-arithmetic",
        title="Unchecked Arithmetic",
        severity="HIGH",
        description="Program performs arithmetic with `+`, `-`, `*` operators without overflow "
                    "protection. While Rust debug builds panic on overflow, release builds wrap silently.",
        fix="Replace raw arithmetic with checked variants: `checked_add`, `checked_sub`, "
            "`checked_mul`, `saturating_add`. Use the `num-traits` crate for safe math.",
        category="logic",
    ),

    "unsafe-code": SolanaRule(
        id="unsafe-code",
        title="Unsafe Rust Code",
        severity="HIGH",
        description="Program contains `unsafe` blocks which bypass Rust's memory safety guarantees. "
                    "Unsafe code can lead to memory corruption, use-after-free, and buffer overflows "
                    "that are impossible in safe Rust.",
        fix="Remove unsafe blocks where possible. If unsafe is necessary, document the invariants "
            "that make it sound and add thorough tests. Consider using safe abstractions instead.",
        category="unsafe",
    ),

    "account-confusion": SolanaRule(
        id="account-confusion",
        title="Account Confusion Attack",
        severity="HIGH",
        description="Program uses multiple accounts of the same type without verifying they are "
                    "distinct. An attacker can pass the same account for two different roles "
                    "(e.g. source and destination) causing unintended state changes.",
        fix="Add explicit checks: `require_keys_neq!(ctx.accounts.from.key(), ctx.accounts.to.key())`. "
            "Anchor's constraint system can enforce this with `#[account(constraint = ...)]`.",
        category="logic",
    ),

    "missing-rent-exemption": SolanaRule(
        id="missing-rent-exemption",
        title="Missing Rent Exemption Check",
        severity="MEDIUM",
        description="Program creates or uses accounts without verifying they are rent-exempt. "
                    "Non-rent-exempt accounts can be garbage collected by the Solana runtime, "
                    "causing data loss and program failures.",
        fix="Ensure accounts hold enough lamports for rent exemption: "
            "`Rent::get()?.minimum_balance(account_size)`. "
            "Use Anchor's `init` constraint which handles this automatically.",
        category="logic",
    ),

    "unvalidated-account-data": SolanaRule(
        id="unvalidated-account-data",
        title="Unvalidated Account Data",
        severity="MEDIUM",
        description="Program deserializes and uses account data without validating its contents. "
                    "An attacker can craft malicious account data that passes deserialization "
                    "but contains unexpected values.",
        fix="Validate all fields after deserialization. Use Anchor's account constraints "
            "`#[account(has_one = authority)]` to enforce relationships between accounts.",
        category="logic",
    ),

    "missing-close-account": SolanaRule(
        id="missing-close-account",
        title="Missing Close Account Check",
        severity="MEDIUM",
        description="Program closes accounts by setting lamports to zero but does not clear "
                    "the account data. A closed account can be re-initialized with stale data "
                    "in the same transaction.",
        fix="Use Anchor's `close` constraint or manually zero out account data before "
            "transferring lamports. Set discriminator to closed state to prevent re-use.",
        category="logic",
    ),

    "pdas-not-validated": SolanaRule(
        id="pdas-not-validated",
        title="PDA Seeds Not Validated",
        severity="MEDIUM",
        description="Program derives or uses Program Derived Addresses (PDAs) without validating "
                    "the seeds used to derive them. An attacker can substitute a PDA derived "
                    "with different seeds.",
        fix="Always verify PDAs with `Pubkey::find_program_address` and check the bump seed. "
            "Use Anchor's `seeds` and `bump` constraints for automatic PDA validation.",
        category="logic",
    ),

    "reentrancy-cpi": SolanaRule(
        id="reentrancy-cpi",
        title="CPI Reentrancy Risk",
        severity="HIGH",
        description="Program makes a CPI call before updating its own state. If the callee "
                    "program calls back into this program (reentrancy via CPI), it may observe "
                    "stale state and exploit the inconsistency.",
        fix="Update all state before making CPI calls. Follow the Checks-Effects-Interactions "
            "pattern. Be aware that Solana does not natively prevent CPI reentrancy.",
        category="logic",
    ),

    "insecure-randomness": SolanaRule(
        id="insecure-randomness",
        title="Insecure Randomness",
        severity="HIGH",
        description="Program uses predictable on-chain data (clock, slot, recent blockhash) "
                    "as a source of randomness. Validators and other programs can predict or "
                    "manipulate these values.",
        fix="Use Switchboard VRF or Chainlink VRF for verifiable on-chain randomness. "
            "Never use `Clock::get()?.unix_timestamp` or `recent_blockhash` as randomness.",
        category="logic",
    ),

    "missing-freeze-authority": SolanaRule(
        id="missing-freeze-authority",
        title="Missing Freeze Authority Check",
        severity="LOW",
        description="Program interacts with token accounts without checking if the mint "
                    "has a freeze authority set. Frozen token accounts will cause transfers "
                    "to fail unexpectedly.",
        fix="Check `mint.freeze_authority` before performing token operations if your "
            "program needs to handle frozen accounts gracefully.",
        category="logic",
    ),

    "deprecated-anchor": SolanaRule(
        id="deprecated-anchor",
        title="Deprecated Anchor Patterns",
        severity="LOW",
        description="Program uses deprecated Anchor patterns or old API versions that "
                    "have known security issues or have been superseded by safer alternatives.",
        fix="Update to the latest Anchor version and replace deprecated patterns. "
            "Run `anchor upgrade` and check the Anchor migration guide.",
        category="logic",
    ),
}


# =============================================================================
# REGEX PATTERNS FOR SOURCE SCANNING
# Each pattern maps to a rule ID
# =============================================================================

SOLANA_PATTERNS = [
    # Missing signer check — accounts used without .is_signer verification
    {
        "rule_id": "missing-signer-check",
        "patterns": [
            r"AccountInfo",
            r"\.key\(\)",
        ],
        "anti_patterns": [
            r"is_signer",
            r"Signer<",
            r"#\[account\(signer\)\]",
        ],
        "description": "AccountInfo used without signer verification",
    },

    # Arbitrary CPI — invoke called with account-provided program
    {
        "rule_id": "arbitrary-cpi",
        "patterns": [
            r"invoke\s*\(",
            r"invoke_signed\s*\(",
        ],
        "anti_patterns": [
            r"require_keys_eq!",
            r"assert_eq!.*program",
            r"== anchor_spl",
            r"== spl_token",
        ],
        "description": "CPI invoke without program ID validation",
    },

    # Integer overflow — raw arithmetic without checked ops
    {
    "rule_id": "integer-overflow",
    "patterns": [
        r"\w+\s*\+\s*\w+",        
        r"\w+\s*\-\s*\w+",        
        r"\w+\s*\*\s*\w+",        
        r"\+=",                    
        r"\-=",                    
    ],
    "anti_patterns": [
        r"checked_add",
        r"checked_sub",
        r"checked_mul",
        r"saturating_add",
        r"saturating_sub",
        r"overflow-checks\s*=\s*true",
        r"wrapping_add",
        r"wrapping_sub",
    ],
    "description": "Unchecked arithmetic on integer types",
},

    # Unsafe code blocks
    {
        "rule_id": "unsafe-code",
        "patterns": [
            r"\bunsafe\s*\{",
            r"\bunsafe\s+fn\b",
            r"\bunsafe\s+impl\b",
        ],
        "anti_patterns": [],
        "description": "Unsafe Rust code block detected",
    },

    # Insecure randomness
    {
        "rule_id": "insecure-randomness",
        "patterns": [
            r"Clock::get\(\)",
            r"unix_timestamp",
            r"recent_blockhash",
            r"slot\s+as\s+u",
        ],
        "anti_patterns": [
            r"switchboard",
            r"chainlink",
            r"vrf",
        ],
        "description": "On-chain values used as randomness source",
    },

    # Missing owner check
    {
        "rule_id": "missing-owner-check",
        "patterns": [
            r"\.owner\b",
            r"AccountInfo",
        ],
        "anti_patterns": [
            r"\.owner\s*==",
            r"Account<",
            r"check_id\(",
            r"owner\s*==\s*program_id",
        ],
        "description": "Account owner not verified",
    },

    # CPI reentrancy — state updated after CPI
    {
        "rule_id": "reentrancy-cpi",
        "patterns": [
            r"invoke\s*\(",
            r"invoke_signed\s*\(",
        ],
        "anti_patterns": [],
        "description": "CPI call detected — verify state is updated before invoke",
    },
]


# =============================================================================
# SEVERITY MULTIPLIERS (same system as EVM rules)
# =============================================================================

SEVERITY_MULTIPLIER = {
    "CRITICAL": 10.0,
    "HIGH": 7.5,
    "MEDIUM": 4.0,
    "LOW": 1.5,
}

CONFIDENCE_WEIGHT = {
    "High": 1.0,
    "Medium": 0.7,
    "Low": 0.4,
}


def compute_solana_risk_score(findings: list[dict]) -> int:
    import math
    if not findings:
        return 0

    total = 0.0
    for f in findings:
        sev = f.get("severity", "LOW").upper()
        conf = f.get("confidence", "Medium")
        sev_mult = SEVERITY_MULTIPLIER.get(sev, 1.5)
        conf_weight = CONFIDENCE_WEIGHT.get(conf, 0.7)
        total += sev_mult * conf_weight

    normalized = 100 * (1 - math.exp(-total / 80))
    final = int(normalized)
    if findings and final == 0:
        final = 5
    return min(final, 100)


def get_rule(rule_id: str) -> SolanaRule:
    return SOLANA_RULES.get(rule_id, SolanaRule(
        id="unknown",
        title="Unclassified Rust Vulnerability",
        severity="LOW",
        description="This issue is not yet mapped to a known rule.",
        fix="Investigate manually.",
    ))