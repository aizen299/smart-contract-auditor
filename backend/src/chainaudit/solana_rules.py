"""
ChainAudit — Solana / Anchor Security Rules
22 rules covering signer validation, CPI misuse, arithmetic, account issues,
randomness, PDA validation, and more.
"""

from dataclasses import dataclass, field


@dataclass
class SolanaRule:
    rule_id: str
    title: str
    severity: str          # CRITICAL | HIGH | MEDIUM | LOW
    category: str
    description: str
    fix: str
    confidence: str = "Medium"
    patterns: list[str] = field(default_factory=list)
    anti_patterns: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)


SOLANA_RULES: list[SolanaRule] = [

    # ── CRITICAL ─────────────────────────────────────────────────────────────

    SolanaRule(
        rule_id="missing-signer-check",
        title="Missing Signer Check",
        severity="CRITICAL",
        category="access-control",
        description=(
            "Account instructions do not verify that the required account is a signer. "
            "An attacker can pass any account as the signer without authorization, "
            "allowing unauthorized access to privileged instructions."
        ),
        fix=(
            "Add ctx.accounts.authority.is_signer check or use Anchor's "
            "Signer<'info> type which enforces signer verification automatically."
        ),
        confidence="Medium",
        patterns=[
            r"pub\s+\w+:\s*AccountInfo<'info>",
        ],
        anti_patterns=[
            r"Signer<'info>",
            r"\.is_signer",
            r"#\[account\(signer\)\]",
            r"require!\(.*\.is_signer",
            r"#\[account\(constraint",
            r"has_one\s*=",
        ],
    ),

    SolanaRule(
        rule_id="missing-owner-check",
        title="Missing Owner Check",
        severity="CRITICAL",
        category="access-control",
        description=(
            "Program does not verify the owner of an account before reading or "
            "modifying it. An attacker can substitute an account owned by a different "
            "program, causing the program to operate on attacker-controlled data."
        ),
        fix=(
            "Use Anchor's Account<'info, T> type which automatically checks the "
            "owner. If using raw AccountInfo, check: require_keys_eq!(account.owner, "
            "program_id). Never trust account data without verifying ownership."
        ),
        confidence="Medium",
        patterns=[
            r"\.data\.borrow\(\)",
            r"try_from_slice",
        ],
        anti_patterns=[
            r"Account<'info",
            r"\.owner",
            r"#\[account\(owner",
            r"require_keys_eq!.*owner",
        ],
    ),

    SolanaRule(
        rule_id="arbitrary-cpi",
        title="Arbitrary CPI",
        severity="CRITICAL",
        category="cpi",
        description=(
            "Program invokes a cross-program invocation (CPI) using an "
            "account-provided program ID without validating it. An attacker can "
            "substitute a malicious program to execute arbitrary code in the "
            "context of your program."
        ),
        fix=(
            "Validate the program ID before CPI: "
            "require_keys_eq!(ctx.accounts.token_program.key(), anchor_spl::token::ID). "
            "Never use unchecked program IDs from instruction accounts."
        ),
        confidence="Medium",
        patterns=[
            r"invoke\(",
            r"invoke_signed\(",
            r"program\.key\(\)",
        ],
        anti_patterns=[
            r"require_keys_eq!.*program",
            r"Program<'info",
            r"\.key\(\).*==.*::ID",
        ],
    ),

    SolanaRule(
        rule_id="account-data-injection",
        title="Account Data Injection",
        severity="CRITICAL",
        category="access-control",
        description=(
            "Program deserializes account data without first verifying the account "
            "discriminator or type. An attacker can pass in a crafted account whose "
            "data decodes correctly but belongs to a different account type."
        ),
        fix=(
            "Use Anchor's Account<'info, T> which checks the 8-byte discriminator "
            "automatically. If deserializing manually, always check the discriminator "
            "field before trusting the data."
        ),
        confidence="Low",
        patterns=[
            r"try_from_slice",
            r"borsh::BorshDeserialize",
            r"unpack_unchecked",
        ],
        anti_patterns=[
            r"Account<'info",
            r"discriminator",
            r"AccountDeserialize",
        ],
    ),

    # ── HIGH ──────────────────────────────────────────────────────────────────

    SolanaRule(
        rule_id="integer-overflow",
        title="Integer Overflow / Underflow",
        severity="HIGH",
        category="arithmetic",
        description=(
            "Program performs arithmetic on integer types without overflow checks. "
            "Rust panics on overflow in debug mode but wraps silently in release mode, "
            "potentially causing fund loss or logic bypasses."
        ),
        fix=(
            "Use checked_add, checked_sub, checked_mul — they return Option<T> and "
            "force explicit error handling. Alternatively use saturating_add/sub if "
            "saturation is acceptable, or enable overflow-checks = true in Cargo.toml."
        ),
        confidence="Medium",
        patterns=[
            r"\+=\s*\w+",
            r"-=\s*\w+",
            r"\*=\s*\w+",
        ],
        anti_patterns=[
            r"checked_add",
            r"checked_sub",
            r"checked_mul",
            r"saturating_add",
            r"saturating_sub",
            r"saturating_mul",
            r"overflow-checks\s*=\s*true",
            r"\.checked_",
        ],
    ),

    SolanaRule(
        rule_id="unsafe-code",
        title="Unsafe Rust Code",
        severity="HIGH",
        category="memory-safety",
        description=(
            "Program contains unsafe blocks which bypass Rust's memory safety "
            "guarantees. Unsafe code can lead to memory corruption, use-after-free, "
            "and buffer overflows that are impossible in safe Rust."
        ),
        fix=(
            "Remove unsafe blocks where possible. If unsafe is necessary, document "
            "the invariants that make it sound and add thorough tests. Consider "
            "using safe abstractions instead."
        ),
        confidence="High",
        patterns=[r"unsafe\s*\{", r"unsafe\s+fn"],
        anti_patterns=[],
    ),

    SolanaRule(
        rule_id="reentrancy-cpi",
        title="CPI Reentrancy Risk",
        severity="HIGH",
        category="cpi",
        description=(
            "Program makes a CPI call before updating its own state. If the callee "
            "program calls back into this program (reentrancy via CPI), it may "
            "observe stale state and exploit the inconsistency."
        ),
        fix=(
            "Update all state before making CPI calls. Follow the "
            "Checks-Effects-Interactions pattern. Be aware that Solana does not "
            "natively prevent CPI reentrancy."
        ),
        confidence="Low",
        patterns=[
            r"invoke\(",
            r"invoke_signed\(",
        ],
        anti_patterns=[
            r"//.*CEI",
            r"//.*checks.*effects.*interactions",
            r"CpiContext",
            r"token::transfer",
            r"token::mint_to",
        ],
    ),

    SolanaRule(
        rule_id="insecure-randomness",
        title="Insecure Randomness",
        severity="HIGH",
        category="cryptography",
        description=(
            "Program uses predictable on-chain data (clock, slot, recent blockhash) "
            "as a source of randomness. Validators and other programs can predict "
            "or manipulate these values."
        ),
        fix=(
            "Use Switchboard VRF or Chainlink VRF for verifiable on-chain randomness. "
            "Never use Clock::get()?.unix_timestamp or recent_blockhash as randomness."
        ),
        confidence="High",
        patterns=[
            r"Clock::get\(\)",
            r"\.unix_timestamp",
            r"\.recent_blockhash",
            r"\bslot\b.*rand|rand.*\bslot\b",
        ],
        anti_patterns=[
            r"VRF",
            r"switchboard",
            r"chainlink.*random",
        ],
    ),

    SolanaRule(
        rule_id="account-confusion",
        title="Account Confusion Attack",
        severity="HIGH",
        category="access-control",
        description=(
            "Program uses a single account type for multiple purposes without "
            "discriminating between them. An attacker can pass an account of one "
            "type where another is expected."
        ),
        fix=(
            "Use Anchor's discriminator system — each account struct has a unique "
            "8-byte prefix. If using raw accounts, add an explicit type field "
            "and check it before operating on the account."
        ),
        confidence="Low",
        patterns=[
            r"try_from_slice",
        ],
        anti_patterns=[
            r"#\[account\]",
            r"Account<'info",
            r"discriminator",
        ],
    ),

    SolanaRule(
        rule_id="bump-seed-canonicalization",
        title="Non-Canonical Bump Seed",
        severity="HIGH",
        category="pda",
        description=(
            "Program uses a user-provided bump seed for PDA derivation instead of "
            "the canonical bump. An attacker can provide a non-canonical bump to "
            "derive a different valid PDA, potentially accessing wrong accounts."
        ),
        fix=(
            "Always use find_program_address to get the canonical bump. Store it "
            "in the account and use it for subsequent derivations. Never accept "
            "bump seeds from user input without validation."
        ),
        confidence="Medium",
        patterns=[
            r"create_program_address",
            r"seeds.*bump",
        ],
        anti_patterns=[
            r"find_program_address",
            r"canonical_bump",
            r"#\[account.*bump\]",
        ],
    ),

    # ── MEDIUM ────────────────────────────────────────────────────────────────

    SolanaRule(
        rule_id="missing-rent-exemption",
        title="Missing Rent Exemption Check",
        severity="MEDIUM",
        category="account-management",
        description=(
            "Program creates or uses accounts without ensuring they are "
            "rent-exempt. Accounts that fall below the rent-exempt threshold "
            "can be garbage collected by the runtime, causing data loss."
        ),
        fix=(
            "Ensure all created accounts are funded to the rent-exempt minimum. "
            "Use Rent::get()?.minimum_balance(data_len) to calculate the required "
            "lamports. With Anchor, the #[account(init)] constraint handles this."
        ),
        confidence="Low",
        patterns=[
            r"create_account",
            r"system_instruction::create_account",
        ],
        anti_patterns=[
            r"rent\.minimum_balance",
            r"Rent::get\(\)",
            r"is_exempt",
        ],
    ),

    SolanaRule(
        rule_id="unvalidated-account-data",
        title="Unvalidated Account Data",
        severity="MEDIUM",
        category="validation",
        description=(
            "Program reads fields from an account without validating that the "
            "account was initialized correctly or that its fields are within "
            "expected bounds."
        ),
        fix=(
            "Add explicit validation constraints with Anchor's #[account] macro "
            "or manual require! checks. Validate all numeric fields are within "
            "expected ranges before using them in calculations."
        ),
        confidence="Low",
        patterns=[
            r"ctx\.accounts\.\w+\.to_account_info\(\)",
            r"Account<'info,\s*AccountInfo>",
        ],
        anti_patterns=[
            r"require!\(",
            r"require_gte!\(",
            r"require_eq!\(",
            r"assert!\(",
            r"#\[account\(.*constraint",
            r"#\[account\(.*has_one",
            r"#\[account\(.*owner",
        ],
    ),

    SolanaRule(
        rule_id="missing-close-account",
        title="Missing Close Account Cleanup",
        severity="MEDIUM",
        category="account-management",
        description=(
            "Program opens temporary accounts but does not close them when "
            "finished. Unclosed accounts accumulate rent and waste lamports. "
            "In some cases, residual data can be exploited."
        ),
        fix=(
            "Use Anchor's close = destination constraint to close accounts and "
            "return lamports. Manually closing: zero out data, move lamports to "
            "destination, and set the account's lamports to 0."
        ),
        confidence="Low",
        patterns=[r"#\[account\(init"],
        anti_patterns=[
            r"close\s*=",
            r"#\[account.*close",
        ],
    ),

    SolanaRule(
        rule_id="pdas-not-validated",
        title="PDA Seeds Not Validated",
        severity="MEDIUM",
        category="pda",
        description=(
            "Program derives a PDA using seeds from user input without validating "
            "that the derived address matches the expected account. An attacker "
            "can craft seeds to derive a different PDA."
        ),
        fix=(
            "Always verify the derived PDA matches the expected account address. "
            "Use Anchor's #[account(seeds = [...], bump)] constraint which "
            "automatically verifies the PDA derivation."
        ),
        confidence="Low",
        patterns=[
            r"Pubkey::create_program_address",
            r"seeds\s*=\s*&\[",
        ],
        anti_patterns=[
            r"#\[account.*seeds",
            r"find_program_address",
        ],
    ),

    SolanaRule(
        rule_id="token-account-owner-check",
        title="Token Account Owner Not Verified",
        severity="MEDIUM",
        category="access-control",
        description=(
            "Program uses a token account without verifying that it is owned by "
            "the expected authority. An attacker can pass a token account they "
            "control to steal or manipulate tokens."
        ),
        fix=(
            "Use Anchor's token::authority constraint: "
            "#[account(token::authority = user)]. If using raw SPL token accounts, "
            "check account.owner == token_program.key() and account.delegate."
        ),
        confidence="Medium",
        patterns=[
            r"TokenAccount",
            r"spl_token",
            r"token::transfer",
        ],
        anti_patterns=[
            r"token::authority",
            r"has_one\s*=",
            r"constraint.*authority",
        ],
    ),

    SolanaRule(
        rule_id="duplicate-mutable-accounts",
        title="Duplicate Mutable Accounts",
        severity="MEDIUM",
        category="access-control",
        description=(
            "Program accepts two accounts that could reference the same address "
            "as mutable. Solana allows passing the same account twice, which can "
            "cause aliasing bugs when both references are written."
        ),
        fix=(
            "Add constraint = account_a.key() != account_b.key() in Anchor to "
            "reject duplicate accounts. Or explicitly check in the instruction handler."
        ),
        confidence="Low",
        patterns=[
            r"#\[account\(mut\)\].*\n.*#\[account\(mut\)\]",
        ],
        anti_patterns=[
            r"constraint.*key\(\).*!=",
        ],
    ),

    # ── LOW ───────────────────────────────────────────────────────────────────

    SolanaRule(
        rule_id="missing-freeze-authority",
        title="Missing Freeze Authority Check",
        severity="LOW",
        category="token",
        description=(
            "Program interacts with a token mint without checking whether a "
            "freeze authority exists. If the mint has a freeze authority, "
            "that authority can freeze user token accounts."
        ),
        fix=(
            "Check mint.freeze_authority when operating on user funds. Warn "
            "users or add a constraint that the mint has no freeze authority: "
            "constraint = mint.freeze_authority == COption::None."
        ),
        confidence="Low",
        patterns=[r"Mint", r"mint\.key\(\)"],
        anti_patterns=[r"freeze_authority"],
    ),

    SolanaRule(
        rule_id="deprecated-anchor",
        title="Deprecated Anchor Patterns",
        severity="LOW",
        category="best-practices",
        description=(
            "Program uses deprecated Anchor patterns or old API versions that "
            "may have known issues or will break in future Anchor releases."
        ),
        fix=(
            "Upgrade to the latest Anchor version. Replace #[access_control] with "
            "Anchor constraints. Replace CpiContext::new_with_signer with the "
            "current API."
        ),
        confidence="Low",
        patterns=[
            r"#\[access_control\]",
            r"anchor_lang::solana_program",
            r"program_pack::Pack",
        ],
        anti_patterns=[],
    ),

    SolanaRule(
        rule_id="missing-event-emit",
        title="Missing Event Emission",
        severity="LOW",
        category="best-practices",
        description=(
            "State-changing instructions do not emit events. Without events, "
            "off-chain systems cannot reliably track program state changes, "
            "making auditing and monitoring difficult."
        ),
        fix=(
            "Add Anchor event structs and emit! macro calls for all significant "
            "state changes. Example: emit!(TransferEvent { from, to, amount })."
        ),
        confidence="Low",
        patterns=[
            r"emit!\(",
        ],
        anti_patterns=[
            r"emit!\(",
            r"#\[event\]",
        ],
    ),

    SolanaRule(
        rule_id="type-cosplay",
        title="Type Cosplay",
        severity="HIGH",
        category="access-control",
        description=(
            "Program deserializes an account as a type without checking that the "
            "account actually contains data of that type. An attacker can pass an "
            "account of a different type that happens to deserialize successfully."
        ),
        fix=(
            "Use Anchor's Account<'info, T> which checks the 8-byte discriminator "
            "prefix to ensure the account contains the correct type. Never use "
            "try_from_slice without first validating the account type."
        ),
        confidence="Medium",
        patterns=[
            r"try_from_slice\(",
            r"unpack\(",
            r"unpack_unchecked\(",
        ],
        anti_patterns=[
            r"Account<'info",
            r"discriminator",
        ],
    ),

    SolanaRule(
        rule_id="sysvar-account-check",
        title="Sysvar Not Verified",
        severity="MEDIUM",
        category="validation",
        description=(
            "Program uses a sysvar account (Clock, Rent, SlotHashes) passed as "
            "an instruction account without verifying it is actually the sysvar. "
            "An attacker can pass a fake sysvar account."
        ),
        fix=(
            "Use Anchor's Sysvar<'info, Clock> type which automatically verifies "
            "the sysvar address. Or check: require_keys_eq!(sysvar.key(), "
            "anchor_lang::solana_program::sysvar::clock::ID)."
        ),
        confidence="Low",
        patterns=[
            r"Clock::from_account_info",
            r"Rent::from_account_info",
            r"sysvar.*AccountInfo",
        ],
        anti_patterns=[
            r"Sysvar<'info",
            r"Clock::get\(\)",
            r"Rent::get\(\)",
        ],
    ),

    SolanaRule(
        rule_id="loss-of-precision",
        title="Loss of Precision in Division",
        severity="MEDIUM",
        category="arithmetic",
        description=(
            "Program performs integer division which truncates the result. "
            "In financial calculations, this can lead to systematic rounding "
            "that benefits attackers (e.g. always rounding in attacker's favor)."
        ),
        fix=(
            "Use mul-then-div ordering to preserve precision. Consider using "
            "u128 for intermediate calculations. For financial math, use a "
            "fixed-point library. Always round in the protocol's favor."
        ),
        confidence="Low",
        patterns=[
            r"\w+\s*/\s*\w+",
            r"/=\s*\w+",
        ],
        anti_patterns=[
            r"checked_div",
            r"u128",
            r"//.*precision",
        ],
    ),
]


# ─────────────────────────────────────────────────────────────────────────────
# Rule lookup helpers
# ─────────────────────────────────────────────────────────────────────────────

_RULE_BY_ID: dict[str, SolanaRule] = {r.rule_id: r for r in SOLANA_RULES}

_DEFAULT_RULE = SolanaRule(
    rule_id="unknown",
    title="Unknown Issue",
    severity="LOW",
    category="unknown",
    description="Unclassified security issue.",
    fix="Review this code manually.",
)


def get_rule(rule_id: str) -> SolanaRule:
    return _RULE_BY_ID.get(rule_id, _DEFAULT_RULE)


def get_rules_by_severity(severity: str) -> list[SolanaRule]:
    return [r for r in SOLANA_RULES if r.severity == severity.upper()]


def get_rules_by_category(category: str) -> list[SolanaRule]:
    return [r for r in SOLANA_RULES if r.category == category.lower()]


# ─────────────────────────────────────────────────────────────────────────────
# Scoring
# ─────────────────────────────────────────────────────────────────────────────

_SEVERITY_SCORES = {"CRITICAL": 35, "HIGH": 20, "MEDIUM": 10, "LOW": 3}


def compute_solana_risk_score(findings: list[dict]) -> int:
    score = 0
    for f in findings:
        base  = _SEVERITY_SCORES.get(f.get("severity", "LOW"), 3)
        occ   = min(f.get("occurrences", 1), 5)
        score += base + (occ - 1) * 2
    return min(score, 100)


# ─────────────────────────────────────────────────────────────────────────────
# Pattern scanning helpers
# ─────────────────────────────────────────────────────────────────────────────

# Pre-built patterns for solana_scanner.py to use
SOLANA_PATTERNS = [
    {
        "rule_id":      rule.rule_id,
        "patterns":     rule.patterns,
        "anti_patterns": rule.anti_patterns,
        "severity":     rule.severity,
        "confidence":   rule.confidence,
    }
    for rule in SOLANA_RULES
    if rule.patterns  # only rules that have regex patterns
]
