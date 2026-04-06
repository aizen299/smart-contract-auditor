"""
ChainAudit — Chain Registry
Defines all supported chains and detection logic.
Adding a new EVM chain requires only a new entry in SUPPORTED_CHAINS.
"""

from dataclasses import dataclass
from pathlib import Path


@dataclass
class ChainConfig:
    name: str
    chain_type: str        # "evm" | "solana"
    chain_id: int | None   # EVM chain ID, None for Solana
    display_name: str
    indicators: list[str]  # Source code indicators for auto-detection


SUPPORTED_CHAINS: dict[str, ChainConfig] = {
    "ethereum": ChainConfig(
        name="ethereum",
        chain_type="evm",
        chain_id=1,
        display_name="Ethereum",
        indicators=[],  # default EVM, no special indicators needed
    ),
    "arbitrum": ChainConfig(
        name="arbitrum",
        chain_type="evm",
        chain_id=42161,
        display_name="Arbitrum",
        indicators=[
            "ArbSys", "ArbGasInfo", "ArbRetryableTx",
            "nitro-contracts", "arbitrum", "L2CrossDomainMessenger",
            "AddressAliasHelper", "ArbOwner",
        ],
    ),
    "optimism": ChainConfig(
        name="optimism",
        chain_type="evm",
        chain_id=10,
        display_name="Optimism",
        indicators=[
            "OVM_", "xDomainMessageSender", "L2CrossDomainMessenger",
            "optimism", "Predeploys", "L1Block",
        ],
    ),
    "base": ChainConfig(
        name="base",
        chain_type="evm",
        chain_id=8453,
        display_name="Base",
        indicators=[
            "base-contracts", "L1Block", "BaseFeeVault",
            "SequencerFeeVault",
        ],
    ),
    "polygon": ChainConfig(
        name="polygon",
        chain_type="evm",
        chain_id=137,
        display_name="Polygon",
        indicators=[
            "IChildToken", "IPolygonZkEVM", "PolygonZkEVMBridge",
            "polygon", "matic",
        ],
    ),
    "bnb": ChainConfig(
        name="bnb",
        chain_type="evm",
        chain_id=56,
        display_name="BNB Chain",
        indicators=[
            "IStaking", "IBSCValidatorSet", "bsc",
        ],
    ),
    "avalanche": ChainConfig(
        name="avalanche",
        chain_type="evm",
        chain_id=43114,
        display_name="Avalanche",
        indicators=[
            "IAllowList", "NativeMinter", "avalanche", "avax",
        ],
    ),
    "solana": ChainConfig(
        name="solana",
        chain_type="solana",
        chain_id=None,
        display_name="Solana",
        indicators=[
            "anchor_lang", "solana_program", "AnchorSerialize",
            "#[program]", "AccountInfo", "ProgramResult",
        ],
    ),
}


def detect_chain_from_source(source: str) -> str:
    """
    Auto-detect chain from contract source code.
    Checks indicators in priority order — most specific first.
    Returns chain name string.
    """
    source_lower = source.lower()
    # L2/sidechain detection — check before generic EVM
    # Require 2+ indicator hits to avoid false positives
    priority_order = [
        "arbitrum", "optimism", "base",
        "polygon", "bnb", "avalanche",
    ]

    for chain_name in priority_order:
        cfg = SUPPORTED_CHAINS[chain_name]
        hits = sum(
            1 for indicator in cfg.indicators
            if indicator.lower() in source_lower
        )
        if hits >= 1:
            return chain_name

    return "ethereum"


def detect_chain_from_file(target: Path) -> str:
    """
    Detect chain from file extension and/or source content.
    .rs files → solana
    .sol files → EVM chain detected from source
    """
    if target.suffix == ".rs":
        return "solana"

    if target.suffix == ".sol":
        try:
            source = target.read_text(errors="ignore")
            return detect_chain_from_source(source)
        except Exception:
            return "ethereum"

    return "ethereum"


def get_chain(name: str) -> ChainConfig:
    """Get chain config by name. Falls back to ethereum."""
    return SUPPORTED_CHAINS.get(name.lower(), SUPPORTED_CHAINS["ethereum"])


def is_evm_chain(chain_name: str) -> bool:
    cfg = SUPPORTED_CHAINS.get(chain_name.lower())
    return cfg is not None and cfg.chain_type == "evm"


def is_solana_chain(chain_name: str) -> bool:
    return chain_name.lower() == "solana"


def list_chains() -> list[dict]:
    """Returns all supported chains for API responses."""
    return [
        {
            "name": cfg.name,
            "display_name": cfg.display_name,
            "chain_type": cfg.chain_type,
            "chain_id": cfg.chain_id,
        }
        for cfg in SUPPORTED_CHAINS.values()
    ]
