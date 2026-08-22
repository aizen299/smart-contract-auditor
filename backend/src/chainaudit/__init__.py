"""ChainAudit — smart contract security scanner for EVM and Solana."""

from importlib.metadata import PackageNotFoundError, version as _version

try:
    # Single source of truth is [project].version in pyproject.toml, read back
    # from the installed distribution metadata. Nothing else hardcodes it.
    __version__ = _version("chainaudit")
except PackageNotFoundError:
    # Running from a source tree that was never pip-installed.
    __version__ = "0.0.0+dev"

__all__ = ["__version__"]
