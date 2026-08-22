"""Shared pytest fixtures for the ChainAudit backend suite."""

import sys
from pathlib import Path

import pytest

# Ensure backend/ is importable so `import api` resolves.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


@pytest.fixture(autouse=True)
def reset_rate_limiter():
    """
    Clear the API rate-limiter state between tests.

    The limiter keys on client address, and every test shares TestClient's
    single "testclient" host, so without this the buckets accumulate across the
    suite and unrelated tests start failing with 429 depending on execution
    order. Tests that exercise the limiter itself drive it deliberately.
    """
    try:
        import api
    except Exception:
        # The API module is optional for tests that only touch the scanner.
        yield
        return

    api._rate_buckets.clear()
    api._last_sweep = 0.0
    yield
    api._rate_buckets.clear()
    api._last_sweep = 0.0


@pytest.fixture(autouse=True)
def auth_disabled_by_default(monkeypatch):
    """
    Run the suite with the scan endpoints open unless a test says otherwise.

    Most tests exercise scanning behaviour — validation, limits, findings — and
    would otherwise all collapse into 401s that assert nothing about the thing
    under test. Auth itself is covered explicitly in test_security.py, which
    re-enables it and drives real signed tokens.
    """
    try:
        import api
    except Exception:
        yield
        return

    monkeypatch.setattr(api, "REQUIRE_AUTH", False)
    yield
