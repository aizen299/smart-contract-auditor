"""
Security regression tests for the ChainAudit API.

Covers the hardening added around zip expansion, rate limiting, CORS and error
disclosure. Each test targets a specific failure mode that was previously
reachable by an unauthenticated caller.
"""

import io
import time as _time
import zipfile

import jwt as _jwt
import pytest
from fastapi.testclient import TestClient

import api


VALID_SOL = b"pragma solidity ^0.8.24;\ncontract A { uint256 x; }\n"
VALID_RS = b"use anchor_lang::prelude::*;\npub fn go() {}\n"


@pytest.fixture
def client():
    return TestClient(api.app)


def make_zip(entries: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    return buf.getvalue()


# ---------------------------------------------------------------------------
# Zip expansion limits
# ---------------------------------------------------------------------------

class TestZipExpansion:
    def test_highly_compressible_entry_is_rejected(self, client):
        """
        A zip bomb: a small upload that expands far past the per-file cap.

        The compressed archive is well under MAX_ZIP_SIZE, so the upload-size
        check alone lets it through; only the uncompressed check stops it.
        """
        bomb = b"A" * (4 * 1024 * 1024)  # 4MB of one byte -> compresses tiny
        payload = make_zip({"Bomb.sol": VALID_SOL + bomb})

        assert len(payload) < api.MAX_ZIP_SIZE, "test archive must pass the upload cap"

        resp = client.post(
            "/scan/zip",
            files={"file": ("bomb.zip", payload, "application/zip")},
        )
        assert resp.status_code == 400
        assert "per-file limit" in resp.json()["detail"]

    def test_archive_wide_total_is_enforced_across_types(self):
        """
        The total cap spans every entry, not each file type separately.

        Solidity and Rust names are checked in one call precisely so their
        expansions accumulate into a single budget.
        """
        big_sol = b"x" * (400 * 1024)   # under the 500KB .sol per-file cap
        big_rs = b"y" * (900 * 1024)    # under the 1MB .rs per-file cap
        entries = {f"C{i}.sol": big_sol for i in range(20)}
        entries.update({f"m{i}.rs": big_rs for i in range(20)})
        payload = make_zip(entries)

        zf = zipfile.ZipFile(io.BytesIO(payload))
        sol_names = [n for n in zf.namelist() if n.endswith(".sol")]
        rs_names = [n for n in zf.namelist() if n.endswith(".rs")]

        total = sum(zf.getinfo(n).file_size for n in sol_names + rs_names)
        assert total > api.MAX_UNCOMPRESSED_TOTAL

        with pytest.raises(Exception) as exc:
            api.check_zip_expansion(
                zf, [(sol_names, api.MAX_FILE_SIZE), (rs_names, api.MAX_RS_SIZE)]
            )
        assert "uncompressed" in str(exc.value.detail)

    def test_normal_archive_still_scans(self, client):
        payload = make_zip({"Ok.sol": VALID_SOL})
        resp = client.post(
            "/scan/zip",
            files={"file": ("ok.zip", payload, "application/zip")},
        )
        assert resp.status_code == 200

    def test_safe_zip_read_rejects_understated_header(self):
        """
        A declared size can lie; the read is bounded independently.

        check_zip_expansion trusts the central directory, so safe_zip_read
        re-checks what the decompressor actually produces.
        """
        payload = make_zip({"Big.sol": b"z" * 4096})
        zf = zipfile.ZipFile(io.BytesIO(payload))
        with pytest.raises(Exception) as exc:
            api.safe_zip_read(zf, "Big.sol", max_size=1024)
        assert "once decompressed" in str(exc.value.detail)

        # Within the limit it returns the bytes unchanged.
        assert api.safe_zip_read(zf, "Big.sol", max_size=8192) == b"z" * 4096


# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------

class TestRateLimit:
    def test_scan_endpoints_are_limited(self, client):
        limit = api.RATE_LIMIT_REQUESTS
        # Requests are rejected on validation but still consume budget, which is
        # the point: a cheap-to-reject request must not be free to repeat.
        for _ in range(limit):
            client.post("/scan", files={"file": ("x.txt", b"nope", "text/plain")})

        resp = client.post("/scan", files={"file": ("x.txt", b"nope", "text/plain")})
        assert resp.status_code == 429
        assert "Retry-After" in resp.headers
        assert int(resp.headers["Retry-After"]) >= 1

    def test_health_is_never_limited(self, client):
        """Uptime monitoring pings /health continuously and must not be throttled."""
        for _ in range(api.RATE_LIMIT_REQUESTS * 3):
            assert client.get("/health").status_code == 200

    def test_limit_is_per_client(self, client):
        for _ in range(api.RATE_LIMIT_REQUESTS + 1):
            client.post("/scan", files={"file": ("x.txt", b"nope", "text/plain")})

        # A different forwarded address gets its own budget.
        resp = client.post(
            "/scan",
            files={"file": ("x.txt", b"nope", "text/plain")},
            headers={"X-Forwarded-For": "203.0.113.9"},
        )
        assert resp.status_code != 429

    def test_idle_buckets_are_swept(self):
        """The key set must not grow for the lifetime of the process."""
        api._rate_buckets.clear()
        api._last_sweep = 0.0
        for i in range(50):
            api._check_rate_limit(f"10.0.0.{i}")
        assert len(api._rate_buckets) == 50

        # Age every bucket past the window, then force a sweep.
        for bucket in api._rate_buckets.values():
            bucket[0] -= api.RATE_LIMIT_WINDOW * 2
        api._last_sweep = 0.0
        api._check_rate_limit("10.0.0.254")

        assert len(api._rate_buckets) == 1, "stale buckets should have been dropped"


# ---------------------------------------------------------------------------
# CORS and error disclosure
# ---------------------------------------------------------------------------

class TestCorsConfiguration:
    def test_origins_are_not_wildcarded(self):
        assert "*" not in api.ALLOWED_ORIGINS

    def test_credentials_are_disabled(self):
        """
        Wildcard origin plus credentials is rejected by browsers outright, so
        the two settings must never drift back together.
        """
        cors = [m for m in api.app.user_middleware if "CORSMiddleware" in str(m)]
        assert cors, "CORS middleware should be installed"
        assert cors[0].kwargs["allow_credentials"] is False

    def test_methods_are_restricted(self):
        cors = [m for m in api.app.user_middleware if "CORSMiddleware" in str(m)][0]
        assert "DELETE" not in cors.kwargs["allow_methods"]
        assert "*" not in cors.kwargs["allow_methods"]


class TestErrorDisclosure:
    def test_rust_scan_failure_does_not_leak_internals(self, client, monkeypatch):
        """
        The 500 detail must stay generic — this endpoint is unauthenticated and
        exception text carries filesystem paths and tool internals.
        """
        def boom(*args, **kwargs):
            raise RuntimeError("/srv/secret/path/internal detail leaked")

        monkeypatch.setattr(api, "run_solana_scan", boom)

        resp = client.post(
            "/scan/rust",
            files={"file": ("lib.rs", VALID_RS, "text/plain")},
        )
        assert resp.status_code == 500
        detail = resp.json()["detail"]
        assert detail == "Unexpected error during scan."
        assert "secret" not in detail
        assert "RuntimeError" not in detail


# ---------------------------------------------------------------------------
# Supabase JWT authentication
# ---------------------------------------------------------------------------

# 32+ bytes: PyJWT warns below the RFC 7518 minimum for SHA256.
TEST_SECRET = "test-jwt-secret-not-a-real-one-0123456789"


def make_token(**overrides) -> str:
    """Mint a Supabase-shaped access token for testing."""
    claims = {
        "sub": "11111111-2222-3333-4444-555555555555",
        "email": "scanner@example.com",
        "aud": "authenticated",
        "exp": int(_time.time()) + 3600,
    }
    claims.update(overrides)
    secret = overrides.pop("_secret", TEST_SECRET)
    return _jwt.encode(claims, secret, algorithm="HS256")


@pytest.fixture
def auth_enabled(monkeypatch):
    monkeypatch.setattr(api, "REQUIRE_AUTH", True)
    monkeypatch.setattr(api, "SUPABASE_JWT_SECRET", TEST_SECRET)


class TestAuthentication:
    def test_scan_requires_a_token(self, client, auth_enabled):
        resp = client.post("/scan", files={"file": ("a.sol", VALID_SOL, "text/plain")})
        assert resp.status_code == 401
        assert "Sign in" in resp.json()["detail"]

    def test_valid_token_is_accepted(self, client, auth_enabled):
        resp = client.post(
            "/scan",
            files={"file": ("a.sol", VALID_SOL, "text/plain")},
            headers={"Authorization": f"Bearer {make_token()}"},
        )
        assert resp.status_code != 401, "a correctly signed token must pass the guard"

    def test_expired_token_is_rejected(self, client, auth_enabled):
        expired = make_token(exp=int(_time.time()) - 60)
        resp = client.post(
            "/scan",
            files={"file": ("a.sol", VALID_SOL, "text/plain")},
            headers={"Authorization": f"Bearer {expired}"},
        )
        assert resp.status_code == 401
        assert "expired" in resp.json()["detail"].lower()

    def test_token_signed_with_wrong_secret_is_rejected(self, client, auth_enabled):
        """The whole point: a self-minted token must not be accepted."""
        forged = _jwt.encode(
            {
                "sub": "attacker",
                "aud": "authenticated",
                "exp": int(_time.time()) + 3600,
            },
            "attacker-chosen-secret-padded-to-32-bytes",
            algorithm="HS256",
        )
        resp = client.post(
            "/scan",
            files={"file": ("a.sol", VALID_SOL, "text/plain")},
            headers={"Authorization": f"Bearer {forged}"},
        )
        assert resp.status_code == 401

    def test_unsigned_alg_none_token_is_rejected(self, client, auth_enabled):
        """`alg: none` is the classic JWT bypass; only HS256 is accepted."""
        unsigned = _jwt.encode(
            {
                "sub": "attacker",
                "aud": "authenticated",
                "exp": int(_time.time()) + 3600,
            },
            key="",
            algorithm="none",
        )
        resp = client.post(
            "/scan",
            files={"file": ("a.sol", VALID_SOL, "text/plain")},
            headers={"Authorization": f"Bearer {unsigned}"},
        )
        assert resp.status_code == 401

    def test_wrong_audience_is_rejected(self, client, auth_enabled):
        resp = client.post(
            "/scan",
            files={"file": ("a.sol", VALID_SOL, "text/plain")},
            headers={"Authorization": f"Bearer {make_token(aud='anon')}"},
        )
        assert resp.status_code == 401

    def test_malformed_authorization_header_is_rejected(self, client, auth_enabled):
        for header in ["", "Bearer", "Bearer   ", "Basic abc", make_token()]:
            resp = client.post(
                "/scan",
                files={"file": ("a.sol", VALID_SOL, "text/plain")},
                headers={"Authorization": header},
            )
            assert resp.status_code == 401, f"header {header!r} should not authenticate"

    def test_missing_secret_fails_closed(self, client, monkeypatch):
        """
        An unconfigured server must refuse to scan, not accept everyone.
        """
        monkeypatch.setattr(api, "REQUIRE_AUTH", True)
        monkeypatch.setattr(api, "SUPABASE_JWT_SECRET", "")
        resp = client.post(
            "/scan",
            files={"file": ("a.sol", VALID_SOL, "text/plain")},
            headers={"Authorization": f"Bearer {make_token()}"},
        )
        assert resp.status_code == 503
        assert resp.status_code != 200

    def test_all_scan_endpoints_are_guarded(self, client, auth_enabled):
        for path, payload in [
            ("/scan", ("a.sol", VALID_SOL)),
            ("/scan/rust", ("lib.rs", VALID_RS)),
            ("/scan/zip", ("a.zip", make_zip({"A.sol": VALID_SOL}))),
        ]:
            resp = client.post(path, files={"file": (*payload, "application/octet-stream")})
            assert resp.status_code == 401, f"{path} is not guarded"

    def test_health_stays_public(self, client, auth_enabled):
        assert client.get("/health").status_code == 200
        assert client.get("/chains").status_code == 200
