from fastapi import Depends, FastAPI, UploadFile, File, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool
from collections import defaultdict, deque
from typing import NamedTuple
import logging
import os
import sys
import threading
import time
import uuid
import shutil
import zipfile
import io
from pathlib import Path

import jwt

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# The scanner package lives under backend/src and is imported as
# `src.chainaudit.*` here (the CLI imports the same modules relatively, as the
# installed `chainaudit` package). This must happen once at import time — doing
# it per request appended a duplicate entry to sys.path on every scan.
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from src.chainaudit.scanner_router import route_scan  # noqa: E402

logging.basicConfig(
    level=os.environ.get("CHAINAUDIT_LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
log = logging.getLogger("chainaudit.api")

app = FastAPI()

# ─────────────────────────────────────────────────────────────────────────────
# Authentication
#
# /scan* requires a Supabase access token. Previously signing in only gated scan
# history while scanning itself was open to anyone with the Render URL, so login
# carried no security meaning.
#
# Two verification modes, because Supabase is mid-migration between them:
#
#   JWKS (preferred) — projects now sign with asymmetric keys (ES256 over ECC
#     P-256, or RS256). There is no shared secret to hold; the public keys are
#     fetched once from the project's JWKS endpoint and cached, so steady-state
#     verification is still local. Set SUPABASE_URL and the endpoint is derived,
#     or set SUPABASE_JWKS_URL explicitly.
#
#   HS256 (legacy) — older projects sign with a single shared secret. Set
#     SUPABASE_JWT_SECRET. Note that a project which has rotated to asymmetric
#     keys keeps its old HS256 secret listed only to verify already-issued
#     tokens; configuring it there would reject every current login.
#
# JWKS wins if both are set. Fails closed: with neither configured the scan
# endpoints return 503 rather than silently accepting everything. Set
# CHAINAUDIT_REQUIRE_AUTH=false to deliberately run an open instance.
# ─────────────────────────────────────────────────────────────────────────────

SUPABASE_JWT_SECRET = os.environ.get("SUPABASE_JWT_SECRET", "")
SUPABASE_URL = os.environ.get("SUPABASE_URL", "").rstrip("/")
SUPABASE_JWKS_URL = os.environ.get(
    "SUPABASE_JWKS_URL",
    f"{SUPABASE_URL}/auth/v1/.well-known/jwks.json" if SUPABASE_URL else "",
)
REQUIRE_AUTH = os.environ.get("CHAINAUDIT_REQUIRE_AUTH", "true").lower() != "false"
# Supabase stamps this audience on user tokens.
_JWT_AUDIENCE = os.environ.get("SUPABASE_JWT_AUDIENCE", "authenticated")
# Asymmetric algorithms Supabase issues. HS256 is deliberately absent: allowing
# it alongside JWKS would let a caller present an HS256 token signed with a
# public key as the HMAC secret — the classic algorithm-confusion attack.
_ASYMMETRIC_ALGS = ["ES256", "RS256"]

_jwk_client: "jwt.PyJWKClient | None" = None
_jwk_lock = threading.Lock()

if REQUIRE_AUTH and not (SUPABASE_JWKS_URL or SUPABASE_JWT_SECRET):
    log.critical(
        "CHAINAUDIT_REQUIRE_AUTH is on but neither SUPABASE_URL/SUPABASE_JWKS_URL "
        "nor SUPABASE_JWT_SECRET is set — scan endpoints will return 503 until "
        "one is configured. Set CHAINAUDIT_REQUIRE_AUTH=false to run an "
        "intentionally open instance."
    )


class AuthenticatedUser(NamedTuple):
    user_id: str
    email: str | None


def _bearer_token(request: Request) -> str | None:
    header = request.headers.get("authorization", "")
    scheme, _, token = header.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        return None
    return token.strip()


def _get_jwk_client() -> "jwt.PyJWKClient":
    """
    Lazily build the JWKS client, shared across requests.

    PyJWKClient caches the key set and refetches when it sees an unknown `kid`,
    so key rotation is picked up without a redeploy and the common path stays a
    local signature check. Built under a lock because scans run in a threadpool.
    """
    global _jwk_client
    with _jwk_lock:
        if _jwk_client is None:
            _jwk_client = jwt.PyJWKClient(SUPABASE_JWKS_URL, cache_keys=True)
        return _jwk_client


def verify_token(token: str) -> AuthenticatedUser:
    """Decode and validate a Supabase access token. Raises HTTPException on failure."""
    try:
        if SUPABASE_JWKS_URL:
            try:
                signing_key = _get_jwk_client().get_signing_key_from_jwt(token).key
            except jwt.exceptions.PyJWKClientConnectionError as exc:
                # The JWKS endpoint is unreachable. Nothing is wrong with the
                # caller's credential, so this must not masquerade as a 401 and
                # tell a signed-in user to sign in again.
                log.error("JWKS endpoint unreachable: %s", exc)
                raise HTTPException(503, "Authentication is temporarily unavailable.")
            except jwt.exceptions.PyJWKClientError as exc:
                # The key set loaded but holds no key for this token's `kid` —
                # a token from another project, a hand-made one, or one signed
                # by a key that has since been revoked. That is a bad
                # credential, not an outage.
                log.warning("No JWKS key matches the presented token: %s", exc)
                raise HTTPException(401, "Invalid authentication token.")
            claims = jwt.decode(
                token,
                signing_key,
                algorithms=_ASYMMETRIC_ALGS,
                audience=_JWT_AUDIENCE,
                options={"require": ["exp", "sub"]},
            )
        else:
            claims = jwt.decode(
                token,
                SUPABASE_JWT_SECRET,
                algorithms=["HS256"],
                # Signature, expiry and audience are all enforced. `sub` is
                # required because it is the identity logs key on.
                audience=_JWT_AUDIENCE,
                options={"require": ["exp", "sub"]},
            )
    except jwt.ExpiredSignatureError:
        raise HTTPException(401, "Session expired. Sign in again.")
    except jwt.InvalidTokenError:
        # Deliberately not echoing the library's reason — it distinguishes
        # "bad signature" from "wrong audience" for an unauthenticated caller.
        raise HTTPException(401, "Invalid authentication token.")

    return AuthenticatedUser(
        user_id=str(claims["sub"]),
        email=claims.get("email"),
    )


async def require_user(request: Request) -> AuthenticatedUser | None:
    """FastAPI dependency guarding the scan endpoints."""
    if not REQUIRE_AUTH:
        return None

    if not (SUPABASE_JWKS_URL or SUPABASE_JWT_SECRET):
        raise HTTPException(503, "Authentication is not configured on this server.")

    token = _bearer_token(request)
    if not token:
        raise HTTPException(401, "Sign in to run a scan.")

    return verify_token(token)


# ─────────────────────────────────────────────────────────────────────────────
# Rate limiting
#
# Every scan spawns Slither / cargo-audit subprocesses, so an unauthenticated
# caller can drive real CPU cost with a one-line loop. This is a sliding window
# per client, held in process memory — adequate for the single-worker deployment
# this service runs as, and deliberately dependency-free. It is abuse control,
# not an authentication substitute: X-Forwarded-For is attacker-controllable in
# general, and is only trusted here because Render terminates TLS in front of
# the app and rewrites it. Multi-worker or multi-instance deployments need a
# shared store (Redis) instead.
# ─────────────────────────────────────────────────────────────────────────────

RATE_LIMIT_REQUESTS = int(os.environ.get("CHAINAUDIT_RATE_LIMIT_REQUESTS", "10"))
RATE_LIMIT_WINDOW   = int(os.environ.get("CHAINAUDIT_RATE_LIMIT_WINDOW", "60"))
_RATE_LIMITED_PREFIXES = ("/scan",)

_rate_lock = threading.Lock()
_rate_buckets: dict[str, deque] = defaultdict(deque)


def _client_key(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


_last_sweep = 0.0


def _sweep_locked(now: float) -> None:
    """Drop buckets with no activity in the window. Caller must hold _rate_lock.

    Without this the key set grows for the process lifetime, since a bucket
    belonging to a client that never returns is otherwise never touched again.
    """
    global _last_sweep
    if now - _last_sweep < RATE_LIMIT_WINDOW:
        return
    cutoff = now - RATE_LIMIT_WINDOW
    for key in [k for k, b in _rate_buckets.items() if not b or b[-1] < cutoff]:
        del _rate_buckets[key]
    _last_sweep = now


def _check_rate_limit(key: str) -> int | None:
    """Record a hit. Returns seconds to wait if the caller is over budget."""
    now = time.monotonic()
    cutoff = now - RATE_LIMIT_WINDOW
    with _rate_lock:
        _sweep_locked(now)
        bucket = _rate_buckets[key]
        while bucket and bucket[0] < cutoff:
            bucket.popleft()
        if len(bucket) >= RATE_LIMIT_REQUESTS:
            return max(1, int(bucket[0] + RATE_LIMIT_WINDOW - now))
        bucket.append(now)
    return None


@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    # Health and info endpoints stay unlimited so uptime monitoring is unaffected.
    if not request.url.path.startswith(_RATE_LIMITED_PREFIXES):
        return await call_next(request)

    key = _client_key(request)
    retry_after = _check_rate_limit(key)
    if retry_after is not None:
        log.warning("Rate limit exceeded for %s on %s", key, request.url.path)
        return JSONResponse(
            status_code=429,
            content={
                "detail": (
                    f"Rate limit exceeded: {RATE_LIMIT_REQUESTS} scans per "
                    f"{RATE_LIMIT_WINDOW}s. Retry in {retry_after}s."
                )
            },
            headers={"Retry-After": str(retry_after)},
        )
    return await call_next(request)


# `allow_origins=["*"]` together with `allow_credentials=True` is rejected by
# browsers — a wildcard origin cannot be used on a credentialed request — so the
# previous configuration was permissive in intent and broken in effect. The
# browser never talks to this service directly anyway: the Next.js app proxies
# /api/scan* server-side via rewrites. Credentials are therefore off, and the
# origin list is explicit for anyone calling the API directly.
_DEFAULT_ORIGINS = "https://chainaudit.vercel.app,http://localhost:3000"
ALLOWED_ORIGINS = [
    origin.strip()
    for origin in os.environ.get("CHAINAUDIT_ALLOWED_ORIGINS", _DEFAULT_ORIGINS).split(",")
    if origin.strip()
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "HEAD", "POST"],
    allow_headers=["Content-Type"],
)

TEMP_DIR = os.path.join(BASE_DIR, "tmp_scans")
os.makedirs(TEMP_DIR, exist_ok=True)

MAX_FILE_SIZE = 500 * 1024        # 500KB per .sol
MAX_ZIP_SIZE  = 5 * 1024 * 1024   # 5MB zip (compressed, as uploaded)
MAX_SOL_FILES = 20
MAX_RS_FILES  = 20
MAX_RS_SIZE   = 1024 * 1024       # 1MB per .rs file

# MAX_ZIP_SIZE caps only the *compressed* upload. Decompression is what actually
# allocates memory, and a 5MB archive can expand to many gigabytes, so the
# uncompressed side needs its own ceiling — both per entry and across the whole
# archive — checked from the zip index before any entry is read.
MAX_UNCOMPRESSED_TOTAL = 20 * 1024 * 1024   # 20MB expanded across the archive



def is_valid_solidity(content: bytes) -> bool:
    try:
        text = content.decode("utf-8")
        return any(kw in text for kw in
                   ["pragma solidity", "contract ", "interface ", "library "])
    except UnicodeDecodeError:
        return False


def check_zip_expansion(
    zf: zipfile.ZipFile,
    groups: list[tuple[list[str], int]],
) -> None:
    """
    Reject an archive whose declared uncompressed size is out of bounds.

    `groups` pairs each set of entry names with its per-file ceiling. All groups
    are counted against one archive-wide total: checking each group separately
    would let the combined expansion reach the sum of the per-group caps.

    Sizes come from the central directory, so nothing is decompressed to find
    out that it is too large. Raises HTTPException on violation.
    """
    total = 0
    for names, per_entry_max in groups:
        for name in names:
            try:
                info = zf.getinfo(name)
            except KeyError:
                continue
            if info.file_size > per_entry_max:
                raise HTTPException(
                    400,
                    f"'{os.path.basename(name)}' expands to "
                    f"{info.file_size // 1024}KB, over the "
                    f"{per_entry_max // 1024}KB per-file limit.",
                )
            total += info.file_size
            if total > MAX_UNCOMPRESSED_TOTAL:
                raise HTTPException(
                    400,
                    "Archive expands to more than "
                    f"{MAX_UNCOMPRESSED_TOTAL // (1024 * 1024)}MB uncompressed.",
                )


def safe_zip_read(zf: zipfile.ZipFile, name: str, max_size: int) -> bytes:
    """
    Read one entry, refusing to buffer more than max_size bytes.

    check_zip_expansion trusts the sizes declared in the central directory;
    this re-checks against what actually comes out of the decompressor, so a
    header that understates the real size cannot get past both.
    """
    with zf.open(name) as handle:
        data = handle.read(max_size + 1)
    if len(data) > max_size:
        raise HTTPException(
            400,
            f"'{os.path.basename(name)}' exceeds the "
            f"{max_size // 1024}KB limit once decompressed.",
        )
    return data


def is_valid_rust(content: bytes) -> bool:
    try:
        text = content.decode("utf-8")
        return any(kw in text for kw in
                   ["fn ", "use anchor_lang", "use solana_program",
                    "pub mod", "#[program]"])
    except UnicodeDecodeError:
        return False


# ─────────────────────────────────────────────────────────────────────────────
# Core scan function — uses scanner_router for all EVM scans
# ─────────────────────────────────────────────────────────────────────────────

def run_scan(contract_path: str, scan_id: str) -> dict | None:
    """
    EVM scan via scanner_router.
    Returns result dict or None on failure.
    """
    try:
        result = route_scan(Path(contract_path))
        if result.get("status") == "error":
            log.warning(
                "EVM scan reported an error (scan_id=%s): %s",
                scan_id, result.get("error"),
            )
            return None
        result["scan_id"] = scan_id
        return result
    except Exception:
        # Returning None collapses every failure into a single 422 for the
        # caller, so the cause has to be recorded here or it is lost entirely.
        log.exception("EVM scan raised (scan_id=%s, path=%s)", scan_id, contract_path)
        return None


def run_solana_scan(rs_path: Path) -> dict:
    """Solana scan via scanner_router."""
    return route_scan(rs_path)


# ─────────────────────────────────────────────────────────────────────────────
# Health + info endpoints
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/")
async def root():
    return {"status": "ok", "service": "ChainAudit API"}


@app.head("/")
async def root_head():
    return Response(status_code=200)


@app.get("/health")
async def health():
    return {"status": "healthy"}


@app.head("/health")
async def health_head():
    return Response(status_code=200)


@app.get("/chains")
async def list_chains():
    """Return all supported chains."""
    from src.chainaudit.chain_registry import list_chains
    return {"chains": list_chains()}


# ─────────────────────────────────────────────────────────────────────────────
# /scan — single Solidity file
# ─────────────────────────────────────────────────────────────────────────────

@app.post("/scan")
async def scan_contract(
    file: UploadFile = File(...),
    user: AuthenticatedUser | None = Depends(require_user),
):
    if not file.filename or not file.filename.endswith(".sol"):
        raise HTTPException(400, "Invalid file type. Only .sol files are accepted.")

    content = await file.read()

    if not content:
        raise HTTPException(400, "File is empty.")
    if len(content) > MAX_FILE_SIZE:
        raise HTTPException(400, f"File too large. Maximum is {MAX_FILE_SIZE // 1024}KB.")
    if not is_valid_solidity(content):
        raise HTTPException(400, "File does not appear to be valid Solidity.")

    scan_id  = str(uuid.uuid4())
    scan_dir = Path(TEMP_DIR) / scan_id
    scan_dir.mkdir(parents=True, exist_ok=True)
    contract_path = scan_dir / "input.sol"

    try:
        contract_path.write_bytes(content)
        report = await run_in_threadpool(run_scan, str(contract_path), scan_id)

        if report is None:
            raise HTTPException(
                422,
                "Could not analyse contract. It may contain syntax errors or "
                "use an unsupported Solidity version.",
            )

        report["file_name"] = file.filename
        return report

    except HTTPException:
        raise
    except Exception:
        raise HTTPException(500, "Unexpected error during scan.")
    finally:
        shutil.rmtree(scan_dir, ignore_errors=True)


# ─────────────────────────────────────────────────────────────────────────────
# /scan/rust — single Rust/Solana file
# ─────────────────────────────────────────────────────────────────────────────

@app.post("/scan/rust")
async def scan_rust(
    file: UploadFile = File(...),
    user: AuthenticatedUser | None = Depends(require_user),
):
    if not file.filename or not file.filename.endswith(".rs"):
        raise HTTPException(400, "Invalid file type. Only .rs files are accepted.")

    content = await file.read()

    if not content:
        raise HTTPException(400, "File is empty.")
    if len(content) > MAX_RS_SIZE:
        raise HTTPException(400, f"File too large. Maximum is {MAX_RS_SIZE // 1024}KB.")
    if not is_valid_rust(content):
        raise HTTPException(400, "File does not appear to be valid Rust/Solana code.")

    scan_id  = str(uuid.uuid4())
    scan_dir = Path(TEMP_DIR) / scan_id
    scan_dir.mkdir(parents=True, exist_ok=True)
    rs_path  = scan_dir / file.filename

    try:
        rs_path.write_bytes(content)
        report = await run_in_threadpool(run_solana_scan, rs_path)

        if report.get("status") == "error":
            raise HTTPException(422, report.get("error", "Could not analyse Rust file."))

        report["scan_id"]   = scan_id
        report["file_name"] = file.filename
        return report

    except HTTPException:
        raise
    except Exception:
        # Detail deliberately generic and matching /scan — the exception text
        # carries filesystem paths and tool internals, and this endpoint is
        # reachable unauthenticated. The traceback goes to the log instead.
        log.exception("Unexpected error during Rust scan (scan_id=%s)", scan_id)
        raise HTTPException(500, "Unexpected error during scan.")
    finally:
        shutil.rmtree(scan_dir, ignore_errors=True)


# ─────────────────────────────────────────────────────────────────────────────
# /scan/zip — zip of .sol and/or .rs files
# ─────────────────────────────────────────────────────────────────────────────

@app.post("/scan/zip")
async def scan_zip(
    file: UploadFile = File(...),
    user: AuthenticatedUser | None = Depends(require_user),
):
    if not file.filename or not file.filename.endswith(".zip"):
        raise HTTPException(400, "Invalid file type. Only .zip files are accepted.")

    content = await file.read()

    if not content:
        raise HTTPException(400, "File is empty.")
    if len(content) > MAX_ZIP_SIZE:
        raise HTTPException(400, f"Zip too large. Maximum is {MAX_ZIP_SIZE // (1024*1024)}MB.")

    try:
        zf = zipfile.ZipFile(io.BytesIO(content))
    except zipfile.BadZipFile:
        raise HTTPException(400, "Invalid zip file.")

    sol_names = [
        n for n in zf.namelist()
        if n.endswith(".sol")
        and not n.startswith("__MACOSX")
        and "node_modules" not in n
        and "/lib/" not in n
        and "/test/" not in n
        and "/mock/" not in n
        and "/mocks/" not in n
        and not os.path.basename(n).startswith(".")
    ]
    rs_names = [
        n for n in zf.namelist()
        if n.endswith(".rs")
        and not n.startswith("__MACOSX")
        and "target/" not in n
        and not os.path.basename(n).startswith(".")
    ]

    if not sol_names and not rs_names:
        raise HTTPException(400, "No Solidity or Rust files found in the zip.")
    if len(sol_names) > MAX_SOL_FILES:
        raise HTTPException(400, f"Too many Solidity files. Maximum is {MAX_SOL_FILES}.")
    if len(rs_names) > MAX_RS_FILES:
        raise HTTPException(400, f"Too many Rust files. Maximum is {MAX_RS_FILES}.")

    # Reject zip bombs before decompressing anything.
    check_zip_expansion(zf, [(sol_names, MAX_FILE_SIZE), (rs_names, MAX_RS_SIZE)])

    scan_id  = str(uuid.uuid4())
    scan_dir = Path(TEMP_DIR) / scan_id
    scan_dir.mkdir(parents=True, exist_ok=True)

    results      = []
    all_findings = []
    total_risk   = 0

    try:
        # ── Solidity files ────────────────────────────────────────────────────
        for idx, sol_name in enumerate(sol_names):
            file_content = safe_zip_read(zf, sol_name, MAX_FILE_SIZE)
            basename     = os.path.basename(sol_name)

            if not is_valid_solidity(file_content):
                results.append({
                    "file": basename, "status": "skipped",
                    "reason": "Not valid Solidity",
                    "risk_score": 0, "findings": [],
                })
                continue

            file_scan_id  = f"{scan_id}_{idx}"
            file_dir      = scan_dir / f"sol_{idx}"
            file_dir.mkdir(exist_ok=True)

            # FIX: save with original basename (not "input.sol") so that
            # detect_chain_from_file() can read the source content and
            # correctly identify the chain (Arbitrum, Optimism, etc.)
            contract_path = file_dir / basename
            contract_path.write_bytes(file_content)

            try:
                report = await run_in_threadpool(run_scan, str(contract_path), file_scan_id)
                if report is None:
                    results.append({
                        "file": basename, "status": "error",
                        "reason": "Slither could not analyse this file",
                        "risk_score": 0, "findings": [],
                    })
                else:
                    chain = report.get("chain", "ethereum")
                    entry = {
                        "file":           basename,
                        "status":         "success",
                        "chain":          chain,
                        "risk_score":     report["risk_score"],
                        "total_findings": report["total_findings"],
                        "findings":       report["findings"],
                    }
                    results.append(entry)
                    all_findings.extend(report["findings"])
                    total_risk = max(total_risk, report["risk_score"])

            except Exception:
                results.append({
                    "file": basename, "status": "timeout",
                    "reason": "Scan timed out",
                    "risk_score": 0, "findings": [],
                })

        # ── Rust files ────────────────────────────────────────────────────────
        if rs_names:
            rs_dir = scan_dir / "rust_files"
            rs_dir.mkdir(exist_ok=True)

            for rs_name in rs_names:
                rs_content  = safe_zip_read(zf, rs_name, MAX_RS_SIZE)
                rs_basename = os.path.basename(rs_name)
                rs_path     = rs_dir / rs_basename
                rs_path.write_bytes(rs_content)

                if not is_valid_rust(rs_content):
                    results.append({
                        "file": rs_basename, "status": "skipped",
                        "reason": "Not valid Rust/Solana code",
                        "chain": "solana", "risk_score": 0, "findings": [],
                    })
                    continue

                try:
                    isolated_dir = rs_dir / rs_basename.replace('.rs', '_scan')
                    isolated_dir.mkdir(exist_ok=True)
                    isolated_file = isolated_dir / rs_basename
                    isolated_file.write_bytes(rs_content)
                    rs_report = await run_in_threadpool(run_solana_scan, isolated_file)
                    results.append({
                        "file":           rs_basename,
                        "status":         rs_report.get("status", "success"),
                        "chain":          "solana",
                        "is_anchor":      rs_report.get("is_anchor", False),
                        "risk_score":     rs_report.get("risk_score", 0),
                        "total_findings": rs_report.get("total_findings", 0),
                        "findings":       rs_report.get("findings", []),
                    })
                    all_findings.extend(rs_report.get("findings", []))
                    total_risk = max(total_risk, rs_report.get("risk_score", 0))
                except Exception as e:
                    results.append({
                        "file": rs_basename, "status": "error",
                        "reason": f"Solana scanner error: {e}",
                        "chain": "solana", "risk_score": 0, "findings": [],
                    })

        return {
            "scan_id":            scan_id,
            "type":               "multi",
            "total_files":        len(sol_names) + len(rs_names),
            "scanned":            sum(1 for r in results if r["status"] == "success"),
            # Highest single-file score, deliberately not an aggregate. One
            # critical contract is what decides whether a deployment is safe, so
            # averaging or summing across files would dilute exactly the signal
            # `fail-on-critical` depends on. `files_at_risk` carries the breadth
            # that the single number cannot.
            "overall_risk_score": total_risk,
            "files_at_risk": sum(
                1 for r in results
                if r.get("status") == "success" and r.get("risk_score", 0) > 0
            ),
            "total_findings":     len(all_findings),
            "has_solana":         bool(rs_names),
            "has_evm":            bool(sol_names),
            "files":              results,
        }

    finally:
        shutil.rmtree(scan_dir, ignore_errors=True)