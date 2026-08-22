# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

ChainAudit — a smart contract security scanner published three ways from one codebase:

- **`chainaudit` PyPI CLI** (`backend/src/chainaudit/`) — the core scanner
- **FastAPI service** (`backend/api.py`) — HTTP wrapper around the same scanner, deployed on Render
- **GitHub Action** (`action.yml`) — composite action that pip-installs the backend and runs the CLI

The Next.js app in `frontend/` is a separate deployable (Vercel) that talks to the FastAPI service.

## Commands

### Backend

```bash
cd backend && python -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt
```

```bash
cd backend && uvicorn api:app --reload
```

Tests must run from `backend/` — `tests/test_cli.py` does `from api import app` and inserts `backend/` on `sys.path`:

```bash
cd backend && pytest tests/ -v
```

Single test or class:

```bash
cd backend && pytest tests/test_cli.py::TestSolanaScanner::test_pattern_scan_detects_missing_signer -v
```

Lint (matches CI):

```bash
cd backend && ruff check src/ api.py tests/
```

Install the CLI from source for local scanning:

```bash
cd backend && pip install -e .
```

Scanning requires external binaries on PATH: `slither` + `solc-select` (EVM), optionally `cargo-audit` / `cargo-geiger` (Solana). Each degrades gracefully when missing except Slither, without which EVM scans return `status: "error"` and log Slither's own stderr. `forge` is not used at all.

### Frontend

```bash
cd frontend && npm install && npm run dev
```

```bash
cd frontend && npm test
```

`npm run build`, `npm run lint`, `npx tsc --noEmit`, and `npm test` all run in CI and all block.

### Retraining the ML model

```bash
cd backend && python -m src.chainaudit.ml.train
```

Requires the SmartBugs dataset (git-ignored; cloned separately into `ml/smartbugs/`, or point `CHAINAUDIT_SMARTBUGS_DIR` elsewhere). `build_dataset()` raises with clone instructions if it is absent rather than training on nothing. It shells out to `solc-select` to switch compiler versions per contract and resets to 0.8.24 when done.

## Architecture

### Everything routes through `scanner_router`

`backend/src/chainaudit/scanner_router.py` is the single dispatcher. `cli.py` and `api.py` both call `route_scan(path)` — neither imports `evm_scanner` or `solana_scanner` directly, and new entry points should keep that discipline.

`route_scan` → `chain_registry.detect_chain_from_file()` → either `_scan_evm` or `_scan_solana`. Zip handling lives in the callers (`cli._handle_zip`, `api.scan_zip`), which drive per-file scans directly.

### Chain detection is two-tier and the tiers disagree on purpose

- `chain_registry.detect_chain_from_source()` — `>= 1` indicator hit picks the chain label (arbitrum/optimism/base/polygon/bnb/avalanche), defaulting to ethereum. Adding an EVM chain is one entry in `SUPPORTED_CHAINS`.
- `evm_rules.detect_l2_chain()` — `>= 2` hits from `L2_INDICATORS` before injecting L2 rules. The stricter threshold exists to stop empty/simple contracts from picking up 12 phantom L2 findings.

So a contract can be *labeled* arbitrum without getting L2 findings injected. That's intended.

### EVM pipeline (`evm_scanner.py` + `evm_rules.py`)

1. `run_slither()` shells out to `slither --json <per-scan temp file>` (90s timeout), logging Slither's stderr when no report appears.
2. `parse_slither_report()` maps each Slither `check` through `SLITHER_TO_RULE` → `RULES`; unmapped checks are **dropped**, and findings are deduplicated to one entry per rule id keeping the highest `impact` while accumulating `occurrences`.
3. L2 rules are injected post-hoc for detected L2 contracts — Slither has no detectors for these, so they are synthesized from source pattern matching, tagged `l2_detected: true`.
4. `compute_risk_score()` — CVSS-inspired: per-finding `cvss_base_score × confidence_weight × severity_multiplier`, summed, then `100 * (1 - exp(-total/80))`. Non-empty findings floor at 5.

Adding an EVM rule means touching **both** `RULES` (with `CvssFactors`) and `SLITHER_TO_RULE`. `tests/test_cli.py::TestRules::test_slither_to_rule_mapping_complete` enforces that every mapping target exists.

**Scans are concurrency-safe, and that is load-bearing.** The API runs scans via `run_in_threadpool`, so two can execute at once. `_scan_evm` therefore does *not* `os.chdir` and gives each scan its own Slither output file (`run_slither(..., json_path=...)`). The module-level `SLITHER_JSON` remains only as the default for tests. Reintroducing shared mutable state here silently corrupts concurrent results rather than failing loudly.

`exploit_simulation` no longer exists. It ran `forge test` against the package directory rather than the contract, with no timeout and no test files to run — removed rather than left as a field that always meant nothing. `--ml-only` is retained as an accepted no-op so the CLI surface is unchanged.

### Solana pipeline (`solana_scanner.py` + `solana_rules.py`)

Three layers, results deduplicated by `check` keeping the most severe:

1. `cargo audit --json` — RustSec CVEs from `Cargo.lock` (skipped if binary absent)
2. Regex pattern scan over `.rs` sources — the layer that always runs
3. `cargo geiger` — unsafe-code counting (skipped if absent)

`SOLANA_PATTERNS` is derived automatically from `SOLANA_RULES` entries that define `patterns`, so a new rule with regexes is live as soon as it's added to the list.

**Anti-pattern semantics matter:** in `_scan_file_patterns`, if *any* `anti_patterns` regex matches anywhere in the file, the finding is suppressed entirely. The count-vs-count version was reverted because it fired constantly on normal Anchor code. Tightening a pattern usually means broadening its anti-patterns, not narrowing the trigger.

Solana risk scoring is flat additive (`compute_solana_risk_score`), unrelated to the EVM CVSS math.

### ML exploitability layer

`ml/predictor.py` holds a lazily-loaded singleton (`predictor`) over `exploitability_model.joblib`. Every lookup table — feature encodings and the Solana→EVM check mapping — lives in **`ml/mapping.py`** and is imported by `predictor.py`, `train.py`, `cli.py` and `scanner_router.py`. They were previously duplicated across those four files; keep the single definition.

The model was trained on title-case Slither values (`"High"`, not `"HIGH"`), which is why callers capitalize before predicting. Solana findings have no native ML support: they're mapped through `SOLANA_TO_EVM_CHECK` to the nearest EVM check, falling back to the `SEVERITY_CONFIDENCE` table.

ML failure never fails a scan (`ml_exploitability: "unknown"`), but it is no longer silent: `predictor._load()` logs once, naming the installed scikit-learn, because an artifact that cannot be unpickled would otherwise disable the headline feature invisibly. `scikit-learn` is pinned to `>=1.8,<1.9` for that reason.

### API and frontend wiring

`api.py` exposes `/scan` (.sol), `/scan/rust` (.rs), `/scan/zip` (mixed), plus `/health` and `/chains`. Uploads are content-sniffed (`is_valid_solidity`/`is_valid_rust`), size- and count-capped, written under `backend/tmp_scans/<uuid>/`, and the directory is removed in a `finally`. Zip entries are additionally bounded on the *uncompressed* side by `check_zip_expansion` (pre-flight, from the central directory) and `safe_zip_read` (bounded read) — the compressed cap alone does not stop a zip bomb. Handlers are `async def` but hand the blocking scan to `run_in_threadpool`.

The frontend never calls the backend origin directly from the browser: `next.config.mjs` `rewrites()` proxy `/api/scan*` → `NEXT_PUBLIC_API_URL`. That's also why the CSP `connect-src` only lists Supabase. Supabase handles auth (middleware refreshes the session on every non-static request) and stores scan history in a `scans` table written client-side from `app/page.tsx` after a successful single-file scan.

**The scan API requires a Supabase JWT.** `require_user` (a FastAPI dependency on all three `/scan*` routes) verifies the bearer token with signature, `exp` and `aud` all enforced. Two modes, because Supabase is mid-migration:

- **JWKS** (this project's mode) — the token is ES256/RS256 signed by the project's asymmetric key. `PyJWKClient` fetches the public keys from `SUPABASE_URL`'s JWKS endpoint once and caches them, refetching only on an unseen `kid`, so steady-state verification is local and rotation needs no redeploy.
- **HS256** — legacy shared secret via `SUPABASE_JWT_SECRET`, for older or self-hosted projects.

JWKS wins when both are configured, which matters: a project that has rotated to signing keys still lists its old HS256 secret under "previously used keys", and verifying against it would reject every current login.

`_ASYMMETRIC_ALGS` deliberately excludes HS256. Accepting it alongside asymmetric algorithms is the algorithm-confusion attack — an attacker signs HS256 using the public key as the HMAC secret. `TestAsymmetricAuth` covers it.

Error taxonomy is load-bearing: an unreachable JWKS endpoint is a **503** (the caller's credential is fine), while a key set with no matching `kid` is a **401** (the credential is bad). Collapsing both into one status either tells signed-in users to re-login during an outage, or reports bad tokens as server faults.

It **fails closed**: with `CHAINAUDIT_REQUIRE_AUTH` on and neither variable set, scans return 503 rather than accepting everyone. `CHAINAUDIT_REQUIRE_AUTH=false` runs an intentionally open instance.

The frontend reads `session.access_token` in `app/page.tsx` and sends it as `Authorization: Bearer …`; Next's rewrite forwards the header to the backend. No session, or a 401 back, redirects to `/login`.

The rate limiter still keys on IP, not user id, and deliberately so: the middleware runs before the auth dependency, and trusting an unverified `sub` from the token would let an attacker mint a fresh bucket per request.

**Tests default to auth off.** `tests/conftest.py` sets `api.REQUIRE_AUTH = False` autouse, so scan-behaviour tests assert about scanning instead of collapsing into 401s. `TestAuthentication` in `test_security.py` re-enables it and drives real signed tokens — including forged-secret, `alg: none`, expired, and wrong-audience cases.

## Gotchas

- **Two import paths for the same package.** `cli.py` uses relative imports (`from .scanner_router import ...`); `api.py` uses `from src.chainaudit.scanner_router import ...` after `sys.path.insert(0, BASE_DIR)`. The API path only works when CWD/`PYTHONPATH` is `backend/` — hence `ENV PYTHONPATH=/app` in the Dockerfile. Don't "unify" these without testing both the installed CLI and the server.
- **Version comes from package metadata** — `chainaudit.__version__` reads the installed distribution, whose single source is `[project].version` in `pyproject.toml`. Nothing hardcodes it; there is no `setup.py`.
- **CI is blocking.** Every step reports its real status — no `|| true`. `ruff` is pinned (`0.16.4`) with rule selection in `[tool.ruff.lint]`, because an unpinned ruff shifts its default rules between releases. The scan job separates "found CRITICALs" (exit 1, report written — expected for the fixtures) from "scan crashed" (no report — fails the build).
- **`.rs` scans are copied into a fresh temp dir before scanning** (in both `cli._scan_rs_file` and `scanner_router._scan_solana`) because `scan_solana` recurses a directory — without isolation, findings bleed across files in multi-file scans. Preserve that when refactoring.
- `backend/reports/`, `backend/tmp_scans/`, `backend/dist/`, and `ml/smartbugs/` are git-ignored. `docker-compose.yml` is ignored too — copy `docker-compose.example.yml`.

## Known open issues

Everything else from the security review has been fixed; these are what remain.

- **`SUPABASE_URL` (or `SUPABASE_JWT_SECRET`) must be set wherever the API runs.** Without one, every scan returns 503 by design. Deployment configuration, not a code gap — but a fresh environment is non-functional until it is set.
- **First request after a cold start fetches the JWKS.** One network call, then cached. If Supabase's auth endpoint is down, scans return 503 until it recovers.
- **Rate limiting is in-process.** Correct for the current single-worker Render deployment. More than one worker or instance needs a shared store; the buckets do not coordinate.
- **`X-Forwarded-For` is trusted for client identity.** Safe only because Render terminates TLS in front of the app and rewrites the header. Direct exposure would make the limiter trivially bypassable.
- **Solana anti-pattern suppression is file-wide.** One `checked_add` anywhere suppresses `integer-overflow` for the whole file. This is a deliberate false-positive tradeoff, but it does mean a partially-safe file can hide a real finding.

## Test fixtures

`contracts/test/` holds hand-built cases used by CI and manual verification: risk-graded `.sol` (`01_empty` … `06_low_risk`), broken syntax, chain-specific contracts (`ArbitrumVault`, `OptimismBridge`, `CrossChainStaking`), Solana `.rs` programs including an Anchor project, and prebuilt zips (`sol_only`, `rust_only`, `mixed_contracts`) for exercising the zip router.
