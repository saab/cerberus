# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Cerberus is a containerized **PyPI intake gatekeeper**. An OpenResty/Lua proxy sits in front of PyPI; a native `uv` (or `pip`) install pointed at it is intercepted, checked against an external approval API, and only served if the package is approved. Approval is **bound to content hashes**, so served bytes are guaranteed byte-identical to what was approved. Slow (hours-long) human approval is supported via a pending state.

Three containers (see `docker-compose.yml`): `proxy` (OpenResty, `:8080`), `approval-api` (FastAPI, `:9000`), and `tester` (a `uv` image that runs the E2E suite; gated behind the compose `test` profile so a plain `up` doesn't start it).

## Commands

Everything runs in Docker — no host Python/Lua/uv needed. Targets are in the `Makefile`.

```bash
make up            # build + start proxy and approval-api
make test          # E2E suite (needs internet: pulls through real PyPI)
make test-unit     # Python unit tests for approval-api (offline, PyPI mocked)
make test-lua      # pure-Lua unit tests via the resty CLI (offline)
make test-all      # full pyramid: unit + lua + e2e
make logs          # tail proxy gate decisions
make down / clean  # stop / stop+remove-orphans
```

Manual approval control against a running stack (also useful while debugging E2E):
`make approve|reject|revoke PKG=<name>`, `make pin PKG=<n> SHA=<sha256>`, `make pending`, `make list`.

**Running a single test.** The unit-test make targets shell out to `docker run` with a bind mount; to filter, replicate the command and add a selector:

```bash
# single Python test (pytest -k); $(pwd -W) yields a Docker-friendly path on Git-Bash/Windows
MSYS_NO_PATHCONV=1 docker run --rm -v "$(pwd -W)/approval-api:/app" -w /app python:3.14-slim \
  sh -c "pip install -q -r requirements.txt -r requirements-dev.txt && pytest -q -k test_reject_is_terminal"
```

The Lua suite is a single self-contained script (`tests/lua/pkgname_spec.lua`) run by the `resty` CLI; there is no per-case selector — edit/run the whole file.

**Windows/Git-Bash gotcha:** `docker run -v` bind mounts get path-mangled by MSYS unless prefixed with `MSYS_NO_PATHCONV=1` and given a Windows-style source path via `$(pwd -W)`. The Makefile bakes this in (`MSYS_NO_PATHCONV` is a no-op on Linux/macOS).

## Request flow (the big picture)

`uv` is pointed at `http://proxy:8080/simple/`. Two nginx locations in `proxy/nginx.conf` handle the two phases of an install, and they gate **independently**:

1. **`/simple/<pkg>/` (index)** — `access_by_lua_file gatekeeper.lua` resolves the package name and checks approval; on approval nginx `proxy_pass`es to `pypi.org`. A `sub_filter` rewrites `https://files.pythonhosted.org` → `http://$http_host/files` so artifact downloads route back through the proxy. **Use `$http_host`, not `$host`** — `$host` drops the port and breaks the `:8080` rewrite.

2. **`/files/...` (artifacts)** — `content_by_lua_file serve_file.lua` does **verify-then-serve**: it re-checks approval, fetches the artifact into proxy memory via `resty.http`, computes its sha256, and only `ngx.print`s the bytes if the digest is in the package's approved hash set. Nothing is streamed to the client until the hash matches, so a mismatch leaks zero bytes. (Artifacts are buffered whole in memory — fine for wheels/sdists, not for very large packages.)

**Source integrity (don't regress this):** both upstream legs verify TLS — the `/simple/` `proxy_pass` uses `proxy_ssl_verify on` (against `/etc/ssl/certs/ca-certificates.crt`), and `serve_file.lua` uses `ssl_verify = true` (trust store from `lua_ssl_trusted_certificate`); the approval-api fetches PyPI over verified HTTPS (`verify=_UPSTREAM_VERIFY`, override via `UPSTREAM_CA_BUNDLE`). Transport integrity = TLS verification; content integrity = the sha256 pin. PyPI dropped PGP in 2023, so there is intentionally no GPG step.

Shared Lua lives in `proxy/lua/lib/`:
- `pkgname.lua` — **pure Lua, no `ngx` deps** (so it's unit-testable with the bare `resty`/`luajit` CLI). PEP 503 normalization + filename→project-name extraction. The filename parser uses `^(.-)%-%d` ("name is everything before the first dash followed by a digit") — do **not** revert to splitting on the first dash, which truncates hyphenated sdist names (`foo-bar-1.0.tar.gz` → `foo`).
- `approval.lua` — calls `approval-api` `/check`, returns a decision table `{approved, status, hashes}`. **Caches approvals only, never pending/rejected**, in the `approvals` shared dict (TTL = `APPROVAL_CACHE_TTL`, default 5s). Consequence: approval/rejection take effect immediately, but a **revoke or re-pin can take up to the TTL to propagate** — tests `sleep CACHE_TTL+1` after revoking/re-pinning for this reason. Also decodes the HTTP Basic Auth username from the client connection (not authenticated — just captured) and forwards it as the optional `user` query param to `/check`; the username is folded into the cache key so a per-user decision isn't served to another user.
- `response.lua` — central place for all non-200 responses. Each scenario maps to a **distinct** HTTP status (so `uv`/`pip`, which surface only the status line, can disambiguate): pending→`503`+`Retry-After`, approval-backend-down→`504`, rejected→`403`, hash-mismatch→`409`, bad name→`400`, upstream-error→`502`. Every response also carries `X-Cerberus-Status` / `X-Cerberus-Reason` headers and a JSON body for clients that read them.

Proxy behavior is tuned via env vars set on the `proxy` service in `docker-compose.yml` (and read by the Lua libs): `APPROVAL_API_URL`, `APPROVAL_CACHE_TTL` (decision cache / revoke latency), `APPROVAL_TIMEOUT_MS` (approval call timeout), `PENDING_RETRY_AFTER` (the `Retry-After` value on `503`/`504`).

## Approval model (`approval-api/app.py`)

In-memory state machine, default-deny: `unknown → (first /check, auto-captured) → pending → approved | rejected`.

- `GET /check` is the proxy's lookup and has a deliberate **side effect**: an unknown package is captured as `pending` (idempotent — repeats don't duplicate the request). This is why the first `uv` attempt on a new package returns `503` and the package then appears in `GET /pending`. It also takes an optional `user` (the connection username the proxy forwards) and records it under `requested_by`, surfaced in `GET /pending` for the human approver.
- `POST /approve` is **TOFU (trust-on-first-use)**: it fetches the package's current sha256 hashes from PyPI's JSON simple API and pins them — **including the PEP 658 `core-metadata` hashes**, because installers fetch `<wheel>.metadata` (its own hash) before the wheel; forgetting these makes approved installs fail at the metadata step. Fails `502` if PyPI is unreachable rather than silently pinning an empty (serve-nothing) set.
- `POST /pin {package, hashes}` is an admin override that sets an exact hash set (used to pin a subset, and by the E2E to prove the binding).
- `POST /revoke` resets a package to `unknown` (re-requestable); `POST /reject` is terminal.

## Tests & gotchas

- **Test pyramid:** `approval-api/test_app.py` (pytest, PyPI mocked with `respx`), `tests/lua/pkgname_spec.lua` (resty, offline), `tests/run_e2e.sh` (drives real `uv` through the proxy over the docker network).
- The E2E and the approval API hit **real PyPI**; the test package `six` is chosen because it's tiny and **zero-dependency** (default-deny otherwise blocks transitive deps).
- `uv` backtracks on a gated dependency: if a dep returns a gate error, uv treats it as unavailable and may fall back to an ancient dependency-free release. The transitive-gating scenario pins `requests==2.32.3` specifically to prevent this escape — keep it pinned.
- After editing `tests/run_e2e.sh`, the `tester` image must be rebuilt (`docker compose build tester` or `make test`, which rebuilds); `docker compose run tester` alone reuses the stale image.
- Lua changes require rebuilding the `proxy` image before they take effect (`docker compose up -d --build proxy`); `make test-lua` rebuilds it for you.
