# Cerberus — Containerized PyPI Intake Gatekeeper

Cerberus is a **package intake proxy** that sits in front of PyPI and gatekeeps
every package download behind an **external approval API**. A native `uv` (or
`pip`) install pointed at the proxy is intercepted by OpenResty/Lua, which asks
a mock external approval service whether the package is allowed. Approved
packages are transparently pulled through from real PyPI; everything else gets a
`403` and the install fails. Approval is **dynamic** — approve or revoke at
runtime and the proxy reacts within seconds.

Approval is **bound to content hashes**: approving a package pins its current
PyPI sha256 hashes, and the proxy verifies every artifact's digest before
serving — so the bytes a client receives are *guaranteed byte-identical to what
was approved*, even if upstream PyPI later changes.

```
                 docker network "cerberus"
 ┌─────────┐   http   ┌──────────────────┐  http  ┌──────────────┐
 │ uv /    │ ───────► │ proxy (openresty)│ ─────► │ approval-api │
 │ tester  │  :8080   │  nginx + Lua     │ :9000  │  (FastAPI)   │
 └─────────┘          │  gatekeeper.lua  │        └──────────────┘
                      └───────┬──────────┘   GET /check?package=
                              │ https (pull-through)
                              ▼
                  pypi.org + files.pythonhosted.org
```

## Components

| Service        | Tech                | Role                                                            |
|----------------|---------------------|----------------------------------------------------------------|
| `proxy`        | OpenResty (nginx+Lua) | Name-gates `/simple/`; verify-then-serves `/files/` (hash-checked). |
| `approval-api` | FastAPI             | Mock external approver. Default-deny; pins per-package sha256 hashes. |
| `tester`       | `uv` image          | Runs the end-to-end gatekeeping suite over the docker network.  |

## How it works

1. `uv` requests `GET /simple/<pkg>/`. The Lua `access_by_lua` gate normalizes
   the name (PEP 503), calls `GET approval-api/check?package=<pkg>`, and either
   `403`s or proxies through to `pypi.org`.
2. The simple-index response's file URLs (`https://files.pythonhosted.org/...`)
   are rewritten by nginx `sub_filter` to route back through the proxy at
   `/files/`.
3. `uv` downloads each artifact via `GET /files/...`. A Lua **verify-then-serve**
   handler fetches the file from `files.pythonhosted.org` into the proxy,
   computes its sha256, and **only releases the bytes if the digest is in the
   package's approved hash set** — otherwise `403` with nothing leaked. The bytes
   are passed through unmodified, so `uv`'s own `#sha256=` check still passes too.

### Pending approvals (slow, human-in-the-loop)

Approval can take a long time (hours), so packages follow a state machine:

```
unknown --(first request, auto-captured)--> pending --(/approve)--> approved
                                               \---(/reject)------> rejected
```

The first time the proxy asks `GET /check` about an **unknown** package, the
approval service **captures it as `pending`** and the proxy answers the client
with `503 Service Unavailable` + a `Retry-After` header. A repeat request for an
already-pending package does **not** create a new request — it reuses the
existing one (idempotent capture), so the operator only ever sees one entry to
act on (`GET /pending`). Once a human runs `/approve` (or `/reject`), the next
request resolves: `approved` → served `200`; `rejected` → `403`.

### Error responses

Every non-success response carries a meaningful HTTP status plus
`X-Cerberus-Status` / `X-Cerberus-Reason` headers and a JSON body. Note that
`uv`/`pip` only surface the **status code + reason** in their failure output (not
the body), so the status code is the primary signal a user sees; the headers,
body, and proxy logs carry the full detail for `curl`, `pip -v`, and CI.

Each scenario uses a **distinct** status code, so the client's terminal output
alone disambiguates them:

| Scenario | HTTP | `X-Cerberus-Status` | What `uv` shows |
|----------|------|---------------------|-----------------|
| approved | `200` | — | (success) |
| pending (awaiting approval) | `503` + `Retry-After` | `pending` | `503 Service Unavailable` (retries, then fails) |
| approval backend unreachable | `504` + `Retry-After` | `approval-unavailable` | `504 Gateway Timeout` |
| rejected by policy | `403` | `rejected` | `403 Forbidden` |
| artifact hash not approved | `409` | `hash-mismatch` | `409 Conflict` |
| unparseable package name | `400` | `invalid-request` | `400 Bad Request` |
| upstream (PyPI/files) fetch failed | `502` | `upstream-error` | `502 Bad Gateway` |

```console
$ curl -i http://localhost:8080/simple/tomli/
HTTP/1.1 503 Service Temporarily Unavailable
Retry-After: 60
X-Cerberus-Status: pending
X-Cerberus-Reason: package 'tomli' is awaiting approval; an approval request has been recorded, retry after it is granted
{"proxy":"cerberus","status":"pending","package":"tomli","message":"package 'tomli' is awaiting approval; ..."}
```

### Per-user attribution

If the client connects with credentials (HTTP Basic Auth — e.g. an index URL like
`http://alice:token@proxy:8080/simple/`), the proxy extracts the **username** and
forwards it to the approval API as the optional `user` query param on `/check`.
The proxy does **not** authenticate — it only captures the username — and the
password is ignored. The approval service records who requested each package
(`requested_by`, surfaced in `GET /pending`) so a human approver can see who is
waiting. The username is also folded into the proxy's decision-cache key, so a
per-user approval is never served to a different user.

```console
$ uv pip install --index-url http://alice:x@localhost:8080/simple/ \
    --allow-insecure-host localhost:8080 requests
$ curl -s localhost:9000/pending        # -> {"pending":["requests"],"requested_by":{"requests":["alice"]}}
```

### Hash-pinned approval (TOFU)

`POST /approve {package}` performs **trust-on-first-use**: the approval service
fetches the package's current sha256 hashes from PyPI's JSON simple API (and the
PEP 658 `core-metadata` hashes) and pins them. Thereafter the proxy serves an
artifact only if its hash is in that pinned set. `POST /pin {package, hashes}` is
an admin override that sets an exact set (used to pin a subset, or to prove the
binding in tests).

A short-lived `lua_shared_dict` cache (`APPROVAL_CACHE_TTL`, default 5s) keeps
revocation/re-pin latency low while avoiding an approval round-trip on every
request — only *approvals* are cached, so denials take effect immediately. The
proxy is **fail-closed**: if the approval API is unreachable, packages are
denied. Artifacts are buffered in proxy memory for hashing (fine for
wheels/sdists; not suited to multi-hundred-MB packages).

### Source integrity

Every fetch from an external source is validated on two independent axes:

- **Transport (TLS).** The proxy verifies the upstream certificate on *both*
  pull-through legs — the `/simple/` index from `pypi.org` (nginx `proxy_ssl_verify
  on` against the system CA bundle) and each artifact from `files.pythonhosted.org`
  (`resty.http` `ssl_verify = true`). The approval API fetches PyPI hashes over
  verified HTTPS too. A failed handshake aborts the request; nothing unverified is
  served. Point `UPSTREAM_CA_BUNDLE` (approval API) at a custom CA for a corporate
  TLS-inspecting proxy.
- **Content (sha256).** Approval pins the artifact hashes from that
  TLS-authenticated index, and the proxy refuses to serve any byte stream whose
  digest isn't in the approved set — so the bytes a client receives are
  cryptographically guaranteed to match what was approved.

> **PGP/GPG note:** PyPI removed PGP signature support in 2023, so per-artifact
> GPG verification is not available for PyPI sources; the sha256 pin (above) is the
> equivalent content-integrity guarantee. Provenance attestations (PEP 740 /
> Sigstore) are the modern successor and a possible future addition.

## Quick start

```bash
# Build and start the proxy + approval API
make up            # or: docker compose up -d --build

# Run the full end-to-end proof: blocked -> approve -> served -> revoke -> blocked
make test          # or: docker compose run --rm tester
```

## Manual demo from the host

```bash
# Not approved yet -> 403
curl -s localhost:8080/simple/six/ -o /dev/null -w '%{http_code}\n'      # 403

# Approve via the external API
make approve PKG=six          # or: curl -XPOST localhost:9000/approve -d '{"package":"six"}'

# Now the index resolves (file URLs rewritten through the proxy)
curl -s localhost:8080/simple/six/ | head

# Install with native uv, pointed at the proxy
uv pip install --index-url http://localhost:8080/simple/ \
  --allow-insecure-host localhost:8080 six

# Revoke and watch it block again (after the cache TTL)
make revoke PKG=six
```

Watch gate decisions live:

```bash
make logs          # docker compose logs -f proxy
```

## Tests

Three layers (run them all with `make test-all`):

| Target | Layer | Network | Covers |
|--------|-------|---------|--------|
| `make test-unit` | Python unit (pytest, PyPI mocked) | offline | TOFU pinning, default-deny, 502-on-unreachable, normalization |
| `make test-lua`  | Lua unit (resty)                  | offline | name normalization + filename extraction (incl. hyphenated-sdist regression), sha256 |
| `make test`      | End-to-end (`uv` via the proxy)   | needs internet | lifecycle, **hash guarantee** (pinned hash enforced), transitive dependency gating |

## Continuous integration & dependency automation

`.github/workflows/ci.yml` runs the full test pyramid as three required checks on
every PR into `main` (and on pushes to `main`): **Unit tests (Python)**, **Unit
tests (Lua)**, and **End-to-end (uv through the proxy)** — each just invokes the
matching `make` target, so CI and local runs are identical.

Dependency updates are automated:
- `.github/dependabot.yml` watches the Python deps (`approval-api`), the three
  Docker base images, and the GitHub Actions themselves (weekly, grouped).
- `.github/workflows/dependabot-auto-merge.yml` enables auto-merge on Dependabot
  PRs; GitHub completes the merge only once the CI checks pass.

For auto-merge to gate on the tests (rather than merge immediately), enable
**Allow auto-merge** (Settings → General) and add a branch-protection rule on
`main` that requires the three CI checks.

### Agentic issue fixing

`.github/workflows/opencode-issue-fix.yml` runs a headless [opencode](https://opencode.ai)
agent when an issue is opened: it attempts a fix on a `opencode/issue-<n>` branch
and opens a **draft** PR for manual review (it never merges; the draft PR is then
validated by the CI checks above). The agent is driven by a **custom
OpenAI-compatible endpoint** and runs non-interactively
(`opencode run --dangerously-skip-permissions`).

Configure under Settings → Secrets and variables → Actions:

| Name | Kind | Purpose |
|------|------|---------|
| `LLM_API_KEY`  | secret   | API key for the OpenAI-compatible endpoint |
| `LLM_BASE_URL` | variable | endpoint base URL ending in `/v1` (use a secret if sensitive) |
| `LLM_MODEL`    | variable | model id to request |
| `GH_PAT`       | secret (optional) | PAT/app token so CI runs on the agent's PR — PRs opened with the default `GITHUB_TOKEN` don't trigger workflows |

It only runs for issues opened by `OWNER`/`MEMBER`/`COLLABORATOR` (the issue body
is untrusted input steering an agent with write access); tighten or switch to a
maintainer-applied label trigger as needed.

## Configuration

| Env var (on `proxy`)  | Default                     | Meaning                                   |
|-----------------------|-----------------------------|-------------------------------------------|
| `APPROVAL_API_URL`    | `http://approval-api:9000`  | Where the gatekeeper sends `/check`.      |
| `APPROVAL_CACHE_TTL`  | `5`                         | Seconds a decision is cached (revoke lag).|
| `APPROVAL_TIMEOUT_MS` | `2000`                      | Approval API call timeout.                |

## Notes & scope

- Client↔proxy is **HTTP** (no TLS cert generation); `uv` uses
  `--allow-insecure-host`. TLS termination can be layered on later.
- Real-PyPI pull-through means the E2E test needs outbound internet. The test
  package `six` is tiny, stable, and dependency-free (default-deny otherwise
  blocks transitive deps — each would need its own approval).
- The design generalizes to other ecosystems (npm, etc.) by adding locations and
  filename extractors; this build targets PyPI.
```

## License

[MIT](LICENSE) © 2026 Erik Hallros, Saab AB
