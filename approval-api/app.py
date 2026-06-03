"""Mock external package-approval API for the Cerberus intake proxy.

Approval binds a package to a set of approved sha256 hashes, and follows a state
machine that supports slow (hours-long) human approval:

    unknown --(first /check)--> pending --(/approve)--> approved
                                   \\----(/reject)----> rejected

The proxy calls GET /check on every request; an unknown package is captured as
`pending` (idempotently — a repeat request reuses the existing pending entry, so
no duplicate approval is created). `/approve` uses trust-on-first-use (TOFU): it
fetches the package's current PyPI hashes and pins them, so the proxy can
guarantee the bytes it serves match what was approved. `/pin` is an admin
override that sets an exact hash set.
"""
import os
import re
import httpx
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

app = FastAPI(title="Cerberus Approval API")

PYPI_SIMPLE = "https://pypi.org/simple"
SIMPLE_JSON = "application/vnd.pypi.simple.v1+json"

# TLS verification of the upstream index. Defaults to the system CA bundle;
# point UPSTREAM_CA_BUNDLE at a custom CA file for a corporate TLS-inspecting
# proxy. Verification is always ON — never set this to a falsy value to disable.
_UPSTREAM_VERIFY = os.getenv("UPSTREAM_CA_BUNDLE") or True

# normalized package name -> set of approved sha256 hex digests (the "approved" set).
_pins: dict[str, set[str]] = {}
_pending: set[str] = set()    # captured, awaiting a human decision
_rejected: set[str] = set()   # explicitly denied
# package -> set of usernames that requested it (from the proxy connection)
_requested_by: dict[str, set[str]] = {}


def normalize(name: str) -> str:
    """PEP 503 normalization: lowercase, collapse runs of -_. into a single -."""
    return re.sub(r"[-_.]+", "-", name).strip().lower()


def status_of(name: str) -> str:
    if name in _pins:
        return "approved"
    if name in _rejected:
        return "rejected"
    if name in _pending:
        return "pending"
    return "unknown"


def fetch_pypi_hashes(name: str) -> set[str]:
    """TOFU: fetch every artifact (and PEP 658 metadata) sha256 PyPI lists.

    The fetch is over HTTPS with TLS certificate verification enabled, so the
    hashes we pin come from an authenticated PyPI rather than a MITM.
    """
    if not PYPI_SIMPLE.startswith("https://"):
        raise HTTPException(status_code=500, detail="refusing to fetch hashes over a non-TLS URL")
    resp = httpx.get(
        f"{PYPI_SIMPLE}/{name}/",
        headers={"Accept": SIMPLE_JSON},
        timeout=10.0,
        follow_redirects=True,
        verify=_UPSTREAM_VERIFY,
    )
    resp.raise_for_status()
    hashes = set()
    for f in resp.json().get("files", []):
        digest = f.get("hashes", {}).get("sha256")
        if digest:
            hashes.add(digest.lower())
        # Installers fetch "<artifact>.metadata" (its own hash) before the artifact.
        core_meta = f.get("core-metadata")
        if isinstance(core_meta, dict) and core_meta.get("sha256"):
            hashes.add(core_meta["sha256"].lower())
    return hashes


class PackageBody(BaseModel):
    package: str


class PinBody(BaseModel):
    package: str
    hashes: list[str]


@app.get("/healthz")
def healthz():
    return {"status": "ok"}


@app.get("/check")
def check(package: str, user: str | None = None):
    name = normalize(package)
    st = status_of(name)
    if st == "unknown":
        # Capture the request as pending (idempotent: a repeat is a no-op).
        _pending.add(name)
        st = "pending"
    # `user` is the optional connection username forwarded by the proxy; record
    # who has requested this package (attribution for the human approver).
    if user:
        _requested_by.setdefault(name, set()).add(user)
    pins = _pins.get(name)
    return {
        "package": name,
        "status": st,
        "approved": st == "approved",
        "hashes": sorted(pins) if pins else [],
        "user": user,
        "requested_by": sorted(_requested_by.get(name, set())),
    }


@app.post("/approve")
def approve(body: PackageBody):
    name = normalize(body.package)
    try:
        hashes = fetch_pypi_hashes(name)
    except httpx.HTTPError as exc:
        # Fail loudly rather than silently pinning an empty (serve-nothing) set.
        raise HTTPException(status_code=502, detail=f"could not fetch hashes from PyPI: {exc}")
    _pins[name] = hashes
    _pending.discard(name)
    _rejected.discard(name)
    return {"package": name, "status": "approved", "approved": True, "hash_count": len(hashes)}


@app.post("/reject")
def reject(body: PackageBody):
    name = normalize(body.package)
    _rejected.add(name)
    _pending.discard(name)
    _pins.pop(name, None)
    return {"package": name, "status": "rejected", "approved": False}


@app.post("/pin")
def pin(body: PinBody):
    """Admin override: set the exact approved hash set (also approves)."""
    name = normalize(body.package)
    _pins[name] = {h.lower() for h in body.hashes}
    _pending.discard(name)
    _rejected.discard(name)
    return {"package": name, "status": "approved", "approved": True, "hash_count": len(_pins[name])}


@app.post("/revoke")
def revoke(body: PackageBody):
    """Forget all state for a package (back to unknown; re-requestable)."""
    name = normalize(body.package)
    _pins.pop(name, None)
    _pending.discard(name)
    _rejected.discard(name)
    _requested_by.pop(name, None)
    return {"package": name, "status": "unknown", "approved": False}


@app.get("/pending")
def pending():
    return {
        "pending": sorted(_pending),
        "requested_by": {p: sorted(_requested_by.get(p, set())) for p in sorted(_pending)},
    }


@app.get("/packages")
def packages():
    return {
        "approved": {k: sorted(v) for k, v in _pins.items()},
        "pending": sorted(_pending),
        "rejected": sorted(_rejected),
    }
