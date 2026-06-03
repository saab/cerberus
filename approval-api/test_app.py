"""Unit tests for the approval API. PyPI is mocked with respx (no network)."""
import httpx
import pytest
import respx
from fastapi.testclient import TestClient

import app as appmod
from app import app, normalize

client = TestClient(app)


@pytest.fixture(autouse=True)
def _clear_state():
    appmod._pins.clear()
    yield
    appmod._pins.clear()


def test_normalize_parity():
    # Mirrors the Lua lib.pkgname.normalize cases (PEP 503).
    assert normalize("Typing_Extensions") == "typing-extensions"
    assert normalize("typing.extensions") == "typing-extensions"
    assert normalize("typing--extensions") == "typing-extensions"
    assert normalize("Six") == "six"


def test_unknown_package_is_captured_pending():
    # First check of an unknown package captures it as pending (default-deny).
    r = client.get("/check", params={"package": "six"})
    assert r.status_code == 200
    assert r.json() == {
        "package": "six", "status": "pending", "approved": False,
        "hashes": [], "user": None, "requested_by": [],
    }
    assert client.get("/pending").json()["pending"] == ["six"]


def test_user_param_is_recorded_and_attributed():
    # The optional connection username forwarded by the proxy is attributed.
    c = client.get("/check", params={"package": "six", "user": "alice"}).json()
    assert c["user"] == "alice"
    assert c["requested_by"] == ["alice"]
    client.get("/check", params={"package": "six", "user": "bob"})
    # Both requesters are tracked; surfaced on the pending queue.
    assert client.get("/check", params={"package": "six"}).json()["requested_by"] == ["alice", "bob"]
    assert client.get("/pending").json()["requested_by"]["six"] == ["alice", "bob"]
    # Revoke clears the attribution.
    client.post("/revoke", json={"package": "six"})
    assert client.get("/check", params={"package": "six"}).json()["requested_by"] == []


def test_repeat_check_does_not_duplicate_pending():
    client.get("/check", params={"package": "Six"})
    client.get("/check", params={"package": "six"})   # same normalized name
    # Still exactly one pending entry (no new approval request created).
    assert client.get("/pending").json()["pending"] == ["six"]


def test_reject_is_terminal_and_not_re_pended():
    client.get("/check", params={"package": "evilpkg"})        # -> pending
    client.post("/reject", json={"package": "evilpkg"})
    c = client.get("/check", params={"package": "evilpkg"}).json()
    assert c["status"] == "rejected" and c["approved"] is False
    # A rejected package stays rejected (does not flip back to pending).
    assert "evilpkg" not in client.get("/pending").json()["pending"]


@respx.mock
def test_approve_clears_pending():
    respx.get("https://pypi.org/simple/six/").mock(
        return_value=httpx.Response(200, json={"files": [{"filename": "six-1.0.tar.gz", "hashes": {"sha256": "AAA"}}]})
    )
    client.get("/check", params={"package": "six"})            # -> pending
    client.post("/approve", json={"package": "six"})
    assert client.get("/pending").json()["pending"] == []
    assert client.get("/check", params={"package": "six"}).json()["status"] == "approved"


@respx.mock
def test_approve_tofu_pins_hashes():
    respx.get("https://pypi.org/simple/six/").mock(
        return_value=httpx.Response(200, json={
            "files": [
                {"filename": "six-1.16.0.tar.gz", "hashes": {"sha256": "AAA"}},
                {"filename": "six-1.17.0-py2.py3-none-any.whl", "hashes": {"sha256": "BBB"}},
            ]
        })
    )
    r = client.post("/approve", json={"package": "Six"})
    assert r.status_code == 200
    assert r.json()["hash_count"] == 2

    c = client.get("/check", params={"package": "six"}).json()
    assert c["approved"] is True
    assert c["hashes"] == ["aaa", "bbb"]   # lowercased + sorted


@respx.mock
def test_approve_pins_core_metadata_hash():
    # uv/pip fetch the PEP 658 "<wheel>.metadata" sidecar (its own hash) first.
    respx.get("https://pypi.org/simple/six/").mock(
        return_value=httpx.Response(200, json={
            "files": [
                {
                    "filename": "six-1.17.0-py2.py3-none-any.whl",
                    "hashes": {"sha256": "WHEELHASH"},
                    "core-metadata": {"sha256": "METAHASH"},
                },
            ]
        })
    )
    client.post("/approve", json={"package": "six"})
    c = client.get("/check", params={"package": "six"}).json()
    assert c["hashes"] == ["metahash", "wheelhash"]   # both pinned, sorted


@respx.mock
def test_approve_pypi_unreachable_returns_502():
    respx.get("https://pypi.org/simple/brokenpkg/").mock(
        side_effect=httpx.ConnectError("boom")
    )
    r = client.post("/approve", json={"package": "brokenpkg"})
    assert r.status_code == 502
    # No silent empty pin was recorded.
    assert client.get("/check", params={"package": "brokenpkg"}).json()["approved"] is False


def test_pin_sets_exact_set_and_revoke_drops_it():
    client.post("/pin", json={"package": "six", "hashes": ["DEAD", "beef"]})
    c = client.get("/check", params={"package": "six"}).json()
    assert c["approved"] is True
    assert c["hashes"] == ["beef", "dead"]   # lowercased + sorted

    client.post("/revoke", json={"package": "six"})
    assert client.get("/check", params={"package": "six"}).json()["approved"] is False


@respx.mock
def test_normalization_equivalence():
    respx.get("https://pypi.org/simple/typing-extensions/").mock(
        return_value=httpx.Response(200, json={
            "files": [{"filename": "x", "hashes": {"sha256": "CAFE"}}]
        })
    )
    client.post("/approve", json={"package": "Typing_Extensions"})
    c = client.get("/check", params={"package": "typing-extensions"}).json()
    assert c["approved"] is True
    assert c["hashes"] == ["cafe"]
