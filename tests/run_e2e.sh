#!/usr/bin/env bash
# End-to-end proof of the Cerberus gatekeeper, run from inside the tester
# container over the docker network. Covers:
#   1. dynamic lifecycle: blocked -> approve -> served -> revoke -> blocked
#   2. hash guarantee: served bytes == approved artifact (pinned hash enforced)
#   3. transitive dependency gating
set -uo pipefail

PROXY="${PROXY_URL:-http://proxy:8080}"
APPROVAL="${APPROVAL_URL:-http://approval-api:9000}"
PKG="${TEST_PACKAGE:-six}"          # tiny, stable, zero-dependency package
CACHE_TTL="${APPROVAL_CACHE_TTL:-5}"
VENV=/opt/venv

PROXY_HOST="${PROXY#http://}"       # e.g. proxy:8080 (for --allow-insecure-host)
export UV_INDEX_URL="${PROXY}/simple/"
export UV_INSECURE_HOST="${PROXY_HOST}"
UV_FLAGS=(--no-cache --allow-insecure-host "${PROXY_HOST}" --python "${VENV}/bin/python")

pass=0; fail=0
ok()   { echo "  ✅ PASS: $1"; pass=$((pass+1)); }
bad()  { echo "  ❌ FAIL: $1"; fail=$((fail+1)); }
step() { echo; echo "=== $1 ==="; }

wait_for() {
  local name="$1" url="$2"
  echo "Waiting for ${name} (${url}) ..."
  for _ in $(seq 1 60); do
    if curl -fsS "$url" >/dev/null 2>&1; then echo "  ${name} is up."; return 0; fi
    sleep 1
  done
  echo "  ${name} did not become healthy in time."; exit 1
}

approve() { curl -fsS -X POST "${APPROVAL}/approve" -H 'Content-Type: application/json' -d "{\"package\":\"${1}\"}" >/dev/null; }
revoke()  { curl -fsS -X POST "${APPROVAL}/revoke"  -H 'Content-Type: application/json' -d "{\"package\":\"${1}\"}" >/dev/null; }
reject()  { curl -fsS -X POST "${APPROVAL}/reject"  -H 'Content-Type: application/json' -d "{\"package\":\"${1}\"}" >/dev/null; }
pin()     { curl -fsS -X POST "${APPROVAL}/pin"     -H 'Content-Type: application/json' -d "{\"package\":\"${1}\",\"hashes\":[\"${2}\"]}" >/dev/null; }
http_code() { curl -s -o /dev/null -w '%{http_code}' "$1"; }
# "blocked" evidence in a uv log: an explicit gate response, not an unrelated error.
BLOCKED_RE='403|forbidden|not approved|503|pending|no.+version|Failed to fetch'

# Install one or more packages into the venv. Returns uv's exit code; log in /tmp/install.log.
install() { uv pip install "${UV_FLAGS[@]}" --reinstall "$@" >/tmp/install.log 2>&1; }

wait_for "approval-api" "${APPROVAL}/healthz"
wait_for "proxy"        "${PROXY}/healthz"

echo; echo "Creating clean venv at ${VENV} ..."
uv venv "$VENV" >/dev/null 2>&1 || { echo "failed to create venv"; exit 1; }

revoke "$PKG" || true   # clean default-deny starting state

# ----------------------------------------------------------------------------
step "Scenario 1 — pending approval workflow (capture, dedupe, reject, approve)"
PEND="${PENDING_PACKAGE:-tomli}"     # real zero-dep package, separate from the rest
revoke "$PEND" || true               # ensure unknown starting state

# First request for an unknown package -> captured as pending -> 503 + Retry-After.
hdr=$(curl -s -D - -o /dev/null "${PROXY}/simple/${PEND}/")
code=$(printf '%s\n' "$hdr" | awk 'NR==1{print $2}')
[ "$code" = 503 ] && ok "unknown package -> 503 (pending)" || bad "expected 503 for unknown package, got '${code}'"
printf '%s\n' "$hdr" | grep -qi '^Retry-After:' && ok "503 carries a Retry-After header" || bad "503 missing Retry-After header"
printf '%s\n' "$hdr" | grep -qi '^X-Cerberus-Status: pending' && ok "503 tagged X-Cerberus-Status: pending" || bad "503 missing X-Cerberus-Status: pending"

# It is now captured in the pending queue (awaiting the slow human approval).
curl -fsS "${APPROVAL}/pending" | grep -q "\"${PEND}\"" && ok "request captured in pending queue" || bad "package not captured as pending"

# A repeat request does NOT create a new approval request -- reuses the existing one.
curl -s -o /dev/null "${PROXY}/simple/${PEND}/"
n=$(curl -fsS "${APPROVAL}/pending" | python3 -c "import sys,json; print(sum(1 for p in json.load(sys.stdin)['pending'] if p=='${PEND}'))")
[ "$n" = 1 ] && ok "repeat request reuses existing pending (no duplicate)" || bad "pending duplicated (count=${n})"

# The connection username (HTTP Basic Auth user) is forwarded to the approval API.
curl -s -u alice:x -o /dev/null "${PROXY}/simple/${PEND}/"
who=$(curl -fsS "${APPROVAL}/check?package=${PEND}" | python3 -c "import sys,json; print(','.join(json.load(sys.stdin)['requested_by']))")
echo "$who" | grep -q 'alice' && ok "proxy forwards connection username to approval API (requested_by=${who})" || bad "username not forwarded (requested_by='${who}')"

# Reject -> terminal 403, tagged.
reject "$PEND"
rhdr=$(curl -s -D - -o /dev/null "${PROXY}/simple/${PEND}/")
code=$(printf '%s\n' "$rhdr" | awk 'NR==1{print $2}')
[ "$code" = 403 ] && ok "rejected package -> 403" || bad "expected 403 after reject, got '${code}'"
printf '%s\n' "$rhdr" | grep -qi '^X-Cerberus-Status: rejected' && ok "403 tagged X-Cerberus-Status: rejected" || bad "403 missing X-Cerberus-Status: rejected"

# Approve (clears pending/rejected) -> 200.
approve "$PEND"
code=$(http_code "${PROXY}/simple/${PEND}/")
[ "$code" = 200 ] && ok "approved package -> 200" || bad "expected 200 after approve, got '${code}'"
revoke "$PEND" || true               # cleanup; clear the cached approval before moving on
sleep $((CACHE_TTL + 1))

# ----------------------------------------------------------------------------
step "Scenario 2 — dynamic lifecycle (blocked -> approve -> served -> revoke -> blocked)"

# BLOCKED: must fail *and* show explicit gate evidence (not just any error).
if install "$PKG"; then
  bad "install of '${PKG}' succeeded but should have been blocked"
elif grep -qiE "$BLOCKED_RE" /tmp/install.log; then
  ok "install blocked by proxy (pending/denied)"
else
  bad "install failed but NOT due to gatekeeping"; tail -n 4 /tmp/install.log | sed 's/^/    | /'
fi

# SERVED
approve "$PKG"; echo "  approved '${PKG}'"
if install "$PKG" && "${VENV}/bin/python" -c "import ${PKG}; print('${PKG}', ${PKG}.__version__)"; then
  ok "approved package installed through proxy and imports"
else
  bad "install/import of approved package failed"; tail -n 6 /tmp/install.log | sed 's/^/    | /'
fi

# REVOKED -> BLOCKED again (wait out the proxy decision cache)
revoke "$PKG"; echo "  revoked '${PKG}'; sleeping $((CACHE_TTL + 1))s for cache to expire ..."
sleep $((CACHE_TTL + 1))
if install "$PKG"; then
  bad "install succeeded after revocation but should have been blocked"
elif grep -qiE "$BLOCKED_RE" /tmp/install.log; then
  ok "install blocked again after revocation"
else
  bad "post-revoke install failed but NOT due to gatekeeping"; tail -n 4 /tmp/install.log | sed 's/^/    | /'
fi

# ----------------------------------------------------------------------------
step "Scenario 3 — hash guarantee (served bytes == approved artifact)"

approve "$PKG"   # TOFU: name-approve + pin all current hashes (so the index is readable)

# Pull two distinct artifacts (URL + sha256) for the package from the proxy's index.
read -r OLD_URL OLD_SHA NEW_URL NEW_SHA < <(python3 - "$PROXY" "$PKG" <<'PY'
import sys, json, urllib.request
proxy, pkg = sys.argv[1], sys.argv[2]
req = urllib.request.Request(f"{proxy}/simple/{pkg}/",
                             headers={"Accept": "application/vnd.pypi.simple.v1+json"})
files = [f for f in json.load(urllib.request.urlopen(req))["files"]
         if f.get("hashes", {}).get("sha256")]
old, new = files[0], files[-1]
print(old["url"], old["hashes"]["sha256"], new["url"], new["hashes"]["sha256"])
PY
)

if [ -z "${OLD_SHA:-}" ] || [ "$OLD_SHA" = "$NEW_SHA" ]; then
  bad "could not obtain two distinct artifacts to test hash pinning"
else
  pin "$PKG" "$OLD_SHA"      # pin ONLY the old artifact's hash
  echo "  pinned only one artifact; sleeping $((CACHE_TTL + 1))s for cache ..."
  sleep $((CACHE_TTL + 1))

  c_old=$(http_code "$OLD_URL")
  nhdr=$(curl -s -D - -o /dev/null "$NEW_URL")
  c_new=$(printf '%s\n' "$nhdr" | awk 'NR==1{print $2}')
  [ "$c_old" = 200 ] && ok "pinned artifact served (200)" || bad "pinned artifact not served (got ${c_old})"
  [ "$c_new" = 409 ] && ok "non-pinned artifact refused (409 Conflict) — hash binding enforced" || bad "non-pinned artifact NOT refused with 409 (got ${c_new})"
  printf '%s\n' "$nhdr" | grep -qi '^X-Cerberus-Status: hash-mismatch' && ok "refusal tagged X-Cerberus-Status: hash-mismatch" || bad "refusal missing X-Cerberus-Status: hash-mismatch"

  approve "$PKG"            # re-pin the full set
  echo "  re-approved (all hashes); sleeping $((CACHE_TTL + 1))s for cache ..."
  sleep $((CACHE_TTL + 1))
  c_new2=$(http_code "$NEW_URL")
  [ "$c_new2" = 200 ] && ok "after re-approve, previously-refused artifact served (200)" || bad "artifact not served after re-approve (got ${c_new2})"
fi

# ----------------------------------------------------------------------------
step "Scenario 4 — transitive dependency gating"
# Pin a modern requests version that genuinely requires these deps, so uv cannot
# backtrack to an ancient (dependency-free) requests release to dodge the gate.
REQ="requests==2.32.3"
DEPS=(charset-normalizer idna urllib3 certifi)
for p in requests "${DEPS[@]}"; do revoke "$p" || true; done

approve requests          # only the top-level package
if install "$REQ"; then
  bad "requests installed while its dependencies were unapproved"
elif grep -qiE "idna|urllib3|charset-normalizer|certifi|${BLOCKED_RE}" /tmp/install.log; then
  ok "install blocked on an unapproved transitive dependency"
else
  bad "requests install failed but NOT clearly due to a blocked dependency"; tail -n 5 /tmp/install.log | sed 's/^/    | /'
fi

for p in requests "${DEPS[@]}"; do approve "$p"; done   # approve the whole closure
if install "$REQ" && "${VENV}/bin/python" -c "import requests; print('requests', requests.__version__)"; then
  ok "requests + full dependency closure served and imports"
else
  bad "requests install failed with full closure approved"; tail -n 8 /tmp/install.log | sed 's/^/    | /'
fi

# ----------------------------------------------------------------------------
step "Summary"
echo "  ${pass} passed, ${fail} failed"
[ "$fail" -eq 0 ] && { echo; echo "🎉 ALL CHECKS PASSED"; exit 0; } || { echo; echo "💥 SOME CHECKS FAILED"; exit 1; }
