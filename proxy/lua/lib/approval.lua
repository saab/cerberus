-- Shared approval lookup used by both the /simple/ access gate and the /files/
-- verify-then-serve handler. Calls the external approval API and returns the
-- approval decision plus the set of approved sha256 hashes for the package.
local http  = require "resty.http"
local cjson = require "cjson.safe"

local _M = {}

local APPROVAL_URL = os.getenv("APPROVAL_API_URL") or "http://approval-api:9000"
local CACHE_TTL    = tonumber(os.getenv("APPROVAL_CACHE_TTL")) or 5      -- seconds
local TIMEOUT_MS   = tonumber(os.getenv("APPROVAL_TIMEOUT_MS")) or 2000  -- ms

local cache = ngx.shared.approvals

local function to_set(list)
  local s = {}
  if type(list) == "table" then
    for _, h in ipairs(list) do
      s[h:lower()] = true
    end
  end
  return s
end

-- The "username" of the proxy connection: the user part of HTTP Basic Auth
-- credentials the client sent (e.g. uv index URL http://USER:pass@proxy/...).
-- We do not authenticate -- we only capture the username to forward downstream.
local function request_user()
  local auth = ngx.var.http_authorization
  if not auth then
    return nil
  end
  local b64 = auth:match("^%s*[Bb]asic%s+(%S+)")
  if not b64 then
    return nil
  end
  local decoded = ngx.decode_base64(b64)
  if not decoded then
    return nil
  end
  local user = decoded:match("^([^:]*)")
  if not user or user == "" then
    return nil
  end
  return user
end

-- check(pkg) -> decision (table), err (string|nil).
--   decision = { approved = bool, status = "approved"|"pending"|"rejected", hashes = set }
-- On any transport/parse error returns (nil, err) so callers fail closed.
--
-- The connection username (if any) is forwarded to the approval API as the
-- optional `user` query param, and folded into the cache key so a per-user
-- decision is never served to a different user.
--
-- Only approvals are cached (never pending/rejected): an unapproved package is
-- always re-checked, so approval is immediate; a cached approval lingers at most
-- CACHE_TTL, so revocation/re-pin propagates within that window.
function _M.check(pkg)
  local user = request_user()
  local cache_key = user and (pkg .. "\0" .. user) or pkg

  local cached = cache:get(cache_key)
  if cached then
    local obj = cjson.decode(cached)
    if obj then
      return { approved = true, status = "approved", hashes = to_set(obj.hashes) }, nil
    end
  end

  local query = { package = pkg }
  if user then
    query.user = user
  end

  local httpc = http.new()
  httpc:set_timeout(TIMEOUT_MS)
  local res, err = httpc:request_uri(APPROVAL_URL .. "/check", {
    query   = query,
    method  = "GET",
    headers = { ["Accept"] = "application/json" },
  })
  if not res then
    return nil, "approval api unreachable: " .. tostring(err)
  end
  if res.status ~= 200 then
    return nil, "approval api status " .. res.status
  end
  local body = cjson.decode(res.body)
  if not body then
    return nil, "approval api returned invalid json"
  end

  local approved = body.approved == true
  local status = body.status or (approved and "approved" or "pending")
  if approved then
    cache:set(cache_key, cjson.encode({ hashes = body.hashes or {} }), CACHE_TTL)
  end
  return { approved = approved, status = status, hashes = to_set(body.hashes) }, nil
end

return _M
