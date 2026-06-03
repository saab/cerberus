-- Shared response helpers so the /simple/ gate and the /files/ handler emit
-- consistent, meaningful HTTP semantics per scenario.
--
-- uv/pip only surface the HTTP status code + canonical reason in their failure
-- output, so each scenario gets a *distinct* status code to differentiate it in
-- the client's terminal:
--   pending                  -> 503 Service Unavailable (+ Retry-After)
--   approval backend down    -> 504 Gateway Timeout (+ Retry-After)
--   rejected by policy       -> 403 Forbidden
--   artifact hash mismatch   -> 409 Conflict
--   bad request              -> 400 Bad Request
--   upstream broken          -> 502 Bad Gateway
-- Every response also carries machine- and human-readable detail in the
-- X-Cerberus-Status / X-Cerberus-Reason headers and a JSON body, for clients
-- (curl, pip -v, CI, logs) that do read them.
local cjson = require "cjson.safe"

local _M = {}

local RETRY_AFTER = tonumber(os.getenv("PENDING_RETRY_AFTER")) or 60  -- seconds

local HTTP_CONFLICT        = 409
local HTTP_GATEWAY_TIMEOUT = 504

local function send(http_status, cstatus, message, pkg, extra_headers)
  ngx.status = http_status
  ngx.header["Content-Type"]      = "application/json"
  ngx.header["X-Cerberus-Status"] = cstatus
  ngx.header["X-Cerberus-Reason"] = message
  if extra_headers then
    for k, v in pairs(extra_headers) do ngx.header[k] = v end
  end
  ngx.log(ngx.WARN, "cerberus: ", cstatus, " http=", http_status,
          " package='", tostring(pkg), "' reason=", message, " uri=", ngx.var.uri)
  ngx.say(cjson.encode({
    proxy   = "cerberus",
    status  = cstatus,
    package = pkg,
    message = message,
  }))
  return ngx.exit(http_status)
end

-- Captured/awaiting human approval -> retryable.
function _M.pending(pkg)
  return send(ngx.HTTP_SERVICE_UNAVAILABLE, "pending",
    "package '" .. tostring(pkg) .. "' is awaiting approval; an approval request has " ..
    "been recorded, retry after it is granted", pkg,
    { ["Retry-After"] = tostring(RETRY_AFTER) })
end

-- Approval backend unreachable/invalid -> fail closed, but retryable (may recover).
function _M.unavailable(pkg, reason)
  return send(HTTP_GATEWAY_TIMEOUT, "approval-unavailable",
    "approval service error, request denied (fail-closed): " .. tostring(reason), pkg,
    { ["Retry-After"] = tostring(RETRY_AFTER) })
end

-- Explicitly rejected by a human -> terminal deny.
function _M.rejected(pkg)
  return send(ngx.HTTP_FORBIDDEN, "rejected",
    "package '" .. tostring(pkg) .. "' was rejected by policy", pkg)
end

-- Artifact bytes do not match an approved hash -> integrity deny (409 Conflict).
function _M.hash_mismatch(pkg, got)
  return send(HTTP_CONFLICT, "hash-mismatch",
    "artifact for '" .. tostring(pkg) .. "' has sha256 " .. tostring(got) ..
    " which is not in the approved set", pkg)
end

function _M.bad_request(pkg, reason)
  return send(ngx.HTTP_BAD_REQUEST, "invalid-request", tostring(reason), pkg)
end

function _M.upstream_error(pkg, reason)
  return send(ngx.HTTP_BAD_GATEWAY, "upstream-error", tostring(reason), pkg)
end

return _M
