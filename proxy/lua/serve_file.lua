-- Verify-then-serve handler for /files/. Fetches the artifact from
-- files.pythonhosted.org into memory, computes its sha256, and only releases the
-- bytes to the client if the digest is in the package's approved hash set. This
-- guarantees the served artifact is byte-identical to what was approved -- a
-- mismatch yields 403 with no bytes leaked. (Artifact is buffered in memory:
-- fine for wheels/sdists, not for very large packages.)
local pkgname  = require "lib.pkgname"
local approval = require "lib.approval"
local respond  = require "lib.response"
local http     = require "resty.http"
local sha256   = require "resty.sha256"
local str      = require "resty.string"

local FILES_BASE = "https://files.pythonhosted.org"

local pkg = pkgname.from_request(ngx.var.uri, nil)
if not pkg then
  return respond.bad_request(nil, "could not determine package name from request")
end

local decision, err = approval.check(pkg)
if err then
  return respond.unavailable(pkg, err)             -- fail closed (retryable)
end
if decision.status == "rejected" then
  return respond.rejected(pkg)
elseif decision.status ~= "approved" then
  return respond.pending(pkg)                       -- pending (or just-captured)
end
local hashset = decision.hashes

-- Strip the /files prefix to get the upstream path (keep any query string).
local upstream_path = ngx.var.uri:gsub("^/files", "")
local target = FILES_BASE .. upstream_path

local httpc = http.new()
httpc:set_timeout(30000)
-- ssl_verify=true validates files.pythonhosted.org's certificate against the
-- trust store configured by `lua_ssl_trusted_certificate` in nginx.conf; the
-- SNI/verification host is taken from the HTTPS target URL. A bad cert fails the
-- request (no bytes served). Content integrity is then enforced by the sha256
-- check below, so transport (TLS) and content (hash pin) are both validated.
local res, ferr = httpc:request_uri(target, {
  method     = "GET",
  ssl_verify = true,
})
if not res then
  return respond.upstream_error(pkg, "could not fetch artifact from upstream: " .. tostring(ferr))
end

-- Pass through upstream non-200 (e.g. 404) unchanged, tagged for observability.
if res.status ~= 200 then
  ngx.status = res.status
  ngx.header["Content-Type"] = res.headers["Content-Type"] or "application/octet-stream"
  ngx.header["X-Cerberus-Status"] = "upstream-status"
  ngx.print(res.body or "")
  return ngx.exit(res.status)
end

-- Compute the digest of exactly the bytes we are about to serve.
local d = sha256:new()
d:update(res.body)
local hex = str.to_hex(d:final())

if not hashset[hex] then
  return respond.hash_mismatch(pkg, hex)
end

ngx.status = 200
ngx.header["Content-Type"] = res.headers["Content-Type"] or "application/octet-stream"
ngx.header["Content-Length"] = #res.body
ngx.log(ngx.INFO, "cerberus: SERVED package='", pkg, "' sha256=", hex)
ngx.print(res.body)
