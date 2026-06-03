-- Access-phase gate for the /simple/ index. Resolves the package name and
-- responds per approval state: approved -> proceed; pending -> 503 (Retry-After);
-- rejected -> 403; error -> 403 (fail closed). The per-artifact hash guarantee
-- is enforced separately in serve_file.lua for /files/.
local pkgname  = require "lib.pkgname"
local approval = require "lib.approval"
local respond  = require "lib.response"

local pkg = pkgname.from_request(ngx.var.uri, ngx.var.pkg)
if not pkg then
  return respond.bad_request(nil, "could not determine package name from request")
end

local decision, err = approval.check(pkg)
if err then
  return respond.unavailable(pkg, err)       -- fail closed (retryable)
end

if decision.status == "approved" then
  ngx.log(ngx.INFO, "cerberus: APPROVED (index) package='", pkg, "'")
  return
elseif decision.status == "rejected" then
  return respond.rejected(pkg)
end

return respond.pending(pkg)                    -- pending (or just-captured)
