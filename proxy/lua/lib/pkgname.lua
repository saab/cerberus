-- Pure-Lua package-name logic (no ngx dependencies) so it is unit-testable with
-- the bare `resty`/`luajit` CLI. PEP 503 normalization + filename extraction.
local _M = {}

-- PEP 503: lowercase and collapse any run of -_. into a single dash.
function _M.normalize(name)
  if not name or name == "" then
    return nil
  end
  return (name:gsub("[-_.]+", "-")):lower()
end

-- Extract the project name from a wheel/sdist filename. The name is everything
-- before the first dash that is followed by a digit (the version always starts
-- with a digit). This correctly handles hyphenated sdist names such as
-- "foo-bar-1.0.tar.gz" -> "foo-bar" (a plain "up to first dash" split would
-- wrongly yield "foo"). Returns the normalized name, or nil if unparseable.
function _M.from_filename(filename)
  if not filename then
    return nil
  end
  local name = filename:match("^(.-)%-%d")
  return _M.normalize(name)
end

-- Resolve the package for a request: use the /simple/ regex capture if present,
-- otherwise parse the basename of the URI as a wheel/sdist filename.
function _M.from_request(uri, pkg_capture)
  if pkg_capture and pkg_capture ~= "" then
    return _M.normalize(pkg_capture)
  end
  if not uri then
    return nil
  end
  local basename = uri:match("([^/]+)$")
  if not basename then
    return nil
  end
  return _M.from_filename(basename)
end

return _M
