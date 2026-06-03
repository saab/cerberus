-- Unit tests for the pure-Lua name logic, plus a sha256 sanity check for the
-- resty libs used by serve_file.lua. Run with the resty CLI (no busted needed):
--   resty /spec/pkgname_spec.lua
package.path = "/usr/local/openresty/lua/?.lua;" .. package.path

local pkgname = require "lib.pkgname"

local fails = 0
local function eq(actual, expected, label)
  if actual == expected then
    print("  PASS: " .. label)
  else
    fails = fails + 1
    print(string.format("  FAIL: %s (got %s, want %s)",
      label, tostring(actual), tostring(expected)))
  end
end

print("normalize:")
eq(pkgname.normalize("Typing_Extensions"), "typing-extensions", "underscore + case")
eq(pkgname.normalize("typing.extensions"), "typing-extensions", "dot separator")
eq(pkgname.normalize("typing--extensions"), "typing-extensions", "collapse double dash")
eq(pkgname.normalize("Six"), "six", "simple lowercase")

print("from_filename:")
eq(pkgname.from_filename("six-1.17.0-py2.py3-none-any.whl"), "six", "wheel")
eq(pkgname.from_filename("foo-bar-1.0.tar.gz"), "foo-bar", "hyphenated sdist (Bug 1 regression guard)")
eq(pkgname.from_filename("zope.interface-5.4.0-cp39-cp39-manylinux1_x86_64.whl"), "zope-interface", "dotted wheel name")
eq(pkgname.from_filename("six-1.17.0-py2.py3-none-any.whl.metadata"), "six", "PEP 658 .metadata")
eq(pkgname.from_filename("backports.functools-lru-cache-1.6.6.tar.gz"), "backports-functools-lru-cache", "dotted + hyphenated sdist")
eq(pkgname.from_filename("README"), nil, "non-package filename -> nil")

print("from_request:")
eq(pkgname.from_request("/simple/foo/", "Foo_Bar"), "foo-bar", "uses /simple/ capture")
eq(pkgname.from_request("/files/aa/bb/six-1.17.0-py2.py3-none-any.whl", nil), "six", "parses /files/ filename")

print("resty sha256 sanity:")
local sha256 = require "resty.sha256"
local str    = require "resty.string"
local d = sha256:new()
d:update("abc")
eq(str.to_hex(d:final()),
  "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
  "sha256('abc')")

if fails > 0 then
  print(string.format("\n%d TEST(S) FAILED", fails))
  os.exit(1)
end
print("\nALL LUA TESTS PASSED")
os.exit(0)
