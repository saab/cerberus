.PHONY: up down build test test-unit test-lua test-all logs clean approve reject revoke pin pending list

build:        ## Build all images
	docker compose build

up:           ## Start proxy + approval-api in the background
	docker compose up -d --build

down:         ## Stop and remove containers
	docker compose down

test:         ## Run the end-to-end gatekeeping suite
	docker compose up -d --build
	docker compose run --rm tester

# MSYS_NO_PATHCONV keeps Git-Bash on Windows from mangling container paths; it is
# ignored on Linux/macOS.
test-unit:    ## Python unit tests for the approval-api (mocks PyPI; offline)
	MSYS_NO_PATHCONV=1 docker run --rm -v "$(CURDIR)/approval-api:/app" -w /app python:3.14-slim \
	  sh -c "pip install -q -r requirements.txt -r requirements-dev.txt && pytest -q"

test-lua:     ## Pure-Lua unit tests via the resty CLI (offline)
	docker compose build proxy
	MSYS_NO_PATHCONV=1 docker run --rm -v "$(CURDIR)/proxy/lua:/usr/local/openresty/lua" \
	  -v "$(CURDIR)/tests/lua:/spec" cerberus-proxy resty /spec/pkgname_spec.lua

test-all: test-unit test-lua test   ## Run the full test pyramid

logs:         ## Tail proxy logs (gate decisions)
	docker compose logs -f proxy

clean:        ## Stop everything and remove volumes/orphans
	docker compose down --remove-orphans

# Convenience helpers for manual demos (PKG=<name>, defaults to six)
PKG ?= six
approve:      ## Approve a package: make approve PKG=requests
	curl -fsS -X POST localhost:9000/approve -H 'Content-Type: application/json' -d '{"package":"$(PKG)"}'; echo
reject:       ## Reject a pending package: make reject PKG=evilpkg
	curl -fsS -X POST localhost:9000/reject -H 'Content-Type: application/json' -d '{"package":"$(PKG)"}'; echo
revoke:       ## Revoke a package (back to unknown): make revoke PKG=requests
	curl -fsS -X POST localhost:9000/revoke -H 'Content-Type: application/json' -d '{"package":"$(PKG)"}'; echo
pin:          ## Admin-pin an exact hash: make pin PKG=six SHA=<sha256>
	curl -fsS -X POST localhost:9000/pin -H 'Content-Type: application/json' -d '{"package":"$(PKG)","hashes":["$(SHA)"]}'; echo
pending:      ## Show packages awaiting approval
	curl -fsS localhost:9000/pending; echo
list:         ## Show all state (approved + pending + rejected)
	curl -fsS localhost:9000/packages; echo
