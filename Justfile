# SPDX-License-Identifier: MPL-2.0
# Owner: Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>
# Justfile - Svalinn edge shield build orchestration

import? "contractile.just"

default:
    @just --list

# Development server with hot reload
dev:
    cd src && deno run --allow-net --allow-read --allow-env --watch main.ts

# Start production server
serve:
    cd src && deno run --allow-net --allow-read --allow-env main.ts

# Build ReScript sources
build-res:
    cd src && npx rescript build

# Build compiled binary
build:
    mkdir -p dist
    deno compile --allow-net --allow-read --allow-env -o dist/svalinn tools/mvp/svalinn_gateway.ts

# Run the tests that execute real svalinn code.
# Previously this pointed at tests/AuthTest.res.mjs and
# tests/PolicyEvaluatorTest.res.mjs -- two files that do not exist anywhere in
# the repo, so `just test` could not run at all. It also would not have
# mattered if it had: every other suite here reimplements svalinn inline and
# tests the reimplementation. Those now live in tests/spec-mirror/ and are NOT
# run by this recipe. See tests/spec-mirror/README.md.
test:
    deno test --allow-read --allow-env tests/schema/
    deno test --allow-all tests/mvp/

# Run the spec mirrors: executable specification, NOT coverage. These import
# zero lines of svalinn -- a pass here says the mirror agrees with itself.
test-spec-mirror:
    deno test --allow-all tests/spec-mirror/

# Type check
check:
    deno check tools/mvp/svalinn_gateway.ts

# Format code
fmt:
    cd src && deno fmt
    cd ui && npx rescript format src/*.res

# Check formatting without modifying
fmt-check:
    cargo fmt --all --check
# Lint code
lint:
    cd src && deno lint

# Clean build artifacts
clean:
    rm -rf dist/
    rm -rf src/**/*.res.mjs
    rm -rf ui/src/**/*.res.mjs

# Run all checks
precommit: fmt lint check test

# Build UI
build-ui:
    cd ui && npm install && npx rescript build

# Serve UI for development
dev-ui:
    cd ui && npx rescript build -w &
    cd ui && python3 -m http.server 3000 || deno run --allow-net --allow-read jsr:@std/http/file-server

# Start everything (gateway + UI)
start-all:
    just serve &
    just dev-ui

# Docker build
docker-build:
    docker build -t svalinn:latest .

# Show configuration
config:
    @echo "SVALINN_PORT=${SVALINN_PORT:-8000}"
    @echo "SVALINN_HOST=${SVALINN_HOST:-0.0.0.0}"
    @echo "VORDR_ENDPOINT=${VORDR_ENDPOINT:-http://localhost:8080}"
    @echo "SPEC_VERSION=${SPEC_VERSION:-v0.1.0}"

# Generate MCP schema
mcp-schema:
    cd src && deno run --allow-read --allow-write scripts/generate-mcp-schema.ts

# Validate spec schemas
validate-schemas:
    cd spec/schemas && for f in *.json; do echo "Validating $f..."; deno run --allow-read jsr:@std/json/validate "$f"; done

# Release a new version
release VERSION:
    @echo "Releasing {{VERSION}}..."
    git tag -a "v{{VERSION}}" -m "Release v{{VERSION}}"
    git push origin "v{{VERSION}}"

# Run panic-attacker pre-commit scan
assail:
    @command -v panic-attack >/dev/null 2>&1 && panic-attack assail . || echo "panic-attack not found — install from https://github.com/hyperpolymath/panic-attacker"

# Self-diagnostic — checks dependencies, permissions, paths
doctor:
    @echo "Running diagnostics for svalinn..."
    @echo "Checking required tools..."
    @command -v just >/dev/null 2>&1 && echo "  [OK] just" || echo "  [FAIL] just not found"
    @command -v git >/dev/null 2>&1 && echo "  [OK] git" || echo "  [FAIL] git not found"
    @echo "Checking for hardcoded paths..."
    @grep -rn '$HOME\|$ECLIPSE_DIR' --include='*.rs' --include='*.ex' --include='*.res' --include='*.gleam' --include='*.sh' . 2>/dev/null | head -5 || echo "  [OK] No hardcoded paths"
    @echo "Diagnostics complete."

# Auto-repair common issues
heal:
    @echo "Attempting auto-repair for svalinn..."
    @echo "Fixing permissions..."
    @find . -name "*.sh" -exec chmod +x {} \; 2>/dev/null || true
    @echo "Cleaning stale caches..."
    @rm -rf .cache/stale 2>/dev/null || true
    @echo "Repair complete."

# Guided tour of key features
tour:
    @echo "=== svalinn Tour ==="
    @echo ""
    @echo "1. Project structure:"
    @ls -la
    @echo ""
    @echo "2. Available commands: just --list"
    @echo ""
    @echo "3. Read README.adoc for full overview"
    @echo "4. Read EXPLAINME.adoc for architecture decisions"
    @echo "5. Run 'just doctor' to check your setup"
    @echo ""
    @echo "Tour complete! Try 'just --list' to see all available commands."

# Open feedback channel with diagnostic context
help-me:
    @echo "=== svalinn Help ==="
    @echo "Platform: $(uname -s) $(uname -m)"
    @echo "Shell: $SHELL"
    @echo ""
    @echo "To report an issue:"
    @echo "  https://github.com/hyperpolymath/svalinn/issues/new"
    @echo ""
    @echo "Include the output of 'just doctor' in your report."


# Print the current CRG grade (reads from READINESS.md '**Current Grade:** X' line)
crg-grade:
    @grade=$$(grep -oP '(?<=\*\*Current Grade:\*\* )[A-FX]' READINESS.md 2>/dev/null | head -1); \
    [ -z "$$grade" ] && grade="X"; \
    echo "$$grade"

# Generate a shields.io badge markdown for the current CRG grade
# Looks for '**Current Grade:** X' in READINESS.md; falls back to X
crg-badge:
    @grade=$$(grep -oP '(?<=\*\*Current Grade:\*\* )[A-FX]' READINESS.md 2>/dev/null | head -1); \
    [ -z "$$grade" ] && grade="X"; \
    case "$$grade" in \
      A) color="brightgreen" ;; B) color="green" ;; C) color="yellow" ;; \
      D) color="orange" ;; E) color="red" ;; F) color="critical" ;; \
      *) color="lightgrey" ;; esac; \
    echo "[![CRG $$grade](https://img.shields.io/badge/CRG-$$grade-$$color?style=flat-square)](https://github.com/hyperpolymath/standards/tree/main/component-readiness-grades)"

secret-scan-trufflehog:
    @command -v trufflehog >/dev/null && trufflehog filesystem . --only-verified || true
