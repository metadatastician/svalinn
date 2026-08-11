> [!WARNING]
> **SUPERSEDED — this document contains claims falsified by measurement on 2026-07-28.**
> See `STATUS.md` in this repo for measured state, and
> `dev-notes/stapeln-ecosystem-COMPREHENSIVE-SITREP-2026-07-28.md` for full evidence.
> Falsified here: states 'Languages: ReScript' and cites src/abi/*.idr and '20+ Obj.magic calls' — the repo has 0 .res files, 0 .idr files, and no src/abi/. Retained for history; do not cite.

<!--
SPDX-License-Identifier: CC-BY-SA-4.0
Copyright (c) Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>
-->
# PROOF-NEEDS.md
## Current State

- **LOC**: ~7,050
- **Languages**: ReScript
- **Existing ABI proofs**: `src/abi/*.idr` (template-level)
- **Dangerous patterns**: 20+ `Obj.magic` calls across auth, MCP server, compose orchestrator, policy store, tests

## What Needs Proving

### Authentication Middleware (src/auth/)
- `AuthMiddleware.res`: `Obj.magic(payload)` for JWT token parsing — unsafe cast from decoded JSON to typed token
- `OAuth2.res`: Multiple `Obj.magic` for OAuth response construction and JSON parsing
- Prove: token validation always produces well-typed auth context or rejects

### MCP Server (src/mcp/)
- `McpServer.res`: 10+ `Obj.magic` calls for parameter extraction from JSON, tool result construction
- Every `Obj.magic(args)["field"]` is an unchecked field access — could fail silently at runtime
- Prove: tool dispatch always receives correctly-shaped arguments matching tool schema

### Container Orchestration (src/compose/)
- `ComposeOrchestrator.res`: `Yaml.parse(content)->Obj.magic` — parsing YAML directly to typed compose file with no validation
- `Obj.magic(options)` for fetch — request options bypass type checking
- Prove: compose file parsing validates structure before use

### Policy Store (src/policy/)
- `PolicyStore.res` uses `Obj.magic` — security policies should never rely on unsafe casts

## Recommended Prover

- **Idris2** for ABI layer — model auth token lifecycle, prove token-to-context is total
- **Idris2** for MCP tool schema — prove JSON schema conformance at the type level

## Priority

**HIGH** — Security-sensitive service (auth, container management, policy enforcement) with pervasive `Obj.magic` in security-critical paths. Every auth and policy code path using unsafe casts is a potential bypass vector.
