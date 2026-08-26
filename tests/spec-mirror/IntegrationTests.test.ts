// SPDX-License-Identifier: MPL-2.0
// Copyright (c) Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>
/**
 * E2E, reflexive, and contract tests for Svalinn
 */

import { assertEquals, assertExists, assertNotEquals } from "jsr:@std/assert@1";

// NOTE: Jwt/OAuth2/PolicyEvaluator were ReScript modules; the *.res.mjs these
// tests imported was removed in the .res→.affine migration (svalinn#47).
// AffineScript has no JS backend yet, so the implementations are stubbed and
// every test is `ignore: true`. When AffineScript emits JS, re-point the stubs
// at the compiled output and drop the `ignore` flags.
const NOT_PORTED = "pending AffineScript→JS backend (migrated from ReScript in svalinn#47)";
const Jwt = {
  parseJwtSegments(_token: string): unknown {
    throw new Error(NOT_PORTED);
  },
};
const OAuth2 = {
  generateState(): string {
    throw new Error(NOT_PORTED);
  },
};
const PolicyEvaluator = {
  evaluate(_policy: unknown, _request: unknown): unknown {
    throw new Error(NOT_PORTED);
  },
};
// `assertNotEquals` retained from the original import surface.
void assertNotEquals;

// ===== Reflexive: JWT round-trip =====

Deno.test({
  name: "Reflexive: JWT encode then decode round-trip preserves sub claim",
  ignore: true,
  fn: () => {
    const subjects = ["user-abc", "service-account-123", "admin@example.com"];
    for (const sub of subjects) {
      const headerObj = { alg: "RS256", typ: "JWT" };
      const payloadObj = {
        sub,
        iss: "https://test.example.com",
        aud: "svalinn",
        exp: 9999999999,
        iat: 0,
      };
      const token = btoa(JSON.stringify(headerObj)) + "." + btoa(JSON.stringify(payloadObj)) +
        ".sig";
      const decoded = Jwt.parseJwtSegments(token) as { payload: { sub: string } };
      assertEquals(decoded.payload.sub, sub);
    }
  },
});

Deno.test({
  name: "Reflexive: JWT decode and re-encode header alg is stable",
  ignore: true,
  fn: () => {
    const algs = ["RS256", "ES256", "RS512"];
    for (const alg of algs) {
      const token = btoa(JSON.stringify({ alg, typ: "JWT" })) + "." +
        btoa(JSON.stringify({ sub: "x" })) + ".sig";
      const decoded = Jwt.parseJwtSegments(token) as { header: { alg: string } };
      assertEquals(decoded.header.alg, alg);
    }
  },
});

Deno.test({
  name: "Reflexive: policy evaluation result is deterministic for same input",
  ignore: true,
  fn: () => {
    const policy = {
      version: "1.0",
      name: "test",
      registries: { allow: ["docker.io"], deny: [], requireSignature: false },
      images: { allowPatterns: ["*"], denyPatterns: [], requireSbom: false },
      resources: { maxMemoryMb: 1024, maxCpuCores: 1 },
      security: {
        allowPrivileged: false,
        allowHostNetwork: false,
        allowHostPid: false,
        allowHostIpc: false,
        readOnlyRoot: false,
        dropCapabilities: [],
        addCapabilities: [],
      },
    };
    const request = { image: "docker.io/library/alpine:3.18" };
    const result1 = PolicyEvaluator.evaluate(policy, request) as { allowed: boolean };
    const result2 = PolicyEvaluator.evaluate(policy, request) as { allowed: boolean };
    assertEquals(result1.allowed, result2.allowed);
  },
});

// ===== Contract: API invariants =====

Deno.test({
  name: "Contract: PolicyEvaluator.evaluate always returns an object with allowed field",
  ignore: true,
  fn: () => {
    const policies = [
      {
        version: "1.0",
        name: "a",
        registries: { allow: [], deny: [], requireSignature: false },
        images: { allowPatterns: ["*"], denyPatterns: [], requireSbom: false },
        resources: { maxMemoryMb: 1024, maxCpuCores: 1 },
        security: {
          allowPrivileged: true,
          allowHostNetwork: true,
          allowHostPid: true,
          allowHostIpc: true,
          readOnlyRoot: false,
          dropCapabilities: [],
          addCapabilities: [],
        },
      },
    ];
    const requests = [
      { image: "alpine:latest" },
      { image: "docker.io/library/nginx:1.25" },
      { image: "x", privileged: true },
    ];
    for (const policy of policies) {
      for (const req of requests) {
        const result = PolicyEvaluator.evaluate(policy, req);
        assertExists(result);
        assertEquals(typeof (result as { allowed: boolean }).allowed, "boolean");
      }
    }
  },
});

Deno.test({
  name: "Contract: JWT parseJwtSegments returns object with header and payload for valid tokens",
  ignore: true,
  fn: () => {
    const token = btoa('{"alg":"RS256","typ":"JWT"}') + "." +
      btoa('{"sub":"u","iss":"i","aud":"a","exp":9999999999,"iat":0}') + ".sig";
    const decoded = Jwt.parseJwtSegments(token);
    assertExists(decoded);
    assertExists((decoded as { header: unknown }).header);
    assertExists((decoded as { payload: unknown }).payload);
  },
});

Deno.test({
  name: "Contract: generateState returns a non-empty string of length 64",
  ignore: true,
  fn: () => {
    const state = OAuth2.generateState();
    assertEquals(typeof state, "string");
    assertEquals(state.length, 64);
    // Must be hex-only
    assertEquals(/^[0-9a-f]{64}$/.test(state), true);
  },
});

Deno.test({
  name: "Contract: generateState produces different values on successive calls",
  ignore: true,
  fn: () => {
    const states = Array.from({ length: 10 }, () => OAuth2.generateState());
    const unique = new Set(states);
    assertEquals(unique.size, states.length, "All states should be unique");
  },
});

Deno.test({
  name: "Contract: policy violations is always an array",
  ignore: true,
  fn: () => {
    const policy = {
      version: "1.0",
      name: "test",
      registries: { allow: ["docker.io"], deny: ["evil.com"], requireSignature: false },
      images: { allowPatterns: ["*"], denyPatterns: [], requireSbom: false },
      resources: { maxMemoryMb: 1024, maxCpuCores: 1 },
      security: {
        allowPrivileged: false,
        allowHostNetwork: false,
        allowHostPid: false,
        allowHostIpc: false,
        readOnlyRoot: false,
        dropCapabilities: [],
        addCapabilities: [],
      },
    };
    const result = PolicyEvaluator.evaluate(policy, { image: "alpine" });
    assertEquals(Array.isArray((result as { violations: unknown[] }).violations), true);
  },
});

// ===== E2E: full workflow =====

Deno.test({
  name: "E2E: decode a JWT built manually, check claims, evaluate policy",
  ignore: true,
  fn: () => {
    // Build a JWT manually
    const header = btoa(JSON.stringify({ alg: "RS256", typ: "JWT" }));
    const payload = btoa(JSON.stringify({
      sub: "service-account-001",
      iss: "https://auth.svalinn.example.com",
      aud: "svalinn",
      exp: 9999999999,
      iat: 0,
      roles: ["operator"],
    }));
    const token = `${header}.${payload}.fake-sig`;

    // Step 1: decode JWT
    const decoded = Jwt.parseJwtSegments(token) as { payload: { sub: string; roles: string[] } };
    assertEquals(decoded.payload.sub, "service-account-001");

    // Step 2: based on role, choose a policy
    const isOperator = decoded.payload.roles?.includes("operator");
    const policy = {
      version: "1.0",
      name: "operator-policy",
      registries: { allow: ["docker.io", "ghcr.io"], deny: [], requireSignature: false },
      images: { allowPatterns: ["*"], denyPatterns: [], requireSbom: false },
      resources: { maxMemoryMb: 4096, maxCpuCores: 4 },
      security: {
        allowPrivileged: false,
        allowHostNetwork: false,
        allowHostPid: false,
        allowHostIpc: false,
        readOnlyRoot: false,
        dropCapabilities: [],
        addCapabilities: [],
      },
    };

    // Step 3: evaluate a container request
    const request = { image: "docker.io/library/nginx:1.25" };
    const result = PolicyEvaluator.evaluate(policy, request) as { allowed: boolean };
    assertEquals(isOperator, true);
    assertEquals(result.allowed, true);
  },
});

Deno.test({
  name: "E2E: smoke — parse a minimal JWT token with one field",
  ignore: true,
  fn: () => {
    const token = btoa('{"alg":"RS256"}') + "." + btoa('{"sub":"test"}') + ".sig";
    const decoded = Jwt.parseJwtSegments(token) as {
      header: { alg: string };
      payload: { sub: string };
    };
    assertEquals(decoded.header.alg, "RS256");
    assertEquals(decoded.payload.sub, "test");
  },
});

Deno.test({
  name: "E2E: denied registry propagates violation details",
  ignore: true,
  fn: () => {
    const policy = {
      version: "1.0",
      name: "strict",
      registries: { allow: ["docker.io"], deny: ["evil.com"], requireSignature: false },
      images: { allowPatterns: ["*"], denyPatterns: [], requireSbom: false },
      resources: { maxMemoryMb: 1024, maxCpuCores: 1 },
      security: {
        allowPrivileged: false,
        allowHostNetwork: false,
        allowHostPid: false,
        allowHostIpc: false,
        readOnlyRoot: false,
        dropCapabilities: [],
        addCapabilities: [],
      },
    };
    const result = PolicyEvaluator.evaluate(policy, { image: "evil.com/malware:latest" }) as {
      allowed: boolean;
      violations: Array<{ rule: string; severity: string }>;
    };
    assertEquals(result.allowed, false);
    const denyViolation = result.violations.find((v) => v.rule === "registries.deny");
    assertExists(denyViolation);
    assertEquals(denyViolation!.severity, "critical");
  },
});
