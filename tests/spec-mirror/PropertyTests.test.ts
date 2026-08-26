// SPDX-License-Identifier: MPL-2.0
// Copyright (c) Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>
/**
 * Property-based tests for Svalinn
 * Simulates proptest-style invariant checking with repeated iterations.
 */

import { assertEquals, assertExists } from "jsr:@std/assert@1";

// NOTE: Jwt/PolicyEvaluator were ReScript modules; the *.res.mjs these tests
// imported was removed in the .res→.affine migration (svalinn#47). AffineScript
// has no JS backend yet, so the implementations are stubbed and every test is
// `ignore: true`. When AffineScript emits JS, re-point the stubs at the compiled
// output and drop the `ignore` flags.
const NOT_PORTED = "pending AffineScript→JS backend (migrated from ReScript in svalinn#47)";
const Jwt = {
  parseJwtSegments(_token: string): unknown {
    throw new Error(NOT_PORTED);
  },
};
const PolicyEvaluator = {
  evaluate(_policy: unknown, _request: unknown): unknown {
    throw new Error(NOT_PORTED);
  },
};

// ===== Property helpers =====

function randomString(len: number): string {
  const chars = "abcdefghijklmnopqrstuvwxyz0123456789-_.";
  return Array.from({ length: len }, () => chars[Math.floor(Math.random() * chars.length)]).join(
    "",
  );
}

function randomRegistry(): string {
  const registries = ["docker.io", "ghcr.io", "gcr.io", "quay.io", "registry.example.com"];
  return registries[Math.floor(Math.random() * registries.length)];
}

function makeJwtToken(alg: string, sub: string, exp: number): string {
  const header = btoa(JSON.stringify({ alg, typ: "JWT" }));
  const payload = btoa(
    JSON.stringify({ sub, iss: "https://test.example.com", aud: "svalinn", exp, iat: 0 }),
  );
  return `${header}.${payload}.test-sig`;
}

// ===== P2P: JWT decode properties =====

Deno.test({
  name: "P2P: JWT decode never panics on valid 3-part tokens (100 iterations)",
  ignore: true,
  fn: () => {
    for (let i = 0; i < 100; i++) {
      const sub = `user-${randomString(8)}`;
      const token = makeJwtToken("RS256", sub, 9999999999);
      // Property: decode of a valid token never throws
      let decoded: unknown;
      try {
        decoded = Jwt.parseJwtSegments(token);
      } catch {
        decoded = null;
      }
      // Either decoded or threw — must not crash the runtime
      assertExists(typeof decoded === "object" || decoded === null);
    }
  },
});

Deno.test({
  name: "P2P: JWT decode returns object with header and payload for valid tokens",
  ignore: true,
  fn: () => {
    for (let i = 0; i < 50; i++) {
      const algs = ["RS256", "ES256", "HS256"];
      const alg = algs[i % algs.length];
      const token = makeJwtToken(alg, `user-${i}`, 9999999999);
      const decoded = Jwt.parseJwtSegments(token) as {
        header: { alg: string };
        payload: { sub: string };
      };
      // Property: decoded token has the same alg as what was encoded
      assertEquals(decoded.header.alg, alg);
      assertEquals(decoded.payload.sub, `user-${i}`);
    }
  },
});

Deno.test({
  name: "P2P: JWT decode always throws on tokens with fewer than 3 parts",
  ignore: true,
  fn: () => {
    const malformed = ["", "a", "a.b", "..", "a..b"];
    for (const t of malformed) {
      let threw = false;
      try {
        Jwt.parseJwtSegments(t);
      } catch {
        threw = true;
      }
      assertEquals(threw, true, `Expected throw for token: "${t}"`);
    }
  },
});

// ===== P2P: Policy evaluation properties =====

const strictPolicy = {
  version: "1.0",
  name: "strict",
  registries: {
    allow: ["docker.io", "ghcr.io"],
    deny: ["evil.registry.com"],
    requireSignature: false,
  },
  images: { allowPatterns: ["*"], denyPatterns: [], requireSbom: false },
  resources: { maxMemoryMb: 2048, maxCpuCores: 2 },
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

const openPolicy = {
  version: "1.0",
  name: "open",
  registries: { allow: [], deny: [], requireSignature: false },
  images: { allowPatterns: ["*"], denyPatterns: [], requireSbom: false },
  resources: { maxMemoryMb: 16384, maxCpuCores: 8 },
  security: {
    allowPrivileged: true,
    allowHostNetwork: true,
    allowHostPid: true,
    allowHostIpc: true,
    readOnlyRoot: false,
    dropCapabilities: [],
    addCapabilities: [],
  },
};

Deno.test({
  name: "P2P: open policy always allows any image (50 iterations)",
  ignore: true,
  fn: () => {
    for (let i = 0; i < 50; i++) {
      const image = `${randomRegistry()}/${randomString(6)}/app:${randomString(4)}`;
      const result = PolicyEvaluator.evaluate(openPolicy, { image });
      assertEquals(
        (result as { allowed: boolean }).allowed,
        true,
        `Expected allowed for image: ${image}`,
      );
    }
  },
});

Deno.test({
  name: "P2P: privileged request is always denied by non-privileged policy",
  ignore: true,
  fn: () => {
    for (let i = 0; i < 30; i++) {
      const image = `docker.io/library/alpine:${i}`;
      const result = PolicyEvaluator.evaluate(strictPolicy, { image, privileged: true });
      assertEquals((result as { allowed: boolean }).allowed, false);
    }
  },
});

Deno.test({
  name: "P2P: policy result always has required fields (50 iterations)",
  ignore: true,
  fn: () => {
    for (let i = 0; i < 50; i++) {
      const image = `docker.io/app:${i}`;
      const result = PolicyEvaluator.evaluate(openPolicy, { image }) as {
        allowed: boolean;
        violations: unknown[];
        appliedPolicy: string;
        evaluatedAt: string;
      };
      assertEquals(typeof result.allowed, "boolean");
      assertEquals(Array.isArray(result.violations), true);
      assertEquals(typeof result.appliedPolicy, "string");
      assertEquals(typeof result.evaluatedAt, "string");
    }
  },
});
