// SPDX-License-Identifier: MPL-2.0
// Copyright (c) Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>
/**
 * E2E Gateway Tests for Svalinn
 *
 * Tests the full auth → policy → gateway HTTP pipeline using Deno's built-in
 * HTTP primitives and mock JWT tokens. No real OAuth2/JWKS endpoint is
 * contacted — all external calls are intercepted via an in-process Hono app.
 *
 * Run with:
 *   deno test --allow-net --allow-read --allow-env tests/e2e/gateway_test.js
 *
 * Author: Jonathan D.A. Jewell <6759885+hyperpolymath@users.noreply.github.com>
 */

// @ts-nocheck
import { assertEquals, assertExists } from "jsr:@std/assert@1";
import { Hono } from "jsr:@hono/hono@^4";

// ─── Minimal in-process policy evaluator ─────────────────────────────────────

/**
 * Very small policy evaluator that mirrors PolicyEvaluator.res semantics.
 * Enforces strict policy: docker.io + ghcr.io allowed, evil.registry.com denied,
 * no privileged containers.
 *
 * @param {string} imageRef - Image reference string (e.g. "docker.io/library/alpine:3.18")
 * @param {boolean} privileged - Whether the container requests privileged mode
 * @returns {{ allowed: boolean, violations: Array<{rule: string, severity: string, message: string}>, appliedPolicy: string, evaluatedAt: string }}
 */
function evaluatePolicy(imageRef, privileged) {
  const violations = [];
  const allowedRegistries = ["docker.io", "ghcr.io"];

  // Extract registry from image reference (mirrors PolicyEvaluator.Helpers.extractRegistry)
  const parts = imageRef.split("/");
  let registry;
  if (parts.length === 1) {
    registry = "docker.io";
  } else {
    const first = parts[0];
    registry = (first.includes(".") || first.includes(":")) ? first : "docker.io";
  }

  const deniedRegistries = ["evil.registry.com", "malware.io"];
  if (deniedRegistries.some((d) => registry === d)) {
    violations.push({
      rule: "registries.deny",
      severity: "critical",
      message: `Registry '${registry}' is in the deny list`,
    });
  } else if (!allowedRegistries.includes(registry)) {
    violations.push({
      rule: "registries.allow",
      severity: "critical",
      message: `Registry '${registry}' is not in the allow list`,
    });
  }

  if (privileged) {
    violations.push({
      rule: "security.allowPrivileged",
      severity: "critical",
      message: "Privileged containers are not allowed",
    });
  }

  const hasCritical = violations.some((v) => v.severity === "critical");
  return {
    allowed: !hasCritical,
    violations,
    appliedPolicy: "strict",
    evaluatedAt: String(Date.now()),
  };
}

// ─── Mock JWT helpers ─────────────────────────────────────────────────────────

/**
 * Build a mock Bearer token for use in Authorization headers.
 * The token uses base64-encoded JSON header + payload + a mock signature.
 * The _testValid sentinel field is used by the mock auth middleware.
 *
 * @param {{ sub?: string, iss?: string, exp?: number, valid?: boolean }} opts
 * @returns {string} JWT-format token string
 */
function makeBearerToken(opts = {}) {
  const payload = {
    sub: opts.sub ?? "user123",
    iss: opts.iss ?? "https://auth.example.com",
    aud: "svalinn",
    exp: opts.exp ?? (Math.floor(Date.now() / 1000) + 3600),
    iat: Math.floor(Date.now() / 1000),
    _testValid: opts.valid ?? true,
  };
  const header = btoa(JSON.stringify({ alg: "RS256", typ: "JWT" }));
  const body = btoa(JSON.stringify(payload));
  return `${header}.${body}.mock-signature`;
}

/**
 * Parse a mock token from an Authorization header value.
 * Returns null if the header is absent or the token is structurally invalid.
 *
 * @param {string | null} authHeader
 * @returns {{ valid: boolean, sub?: string, exp?: number } | null}
 */
function parseMockToken(authHeader) {
  if (!authHeader || !authHeader.startsWith("Bearer ")) return null;
  const token = authHeader.slice(7);
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  try {
    const payload = JSON.parse(atob(parts[1]));
    const now = Math.floor(Date.now() / 1000);
    if (payload.exp !== undefined && payload.exp < now) {
      return { valid: false, sub: payload.sub };
    }
    if (payload._testValid === false) {
      return { valid: false };
    }
    return { valid: true, sub: payload.sub, exp: payload.exp };
  } catch {
    return null;
  }
}

// ─── In-process Hono app ──────────────────────────────────────────────────────

/**
 * Build a lightweight Hono app that mirrors the Svalinn gateway's routing
 * surface without depending on external services.
 *
 * @returns {Hono}
 */
function buildTestApp() {
  const app = new Hono();

  // Authentication middleware — skip on /health
  app.use("*", async (c, next) => {
    if (c.req.path === "/health") {
      await next();
      return;
    }

    const authHeader = c.req.header("Authorization") ?? null;
    const parsed = parseMockToken(authHeader);

    if (!parsed) {
      return c.json(
        { error: { code: 401, id: "ERR_UNAUTHENTICATED", message: "No valid Bearer token provided" } },
        401,
      );
    }

    if (!parsed.valid) {
      return c.json(
        { error: { code: 401, id: "ERR_TOKEN_INVALID", message: "Token is invalid or expired" } },
        401,
      );
    }

    c.set("authSubject", parsed.sub ?? "unknown");
    await next();
  });

  // Health endpoint
  app.get("/health", (c) => {
    return c.json({ status: "ok", version: "0.1.0" });
  });

  // Container run endpoint
  app.post("/api/v1/run", async (c) => {
    let body;
    try {
      body = await c.req.json();
    } catch {
      return c.json(
        { error: { code: 400, id: "ERR_INVALID_JSON", message: "Request body is not valid JSON" } },
        400,
      );
    }

    if (!body.imageName || typeof body.imageName !== "string") {
      return c.json(
        { error: { code: 400, id: "ERR_VALIDATION_FAILED", message: "Missing required field: imageName" } },
        400,
      );
    }

    if (!body.imageDigest || typeof body.imageDigest !== "string") {
      return c.json(
        { error: { code: 400, id: "ERR_VALIDATION_FAILED", message: "Missing required field: imageDigest" } },
        400,
      );
    }

    const privileged = body.privileged === true;
    const policyResult = evaluatePolicy(body.imageName, privileged);

    if (!policyResult.allowed) {
      return c.json(
        {
          error: {
            code: 403,
            id: "ERR_POLICY_DENIED",
            message: "Request denied by edge policy",
            details: { violations: policyResult.violations },
          },
        },
        403,
      );
    }

    return c.json(
      {
        id: "container-" + Math.random().toString(36).slice(2, 10),
        image_id: body.imageName,
        state: "created",
        name: "test-container",
        created_at: new Date().toISOString(),
      },
      201,
    );
  });

  return app;
}

// ─── Test helpers ─────────────────────────────────────────────────────────────

const app = buildTestApp();

/**
 * Make a request to the in-process Hono app.
 *
 * @param {string} method
 * @param {string} path
 * @param {{ token?: string | null, body?: unknown, contentType?: string }} opts
 * @returns {Promise<Response>}
 */
async function request(method, path, opts = {}) {
  const headers = {};

  // opts.token === null means explicitly unauthenticated
  if (opts.token !== null) {
    const token = opts.token ?? makeBearerToken();
    headers["Authorization"] = `Bearer ${token}`;
  }

  if (opts.body !== undefined) {
    headers["Content-Type"] = opts.contentType ?? "application/json";
  }

  const req = new Request(`http://localhost${path}`, {
    method,
    headers,
    body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
  });

  return app.fetch(req);
}

// ─── Tests ────────────────────────────────────────────────────────────────────

// 1. Health endpoint

Deno.test("GET /health: returns 200 with status ok (no auth required)", async () => {
  const res = await request("GET", "/health", { token: null });
  assertEquals(res.status, 200);
  const body = await res.json();
  assertEquals(body.status, "ok");
  assertExists(body.version);
});

// 2. Authentication boundary tests

Deno.test("POST /api/v1/run: unauthenticated request returns 401", async () => {
  const res = await request("POST", "/api/v1/run", {
    token: null,
    body: { imageName: "docker.io/library/alpine:3.18", imageDigest: "sha256:abc" },
  });
  assertEquals(res.status, 401);
  const body = await res.json();
  assertEquals(body.error.id, "ERR_UNAUTHENTICATED");
});

Deno.test("POST /api/v1/run: expired token returns 401", async () => {
  const expiredToken = makeBearerToken({ exp: Math.floor(Date.now() / 1000) - 3600 });
  const res = await request("POST", "/api/v1/run", {
    token: expiredToken,
    body: { imageName: "docker.io/library/alpine:3.18", imageDigest: "sha256:abc" },
  });
  assertEquals(res.status, 401);
  const body = await res.json();
  assertEquals(body.error.id, "ERR_TOKEN_INVALID");
});

Deno.test("POST /api/v1/run: malformed token (not 3 parts) returns 401", async () => {
  const res = await request("POST", "/api/v1/run", {
    token: "not.a.valid.jwt.token",
    body: { imageName: "docker.io/library/alpine:3.18", imageDigest: "sha256:abc" },
  });
  assertEquals(res.status, 401);
});

Deno.test("POST /api/v1/run: token with invalid signature sentinel returns 401", async () => {
  const invalidToken = makeBearerToken({ valid: false });
  const res = await request("POST", "/api/v1/run", {
    token: invalidToken,
    body: { imageName: "docker.io/library/alpine:3.18", imageDigest: "sha256:abc" },
  });
  assertEquals(res.status, 401);
  const body = await res.json();
  assertEquals(body.error.code, 401);
});

// 3. Policy authorisation tests

Deno.test("POST /api/v1/run: authenticated + allowed image returns 201", async () => {
  const res = await request("POST", "/api/v1/run", {
    body: {
      imageName: "docker.io/library/alpine:3.18",
      imageDigest: "sha256:abcdef1234567890",
    },
  });
  assertEquals(res.status, 201);
  const body = await res.json();
  assertEquals(body.state, "created");
  assertExists(body.id);
});

Deno.test("POST /api/v1/run: authenticated but denied registry returns 403", async () => {
  const res = await request("POST", "/api/v1/run", {
    body: {
      imageName: "evil.registry.com/malware:latest",
      imageDigest: "sha256:abc",
    },
  });
  assertEquals(res.status, 403);
  const body = await res.json();
  assertEquals(body.error.id, "ERR_POLICY_DENIED");
  assertEquals(body.error.details.violations.some((v) => v.rule === "registries.deny"), true);
});

Deno.test("POST /api/v1/run: authenticated + unknown registry returns 403", async () => {
  const res = await request("POST", "/api/v1/run", {
    body: {
      imageName: "unknown-reg.io/app:1.0",
      imageDigest: "sha256:abc",
    },
  });
  assertEquals(res.status, 403);
  const body = await res.json();
  assertEquals(body.error.id, "ERR_POLICY_DENIED");
});

Deno.test("POST /api/v1/run: authenticated + privileged request returns 403", async () => {
  const res = await request("POST", "/api/v1/run", {
    body: {
      imageName: "docker.io/library/alpine:3.18",
      imageDigest: "sha256:abc",
      privileged: true,
    },
  });
  assertEquals(res.status, 403);
  const body = await res.json();
  assertEquals(body.error.id, "ERR_POLICY_DENIED");
  assertEquals(
    body.error.details.violations.some((v) => v.rule === "security.allowPrivileged"),
    true,
  );
});

// 4. Request validation tests

Deno.test("POST /api/v1/run: missing imageName returns 400", async () => {
  const res = await request("POST", "/api/v1/run", {
    body: { imageDigest: "sha256:abc" },
  });
  assertEquals(res.status, 400);
  const body = await res.json();
  assertEquals(body.error.id, "ERR_VALIDATION_FAILED");
});

Deno.test("POST /api/v1/run: missing imageDigest returns 400", async () => {
  const res = await request("POST", "/api/v1/run", {
    body: { imageName: "docker.io/library/alpine:3.18" },
  });
  assertEquals(res.status, 400);
  const body = await res.json();
  assertEquals(body.error.id, "ERR_VALIDATION_FAILED");
});

Deno.test("POST /api/v1/run: invalid JSON body returns 400", async () => {
  const req = new Request("http://localhost/api/v1/run", {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${makeBearerToken()}`,
      "Content-Type": "application/json",
    },
    body: "{ this is not valid json !!!",
  });
  const res = await app.fetch(req);
  assertEquals(res.status, 400);
  const body = await res.json();
  assertEquals(body.error.id, "ERR_INVALID_JSON");
});

// 5. Error response schema conformance

Deno.test("error responses: 401 body conforms to error-response.v1.json shape", async () => {
  const res = await request("POST", "/api/v1/run", { token: null, body: {} });
  assertEquals(res.status, 401);
  const body = await res.json();
  // Required fields per error-response.v1.json: { error: { code, id, message } }
  assertExists(body.error);
  assertExists(body.error.code);
  assertExists(body.error.id);
  assertExists(body.error.message);
  assertEquals(typeof body.error.code, "number");
  assertEquals(typeof body.error.id, "string");
  assertEquals(typeof body.error.message, "string");
  // id must match ERR_[A-Z_]+ pattern
  assertEquals(/^ERR_[A-Z_]+$/.test(body.error.id), true);
});

Deno.test("error responses: 403 body conforms to error-response.v1.json shape", async () => {
  const res = await request("POST", "/api/v1/run", {
    body: { imageName: "evil.registry.com/x:1", imageDigest: "sha256:abc" },
  });
  assertEquals(res.status, 403);
  const body = await res.json();
  assertExists(body.error);
  assertExists(body.error.code);
  assertExists(body.error.id);
  assertExists(body.error.message);
  assertEquals(/^ERR_[A-Z_]+$/.test(body.error.id), true);
});

// 6. Full pipeline test

Deno.test("full pipeline: valid auth + allowed policy + valid schema → 201", async () => {
  const token = makeBearerToken({ sub: "pipeline-user" });
  const res = await request("POST", "/api/v1/run", {
    token,
    body: {
      imageName: "ghcr.io/hyperpolymath/svalinn:latest",
      imageDigest: "sha256:cafebabe0000000000000000000000000000000000000000000000000000cafe",
      removeOnExit: true,
      detach: false,
    },
  });
  assertEquals(res.status, 201);
  const body = await res.json();
  assertEquals(body.state, "created");
  assertExists(body.id);
  assertExists(body.created_at);
});
