// SPDX-License-Identifier: MPL-2.0
// Copyright (c) Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>
/**
 * Property-Based Tests for Svalinn Policy Evaluation
 *
 * Tests invariant properties of the policy evaluator without relying on
 * external services:
 *   1. Determinism: same input always produces the same decision.
 *   2. Composition: allow ∩ allow = allow, allow ∩ deny = deny.
 *   3. JSON schema round-trip: gatekeeper-policy.v1.json field constraints.
 *   4. Monotonicity: adding deny rules never promotes a denied request to allowed.
 *   5. Registry extraction invariants.
 *
 * Run with:
 *   deno test --allow-net --allow-read --allow-env tests/property/policy_properties_test.js
 *
 * Author: Jonathan D.A. Jewell <6759885+hyperpolymath@users.noreply.github.com>
 */

// @ts-nocheck
import { assertEquals, assertExists } from "jsr:@std/assert@1";

// ─── Embedded policy evaluator (mirrors PolicyEvaluator.res) ─────────────────

/**
 * Extract the registry hostname from an image reference.
 * Matches the logic in PolicyEvaluator.Helpers.extractRegistry.
 *
 * @param {string} image
 * @returns {string}
 */
function extractRegistry(image) {
  const parts = image.split("/");
  if (parts.length === 1) return "docker.io";
  const first = parts[0];
  return (first.includes(".") || first.includes(":")) ? first : "docker.io";
}

/**
 * Basic glob pattern matching using regex conversion.
 * Matches PolicyEvaluator.Helpers.matchGlob semantics.
 *
 * @param {string} pattern
 * @param {string} value
 * @returns {boolean}
 */
function matchGlob(pattern, value) {
  const escaped = pattern.replace(/[.+^${}()|[\]\\]/g, "\\$&");
  const regexStr = escaped.replace(/\*/g, ".*").replace(/\?/g, ".");
  return new RegExp(`^${regexStr}$`).test(value);
}

/**
 * Evaluate a container request against an edge policy.
 * Returns a policyResult matching PolicyTypes.Types.policyResult.
 *
 * @param {{ name: string, registries: { allow: string[], deny: string[], requireSignature: boolean }, security: { allowPrivileged: boolean, allowHostNetwork: boolean } }} policy
 * @param {{ image: string, registry?: string, privileged?: boolean }} req
 * @returns {{ allowed: boolean, violations: Array<{rule: string, severity: string, message: string}>, appliedPolicy: string, evaluatedAt: string }}
 */
function evaluate(policy, req) {
  const violations = [];
  const registry = req.registry ?? extractRegistry(req.image);

  if (policy.registries.deny.length > 0 &&
      policy.registries.deny.some((d) => matchGlob(d, registry))) {
    violations.push({
      rule: "registries.deny",
      severity: "critical",
      message: `Registry '${registry}' is in the deny list`,
    });
  }

  if (policy.registries.allow.length > 0 &&
      !policy.registries.allow.some((a) => matchGlob(a, registry))) {
    violations.push({
      rule: "registries.allow",
      severity: "critical",
      message: `Registry '${registry}' is not in the allow list`,
    });
  }

  if (req.privileged && !policy.security.allowPrivileged) {
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
    appliedPolicy: policy.name,
    evaluatedAt: String(Date.now()),
  };
}

// ─── Policy factory ───────────────────────────────────────────────────────────

/**
 * Build a test edge policy with the given parameters.
 *
 * @param {string} name
 * @param {string[]} allowRegistries
 * @param {string[]} denyRegistries
 * @param {boolean} allowPrivileged
 * @returns {object}
 */
function makePolicy(name, allowRegistries, denyRegistries, allowPrivileged) {
  return {
    name,
    registries: {
      allow: allowRegistries,
      deny: denyRegistries,
      requireSignature: false,
    },
    security: {
      allowPrivileged,
      allowHostNetwork: false,
    },
  };
}

// ─── Test fixtures ────────────────────────────────────────────────────────────

const SAMPLE_IMAGES = [
  "docker.io/library/alpine:3.18",
  "ghcr.io/hyperpolymath/app:1.0",
  "evil.registry.com/malware:latest",
  "localhost:5000/local-image:dev",
  "alpine:latest",
  "nginx:1.25",
  "quay.io/prometheus/node-exporter:v1.6.0",
];

const SAMPLE_ALLOW_LISTS = [
  [],
  ["docker.io"],
  ["docker.io", "ghcr.io"],
  ["*"],
  ["*.internal"],
];

const SAMPLE_DENY_LISTS = [
  [],
  ["evil.registry.com"],
  ["*"],
];

// ─── 1. Determinism ───────────────────────────────────────────────────────────

Deno.test("determinism: same image + policy always produces same result", () => {
  for (const image of SAMPLE_IMAGES) {
    for (const allow of SAMPLE_ALLOW_LISTS) {
      for (const deny of SAMPLE_DENY_LISTS) {
        const policy = makePolicy("det-test", allow, deny, false);
        const req = { image };

        const r1 = evaluate(policy, req);
        const r2 = evaluate(policy, req);
        const r3 = evaluate(policy, req);

        assertEquals(
          r1.allowed,
          r2.allowed,
          `Determinism failed: image=${image} allow=${JSON.stringify(allow)} deny=${JSON.stringify(deny)}`,
        );
        assertEquals(r2.allowed, r3.allowed);
        assertEquals(r1.violations.length, r2.violations.length);
        assertEquals(
          r1.violations.map((v) => v.rule).sort().join(","),
          r2.violations.map((v) => v.rule).sort().join(","),
        );
      }
    }
  }
});

Deno.test("determinism: privileged flag always produces same result", () => {
  const policy = makePolicy("priv-det", ["docker.io"], [], false);

  for (const privileged of [true, false]) {
    const req = { image: "docker.io/library/alpine:3.18", privileged };
    const r1 = evaluate(policy, req);
    const r2 = evaluate(policy, req);
    assertEquals(r1.allowed, r2.allowed);
    assertEquals(r1.violations.length, r2.violations.length);
  }
});

// ─── 2. Composition properties ────────────────────────────────────────────────

Deno.test("composition: allow ∩ allow = allow (both permissive → allowed)", () => {
  const p1 = makePolicy("allow-all-1", [], [], false);
  const p2 = makePolicy("allow-all-2", [], [], false);

  for (const image of ["docker.io/library/alpine:3.18", "alpine:latest"]) {
    const req = { image };
    const r1 = evaluate(p1, req);
    const r2 = evaluate(p2, req);
    assertEquals(r1.allowed, true, `p1 should allow ${image}`);
    assertEquals(r2.allowed, true, `p2 should allow ${image}`);
  }
});

Deno.test("composition: strict ∩ strict for same registry → both deny unknown", () => {
  const p1 = makePolicy("strict-1", ["docker.io"], [], false);
  const p2 = makePolicy("strict-2", ["docker.io"], [], false);
  const req = { image: "unknown.example.com/app:1.0" };

  const r1 = evaluate(p1, req);
  const r2 = evaluate(p2, req);

  assertEquals(r1.allowed, false);
  assertEquals(r2.allowed, false);
});

Deno.test("composition: allow ∩ deny = deny (permissive ∩ strict → strict wins)", () => {
  const permissive = makePolicy("perm", [], [], true);
  const strict = makePolicy("strict", ["docker.io"], ["evil.registry.com"], false);

  // Request that permissive allows but strict denies
  const req = { image: "evil.registry.com/app:1.0", privileged: true };

  const permResult = evaluate(permissive, req);
  const strictResult = evaluate(strict, req);

  assertEquals(permResult.allowed, true, "permissive should allow this request");
  assertEquals(strictResult.allowed, false, "strict should deny this request");

  // Composed: deny takes precedence — at least one critical violation exists
  const composedViolations = [...permResult.violations, ...strictResult.violations];
  const hasCritical = composedViolations.some((v) => v.severity === "critical");
  assertEquals(hasCritical, true);
});

Deno.test("composition: empty deny + non-empty allow → deny unknown registries", () => {
  const policy = makePolicy("selective", ["docker.io", "ghcr.io"], [], false);

  const allowed = ["docker.io/library/alpine:3.18", "ghcr.io/owner/app:1.0", "alpine:latest"];
  const denied = ["quay.io/app:1", "registry.k8s.io/pause:3", "evil.example.com/c:3"];

  for (const image of allowed) {
    const result = evaluate(policy, { image });
    const hasRegistryViolation = result.violations.some((v) => v.rule === "registries.allow");
    assertEquals(hasRegistryViolation, false, `Expected ${image} to pass registries.allow`);
  }

  for (const image of denied) {
    const result = evaluate(policy, { image });
    const hasRegistryViolation = result.violations.some((v) => v.rule === "registries.allow");
    assertEquals(hasRegistryViolation, true, `Expected ${image} to fail registries.allow`);
  }
});

// ─── 3. JSON schema round-trip for gatekeeper-policy.v1.json ─────────────────

/**
 * Minimal inline schema validator for gatekeeper-policy.v1.json.
 * Implements the required-field + type checks from the schema.
 *
 * @param {unknown} obj
 * @returns {string[]} Array of validation error strings (empty = valid)
 */
function validateGatekeeperPolicy(obj) {
  const errors = [];
  if (typeof obj !== "object" || obj === null) return ["root must be an object"];

  if (obj.version !== 1) errors.push("version must be 1");
  if (!Array.isArray(obj.requiredPredicates) || obj.requiredPredicates.length < 1) {
    errors.push("requiredPredicates must be a non-empty array");
  }
  if (!Array.isArray(obj.allowedSigners) || obj.allowedSigners.length < 1) {
    errors.push("allowedSigners must be a non-empty array");
  }
  if (Array.isArray(obj.allowedSigners)) {
    for (const s of obj.allowedSigners) {
      if (!/^sha256:[a-f0-9]{64}$/.test(s)) {
        errors.push(`allowedSigners: '${s}' does not match sha256:[a-f0-9]{64}`);
      }
    }
  }
  if (typeof obj.logQuorum !== "number" || obj.logQuorum < 1) {
    errors.push("logQuorum must be integer >= 1");
  }
  if (obj.mode !== undefined && obj.mode !== "strict" && obj.mode !== "permissive") {
    errors.push("mode must be 'strict' or 'permissive'");
  }

  return errors;
}

const VALID_POLICIES = [
  {
    version: 1,
    requiredPredicates: ["https://slsa.dev/provenance/v1"],
    allowedSigners: ["sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"],
    logQuorum: 1,
    mode: "strict",
  },
  {
    version: 1,
    requiredPredicates: ["https://slsa.dev/provenance/v1", "https://spdx.dev/Document"],
    allowedSigners: [
      "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    ],
    logQuorum: 2,
    mode: "permissive",
    notes: "Dual-signer policy for CI/CD",
  },
];

Deno.test("schema round-trip: valid gatekeeper policies pass validation", () => {
  for (const policy of VALID_POLICIES) {
    const errors = validateGatekeeperPolicy(policy);
    assertEquals(errors, [], `Policy failed: ${JSON.stringify(errors)}`);
  }
});

Deno.test("schema round-trip: invalid version is rejected", () => {
  const bad = { ...VALID_POLICIES[0], version: 2 };
  const errors = validateGatekeeperPolicy(bad);
  assertEquals(errors.some((e) => e.includes("version")), true);
});

Deno.test("schema round-trip: empty requiredPredicates is rejected", () => {
  const bad = { ...VALID_POLICIES[0], requiredPredicates: [] };
  const errors = validateGatekeeperPolicy(bad);
  assertEquals(errors.some((e) => e.includes("requiredPredicates")), true);
});

Deno.test("schema round-trip: signer not matching sha256 pattern is rejected", () => {
  const bad = { ...VALID_POLICIES[0], allowedSigners: ["not-a-valid-key-id"] };
  const errors = validateGatekeeperPolicy(bad);
  assertEquals(errors.some((e) => e.includes("allowedSigners")), true);
});

Deno.test("schema round-trip: logQuorum = 0 is rejected", () => {
  const bad = { ...VALID_POLICIES[0], logQuorum: 0 };
  const errors = validateGatekeeperPolicy(bad);
  assertEquals(errors.some((e) => e.includes("logQuorum")), true);
});

Deno.test("schema round-trip: invalid mode value is rejected", () => {
  const bad = { ...VALID_POLICIES[0], mode: "allow-all" };
  const errors = validateGatekeeperPolicy(bad);
  assertEquals(errors.some((e) => e.includes("mode")), true);
});

Deno.test("schema round-trip: missing allowedSigners is rejected", () => {
  const { allowedSigners: _removed, ...bad } = VALID_POLICIES[0];
  const errors = validateGatekeeperPolicy(bad);
  assertEquals(errors.some((e) => e.includes("allowedSigners")), true);
});

// ─── 4. Registry extraction invariants ───────────────────────────────────────

Deno.test("registry extraction: bare name always maps to docker.io", () => {
  const bareNames = ["alpine", "nginx", "ubuntu", "debian:bullseye"];
  for (const name of bareNames) {
    assertEquals(extractRegistry(name), "docker.io");
  }
});

Deno.test("registry extraction: explicit registry hostname is preserved", () => {
  assertEquals(extractRegistry("ghcr.io/owner/repo:tag"), "ghcr.io");
  assertEquals(extractRegistry("quay.io/prometheus/node-exporter:v1"), "quay.io");
  assertEquals(extractRegistry("registry.k8s.io/pause:3.9"), "registry.k8s.io");
});

Deno.test("registry extraction: localhost with port is preserved", () => {
  assertEquals(extractRegistry("localhost:5000/myapp:dev"), "localhost:5000");
});

// ─── 5. Monotonicity ─────────────────────────────────────────────────────────

Deno.test("monotonicity: adding deny entries never promotes denied to allowed", () => {
  const req = { image: "evil.registry.com/malware:latest" };
  const policyWithDeny = makePolicy("with-deny", [], ["evil.registry.com"], false);
  const policyWithMoreDeny = makePolicy(
    "more-deny", [], ["evil.registry.com", "extra-bad.com"], false
  );

  const r1 = evaluate(policyWithDeny, req);
  const r2 = evaluate(policyWithMoreDeny, req);

  // If r1 denies, r2 must also deny (more restrictions cannot promote to allow)
  if (!r1.allowed) {
    assertEquals(r2.allowed, false);
  }
});

// ─── 6. Glob matching edge cases ─────────────────────────────────────────────

Deno.test("glob: '*' matches any string", () => {
  assertEquals(matchGlob("*", "docker.io"), true);
  assertEquals(matchGlob("*", "evil.example.com"), true);
  assertEquals(matchGlob("*", ""), true);
});

Deno.test("glob: '*.internal' matches subdomains but not the root or external", () => {
  assertEquals(matchGlob("*.internal", "registry.internal"), true);
  assertEquals(matchGlob("*.internal", "a.b.internal"), true);
  assertEquals(matchGlob("*.internal", "internal"), false);
  assertEquals(matchGlob("*.internal", "evil.external.com"), false);
});

Deno.test("glob: exact match only for patterns without wildcards", () => {
  assertEquals(matchGlob("docker.io", "docker.io"), true);
  assertEquals(matchGlob("docker.io", "evil.docker.io"), false);
  assertEquals(matchGlob("docker.io", "docker.io.evil.com"), false);
});
