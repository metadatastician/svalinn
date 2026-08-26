// SPDX-License-Identifier: MPL-2.0
//
// The FIRST svalinn tests that execute svalinn's own code.
//
// Everything under tests/spec-mirror/ reimplements the gateway inline and then
// tests the reimplementation. These spawn the real tools/mvp/svalinn_gateway.ts
// as a subprocess and drive it over a real socket, so a pass here is evidence
// about svalinn rather than about a mirror.
//
// Modelled on rokur's test/integration_test.js, including its synchronous
// teardown: awaiting the subprocess exit after SIGTERM hangs the run.

import { assertEquals } from "@std/assert";
import { afterAll, beforeAll, describe, it } from "@std/testing/bdd";

const suiteOpts = { sanitizeResources: false, sanitizeOps: false };
const REPO_ROOT = new URL("../..", import.meta.url).pathname;
const TOKEN = "test-token-gatekeeper";

//  ANY HTTP response means the server is up and routing. Do NOT require 2xx:
//  /healthz answers 503 "degraded" whenever `vordr` is not on PATH, which is
//  the normal state on a test machine -- svalinn is still listening and still
//  applying policy, which is all these tests care about. Only a network error
//  means "not up yet".
async function waitFor(url: string, attempts = 40): Promise<void> {
  for (let i = 0; i < attempts; i++) {
    try {
      const r = await fetch(url);
      await r.body?.cancel();
      return;
    } catch { /* connection refused: not up yet */ }
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error(`${url} did not become ready`);
}

//  captureStderr=false for long-running servers. A piped stderr that nobody
//  drains fills its buffer and BLOCKS the child -- the server then never
//  finishes starting. Only the short-lived fail-closed cases pipe it, and they
//  read it immediately via proc.output().
function spawnGateway(
  port: number,
  configPath?: string,
  captureStderr = false,
): Deno.ChildProcess {
  const env: Record<string, string> = {
    ...Deno.env.toObject(),
    SVALINN_PORT: String(port),
    SVALINN_HOST: "127.0.0.1",
    SVALINN_API_TOKEN: TOKEN,
  };
  if (configPath) env.SVALINN_GATEKEEPER_CONFIG = configPath;
  else env.SVALINN_GATEKEEPER_CONFIG = "";
  return new Deno.Command("deno", {
    //  --allow-all: this is a test spawning our own gateway, and enumerating
    //  flags only adds a way for the subprocess to die for reasons unrelated
    //  to what is being tested.
    args: ["run", "--allow-all", "tools/mvp/svalinn_gateway.ts"],
    cwd: REPO_ROOT,
    env,
    stdout: "null",
    stderr: captureStderr ? "piped" : "null",
  }).spawn();
}

function writePolicy(body: string): string {
  const p = Deno.makeTempFileSync({ suffix: ".yaml" });
  Deno.writeTextFileSync(p, body);
  return p;
}

// ---------------------------------------------------------------------------
describe("gatekeeper policy is enforced", suiteOpts, () => {
  const PORT = 18801;
  const BASE = `http://127.0.0.1:${PORT}`;
  let proc: Deno.ChildProcess;
  let policyPath: string;

  beforeAll(async () => {
    policyPath = writePolicy(`
version: "1.0"
auth:
  public:
    - /healthz
  authenticated:
    - /v1/*
  token_env: SVALINN_API_TOKEN
rate_limits:
  max: 0
`);
    proc = spawnGateway(PORT, policyPath);
    await waitFor(`${BASE}/healthz`);
  });

  afterAll(() => {
    try { proc.kill("SIGTERM"); } catch { /* gone */ }
    try { Deno.removeSync(policyPath); } catch { /* gone */ }
  });

  it("allows a public path with no token", async () => {
    const r = await fetch(`${BASE}/healthz`);
    await r.body?.cancel();
    // 200 or 503 (degraded) both mean the gate ALLOWED it through to routing.
    assertEquals(r.status !== 401 && r.status !== 403, true);
  });

  it("rejects an authenticated path with no token (401)", async () => {
    const r = await fetch(`${BASE}/v1/containers`);
    await r.body?.cancel();
    assertEquals(r.status, 401);
  });

  it("accepts an authenticated path with the right token", async () => {
    const r = await fetch(`${BASE}/v1/containers`, {
      headers: { authorization: `Bearer ${TOKEN}` },
    });
    await r.body?.cancel();
    assertEquals(r.status !== 401 && r.status !== 403, true);
  });

  it("rejects a wrong token (401)", async () => {
    const r = await fetch(`${BASE}/v1/containers`, {
      headers: { authorization: "Bearer wrong" },
    });
    await r.body?.cancel();
    assertEquals(r.status, 401);
  });

  it("DEFAULT-DENIES a path in neither list (403)", async () => {
    //  /verify exists as a route but is absent from this policy. The gate must
    //  refuse it rather than fall through to the handler.
    const r = await fetch(`${BASE}/verify`, {
      method: "POST",
      headers: { authorization: `Bearer ${TOKEN}` },
      body: "{}",
    });
    await r.body?.cancel();
    assertEquals(r.status, 403);
  });
});

// ---------------------------------------------------------------------------
describe("no policy file: behaviour is unchanged", suiteOpts, () => {
  const PORT = 18802;
  const BASE = `http://127.0.0.1:${PORT}`;
  let proc: Deno.ChildProcess;

  beforeAll(async () => {
    proc = spawnGateway(PORT); // no SVALINN_GATEKEEPER_CONFIG
    await waitFor(`${BASE}/healthz`);
  });

  afterAll(() => {
    try { proc.kill("SIGTERM"); } catch { /* gone */ }
  });

  it("serves an otherwise-gated path without any token", async () => {
    //  With no policy there is no default-deny: adopting the file is opt-in,
    //  so its absence must not change how svalinn already behaves.
    const r = await fetch(`${BASE}/v1/containers`);
    await r.body?.cancel();
    assertEquals(r.status !== 401 && r.status !== 403, true);
  });
});

// ---------------------------------------------------------------------------
describe("a broken policy is fatal", suiteOpts, () => {
  it("exits non-zero rather than guarding with rules it could not parse", async () => {
    const bad = writePolicy("auth:\n  public:\n    - /healthz\n  nonsense: {{\n");
    const proc = spawnGateway(18803, bad, true);
    const { code, stderr } = await proc.output();
    const text = new TextDecoder().decode(stderr);
    assertEquals(code, 1, `expected exit 1, got ${code}. stderr: ${text}`);
    Deno.removeSync(bad);
  });

  it("rejects an unknown top-level key", async () => {
    const bad = writePolicy(`version: "1.0"\nauth:\n  public: [/healthz]\nnot_a_key: 1\n`);
    const proc = spawnGateway(18804, bad, true);
    const { code, stderr } = await proc.output();
    const text = new TextDecoder().decode(stderr);
    assertEquals(code, 1, `expected exit 1, got ${code}`);
    assertEquals(text.includes("unknown top-level key"), true, text);
    Deno.removeSync(bad);
  });
});
