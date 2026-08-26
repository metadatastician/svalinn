// SPDX-License-Identifier: MPL-2.0
// Copyright (c) Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>
type GateRequest = {
  bundlePath?: string;
  trustStorePath?: string;
  policyPath?: string;
  bundle?: unknown;
  trustStore?: unknown;
  policy?: unknown;
  imageDigest: string;
};

type RunRequest = GateRequest & {
  imageName?: string;
  profile?: string;
  removeOnExit?: boolean;
  detach?: boolean;
  vordrArgs?: string[];
  runCommand?: string[];
  useCommandSeparator?: boolean;
};

type JobState = "queued" | "starting" | "running" | "failed";

type JobRecord = {
  state: JobState;
  imageName?: string;
  profile?: string;
  removeOnExit?: boolean;
  lastError?: string;
  errorId?: string;
  errorCode?: number;
  detach?: boolean;
  vordrArgs?: string[];
  runCommand?: string[];
  useCommandSeparator?: boolean;
  policyHash?: string;
};

const jobs = new Map<string, JobRecord>();
const queue: string[] = [];
const statePath = Deno.env.get("SVALINN_STATE_PATH") ?? "tools/mvp/state.json";
const gateTimeoutMs = Number(Deno.env.get("SVALINN_GATE_TIMEOUT_MS") ?? "10000");
const vordrTimeoutMs = Number(Deno.env.get("SVALINN_VORDR_TIMEOUT_MS") ?? "30000");
const auditPath = Deno.env.get("SVALINN_AUDIT_PATH") ?? "tools/mvp/audit.log";
const containersFallbackPath = Deno.env.get("SVALINN_CONTAINERS_FALLBACK") ??
  "tools/mvp/containers.json";
const imagesFallbackPath = Deno.env.get("SVALINN_IMAGES_FALLBACK") ??
  "tools/mvp/images.json";
const preflight = {
  python3: false,
  openssl: false,
  vordr: false,
};

function jsonResponse(status: number, payload: unknown) {
  return new Response(JSON.stringify(payload, null, 2), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function logEvent(level: "info" | "warn" | "error", message: string, fields?: Record<string, unknown>) {
  const payload = {
    ts: new Date().toISOString(),
    level,
    message,
    ...fields,
  };
  console.log(JSON.stringify(payload));
}

function errorResponse(
  code: number,
  id: string,
  message: string,
  details?: Record<string, unknown>,
  suggestions?: string[],
) {
  let status = 500;
  if (id === "ERR_USAGE") {
    status = 400;
  } else if (id === "ERR_POLICY_DENIED") {
    status = 403;
  } else if (id === "ERR_CONTAINER_NOT_FOUND") {
    status = 404;
  }
  return jsonResponse(status, {
    error: {
      code,
      id,
      message,
      details,
      suggestions,
    },
  });
}

function validateDigest(value: string) {
  return value.startsWith("sha256:") && value.length == 71;
}

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((item) => typeof item === "string");
}

function validateGatePayload(payload: GateRequest): string | null {
  if (!payload.imageDigest || typeof payload.imageDigest !== "string") {
    return "imageDigest is required";
  }
  if (!validateDigest(payload.imageDigest)) {
    return "imageDigest must be sha256:<64-hex>";
  }
  const hasBundle = Boolean(payload.bundle || payload.bundlePath);
  const hasTrust = Boolean(payload.trustStore || payload.trustStorePath);
  const hasPolicy = Boolean(payload.policy || payload.policyPath);
  if (!hasBundle || !hasTrust || !hasPolicy) {
    return "bundlePath, trustStorePath, and policyPath are required";
  }
  if (payload.bundlePath && typeof payload.bundlePath !== "string") {
    return "bundlePath must be a string";
  }
  if (payload.trustStorePath && typeof payload.trustStorePath !== "string") {
    return "trustStorePath must be a string";
  }
  if (payload.policyPath && typeof payload.policyPath !== "string") {
    return "policyPath must be a string";
  }
  if (payload.bundle && typeof payload.bundle !== "object") {
    return "bundle must be an object";
  }
  if (payload.trustStore && typeof payload.trustStore !== "object") {
    return "trustStore must be an object";
  }
  if (payload.policy && typeof payload.policy !== "object") {
    return "policy must be an object";
  }
  if (payload.bundle) {
    const bundle = payload.bundle as Record<string, unknown>;
    if (bundle.mediaType !== "application/vnd.verified-container.bundle+json") {
      return "bundle.mediaType must be application/vnd.verified-container.bundle+json";
    }
    if (bundle.version !== "0.1.0") {
      return "bundle.version must be 0.1.0";
    }
    if (!Array.isArray(bundle.attestations)) {
      return "bundle.attestations must be an array";
    }
    if (!Array.isArray(bundle.logEntries)) {
      return "bundle.logEntries must be an array";
    }
  }
  if (payload.trustStore) {
    const trustStore = payload.trustStore as Record<string, unknown>;
    if (typeof trustStore.version !== "number") {
      return "trustStore.version must be a number";
    }
    if (typeof trustStore.keys !== "object" || trustStore.keys === null) {
      return "trustStore.keys must be an object";
    }
    if (typeof trustStore.logs !== "object" || trustStore.logs === null) {
      return "trustStore.logs must be an object";
    }
  }
  if (payload.policy) {
    const policy = payload.policy as Record<string, unknown>;
    if (!Array.isArray(policy.requiredPredicates)) {
      return "policy.requiredPredicates must be an array";
    }
    if (!Array.isArray(policy.allowedSigners)) {
      return "policy.allowedSigners must be an array";
    }
    if (typeof policy.logQuorum !== "number") {
      return "policy.logQuorum must be a number";
    }
  }
  return null;
}

function validateRunPayload(payload: RunRequest): string | null {
  const baseError = validateGatePayload(payload);
  if (baseError) {
    return baseError;
  }
  if (!payload.imageName || typeof payload.imageName !== "string") {
    return "imageName is required";
  }
  if (payload.runCommand && !isStringArray(payload.runCommand)) {
    return "runCommand must be an array of strings";
  }
  if (payload.vordrArgs && !isStringArray(payload.vordrArgs)) {
    return "vordrArgs must be an array of strings";
  }
  return null;
}

async function materializeJson(value: unknown): Promise<string> {
  const path = await Deno.makeTempFile({ prefix: "svalinn-mvp-" });
  await Deno.writeTextFile(path, JSON.stringify(value, null, 2));
  return path;
}

async function runVordrJson(args: string[]): Promise<unknown> {
  const cmd = new Deno.Command("vordr", {
    args,
    stdout: "piped",
    stderr: "piped",
    signal: AbortSignal.timeout(vordrTimeoutMs),
  });
  const output = await cmd.output();
  if (!output.success) {
    const message = new TextDecoder().decode(output.stderr).trim();
    throw new Error(message || "vordr command failed");
  }
  const stdout = new TextDecoder().decode(output.stdout).trim();
  if (!stdout) {
    return [];
  }
  return JSON.parse(stdout);
}

function deriveContainerField(obj: Record<string, unknown>, keys: Array<string>): string {
  for (const key of keys) {
    const value = obj[key];
    if (typeof value === "string" && value.length > 0) {
      return value;
    }
  }
  return "";
}

function normalizeContainers(payload: unknown): Array<Record<string, string>> {
  if (!Array.isArray(payload)) {
    return [];
  }
  return payload
    .filter(item => typeof item === "object" && item !== null)
    .map(item => {
      const record = item as Record<string, unknown>;
      const id = deriveContainerField(record, ["id", "container_id", "containerId", "name"]);
      const name = deriveContainerField(record, ["name", "container_name", "containerName", "id"]);
      const image = deriveContainerField(record, ["image", "imageName", "image_name"]);
      const status = deriveContainerField(record, ["status", "state"]);
      const policy = deriveContainerField(record, ["policyVerdict", "policy", "gate"]);
      const createdAt = deriveContainerField(record, ["createdAt", "created_at", "created"]);
      return {
        id,
        name,
        image,
        status,
        policyVerdict: policy || "unknown",
        createdAt,
      };
    })
    .filter(container => container.id.length > 0);
}

async function loadContainersFallback(): Promise<Array<Record<string, string>>> {
  try {
    const content = await Deno.readTextFile(containersFallbackPath);
    const payload = JSON.parse(content);
    if (Array.isArray(payload)) {
      return payload as Array<Record<string, string>>;
    }
    if (payload && typeof payload === "object" && Array.isArray(payload.containers)) {
      return payload.containers as Array<Record<string, string>>;
    }
    return [];
  } catch {
    return [];
  }
}

function deriveImageField(obj: Record<string, unknown>, keys: Array<string>): string {
  for (const key of keys) {
    const value = obj[key];
    if (typeof value === "string" && value.length > 0) {
      return value;
    }
  }
  return "";
}

function normalizeImages(payload: unknown): Array<Record<string, unknown>> {
  if (!Array.isArray(payload)) {
    return [];
  }
  return payload
    .filter(item => typeof item === "object" && item !== null)
    .map(item => {
      const record = item as Record<string, unknown>;
      const name = deriveImageField(record, ["name", "repository", "image"]);
      const tag = deriveImageField(record, ["tag", "version"]);
      const digest = deriveImageField(record, ["digest", "id"]);
      const verified = record["verified"] === true;
      return {
        name,
        tag,
        digest,
        verified,
      };
    })
    .filter(image => typeof image.name === "string" && image.name.length > 0);
}

async function loadImagesFallback(): Promise<Array<Record<string, unknown>>> {
  try {
    const content = await Deno.readTextFile(imagesFallbackPath);
    const payload = JSON.parse(content);
    if (Array.isArray(payload)) {
      return payload as Array<Record<string, unknown>>;
    }
    if (payload && typeof payload === "object" && Array.isArray(payload.images)) {
      return payload.images as Array<Record<string, unknown>>;
    }
    return [];
  } catch {
    return [];
  }
}

async function sha256Hex(input: string): Promise<string> {
  const data = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest("SHA-256", data);
  const bytes = new Uint8Array(digest);
  return Array.from(bytes)
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

async function runGate(request: GateRequest) {
  const tempFiles: string[] = [];
  const bundlePath = request.bundle
    ? await materializeJson(request.bundle)
    : request.bundlePath;
  const trustStorePath = request.trustStore
    ? await materializeJson(request.trustStore)
    : request.trustStorePath;
  const policyPath = request.policy
    ? await materializeJson(request.policy)
    : request.policyPath;

  if (request.bundle) {
    tempFiles.push(bundlePath as string);
  }
  if (request.trustStore) {
    tempFiles.push(trustStorePath as string);
  }
  if (request.policy) {
    tempFiles.push(policyPath as string);
  }

  if (!bundlePath || !trustStorePath || !policyPath) {
    throw new Error("bundlePath, trustStorePath, and policyPath are required");
  }

  // svalinn-gate is the Rust port of the former svalinn_gate.py — build once with
  // `cargo build --release --manifest-path tools/mvp/svalinn-gate/Cargo.toml`.
  const cmd = new Deno.Command("tools/mvp/svalinn-gate/target/release/svalinn-gate", {
    args: [
      "verify",
      "--bundle",
      bundlePath,
      "--trust-store",
      trustStorePath,
      "--policy",
      policyPath,
      "--image-digest",
      request.imageDigest,
      "--json",
    ],
    stdout: "piped",
    stderr: "piped",
    signal: AbortSignal.timeout(gateTimeoutMs),
  });
  try {
    const output = await cmd.output();
    if (!output.success) {
      const stdout = new TextDecoder().decode(output.stdout).trim();
      const stderr = new TextDecoder().decode(output.stderr).trim();
      if (stdout) {
        try {
          const payload = JSON.parse(stdout);
          if (payload?.error?.message) {
            const error = new Error(payload.error.message);
            (error as Error & { gateError?: typeof payload.error }).gateError = payload.error;
            throw error;
          }
        } catch {
          // fall through to stderr
        }
      }
      throw new Error(stderr || "verification failed");
    }
    const stdout = new TextDecoder().decode(output.stdout).trim();
    if (!stdout) {
      return { report: {} };
    }
    const payload = JSON.parse(stdout);
    return payload.report ? { report: payload.report } : { report: {} };
  } finally {
    for (const path of tempFiles) {
      try {
        await Deno.remove(path);
      } catch {
        // ignore cleanup errors
      }
    }
  }
}

async function loadState() {
  try {
    const content = await Deno.readTextFile(statePath);
    const data = JSON.parse(content);
    if (data && typeof data === "object" && Array.isArray(data.jobs)) {
      for (const entry of data.jobs) {
        if (entry && typeof entry.id === "string" && entry.state) {
          jobs.set(entry.id, entry);
        }
      }
    }
  } catch {
    // ignore missing or invalid state
  }
}

async function saveState() {
  const snapshot = {
    updatedAt: new Date().toISOString(),
    jobs: Array.from(jobs.entries()).map(([id, job]) => ({ id, ...job })),
  };
  await Deno.writeTextFile(statePath, JSON.stringify(snapshot, null, 2));
}

async function appendAudit(event: Record<string, unknown>) {
  const payload = JSON.stringify({ ts: new Date().toISOString(), ...event }) + "\n";
  await Deno.writeTextFile(auditPath, payload, { append: true });
}

function enqueueJob(
  imageName?: string,
  profile?: string,
  removeOnExit?: boolean,
  detach?: boolean,
  vordrArgs?: string[],
  runCommand?: string[],
  useCommandSeparator?: boolean,
  policyHash?: string,
): string {
  const id = crypto.randomUUID();
  jobs.set(id, {
    state: "queued",
    imageName,
    profile,
    removeOnExit,
    detach,
    vordrArgs,
    runCommand,
    useCommandSeparator,
    policyHash,
  });
  queue.push(id);
  saveState();
  return id;
}

async function tickScheduler() {
  if (queue.length === 0) {
    return;
  }
  const jobId = queue.shift();
  if (!jobId) {
    return;
  }
  const job = jobs.get(jobId);
  if (!job) {
    return;
  }
  jobs.set(jobId, { ...job, state: "starting" });
  await saveState();

  if (!job.imageName) {
    jobs.set(jobId, { ...job, state: "failed", lastError: "imageName required" });
    await saveState();
    return;
  }

  const profile = job.profile ?? "strict";
  const args = ["run", "--profile", profile, "--name", jobId];
  if (job.detach) {
    args.push("--detach");
  }
  if (job.removeOnExit) {
    args.push("--remove-on-exit");
  }
  if (job.vordrArgs && job.vordrArgs.length > 0) {
    args.push(...job.vordrArgs);
  }
  args.push(job.imageName);
  if (job.useCommandSeparator ?? (job.runCommand && job.runCommand.length > 0)) {
    args.push("--");
  }
  if (job.runCommand && job.runCommand.length > 0) {
    args.push(...job.runCommand);
  }
  const cmd = new Deno.Command("vordr", {
    args,
    stdout: "piped",
    stderr: "piped",
    signal: AbortSignal.timeout(vordrTimeoutMs),
  });
  try {
    const output = await cmd.output();
    if (!output.success) {
      const message = new TextDecoder().decode(output.stderr).trim();
      jobs.set(jobId, {
        ...job,
        state: "failed",
        lastError: message || "vordr run failed",
        errorId: "ERR_RUNTIME_EXEC",
        errorCode: 12,
      });
      await saveState();
      return;
    }
    jobs.set(jobId, { ...job, state: "running" });
    await saveState();
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    const isNotFound = err instanceof Deno.errors.NotFound;
    jobs.set(jobId, {
      ...job,
      state: "failed",
      lastError: message,
      errorId: isNotFound ? "ERR_RUNTIME_NOT_FOUND" : "ERR_RUNTIME_EXEC",
      errorCode: isNotFound ? 11 : 12,
    });
    await saveState();
  }
}

async function checkCommand(command: string): Promise<boolean> {
  try {
    const cmd = new Deno.Command("which", { args: [command], stdout: "null", stderr: "null" });
    const output = await cmd.output();
    return output.success;
  } catch {
    return false;
  }
}

async function strictHealth() {
  const results: Record<string, boolean | string> = {};
  try {
    const cmd = new Deno.Command("python3", { args: ["--version"], stdout: "null", stderr: "null" });
    results.python3 = (await cmd.output()).success;
  } catch (err) {
    results.python3 = String(err);
  }
  try {
    const cmd = new Deno.Command("openssl", { args: ["version"], stdout: "null", stderr: "null" });
    results.openssl = (await cmd.output()).success;
  } catch (err) {
    results.openssl = String(err);
  }
  try {
    const cmd = new Deno.Command("vordr", { args: ["version"], stdout: "null", stderr: "null" });
    results.vordr = (await cmd.output()).success;
  } catch (err) {
    results.vordr = String(err);
  }
  try {
    await Deno.writeTextFile(statePath, "", { append: true });
    results.stateWritable = true;
  } catch (err) {
    results.stateWritable = String(err);
  }
  try {
    await Deno.writeTextFile(auditPath, "", { append: true });
    results.auditWritable = true;
  } catch (err) {
    results.auditWritable = String(err);
  }
  return results;
}

async function initPreflight() {
  preflight.python3 = await checkCommand("python3");
  preflight.openssl = await checkCommand("openssl");
  preflight.vordr = await checkCommand("vordr");
  logEvent("info", "preflight", preflight);
}

await loadState();
import { parse as parseYaml } from "@std/yaml";

// ---------------------------------------------------------------------------
// .gatekeeper.yaml — the bundle's policy file for svalinn
//
// ABSENT IS THE NORMAL CASE. No .gatekeeper.yaml is committed to this repo, so
// with no file the gateway behaves exactly as it always has: env-only, every
// route open. Adopting the file is opt-in and additive.
//
// PRESENT-BUT-WRONG IS FATAL. A malformed or unrecognised policy exits(1)
// rather than starting. svalinn is the edge shield; running it on a policy we
// could not fully parse would mean guarding with rules nobody verified.
// ---------------------------------------------------------------------------

type GateConfig = {
  publicPaths: string[];
  authenticatedPaths: string[];
  tokenEnv: string;
  rateWindowMs: number;
  rateMax: number;
};

const GATE_TABLES = ["version", "auth", "rate_limits"];

function fail(message: string): never {
  console.error(JSON.stringify({
    level: "FATAL",
    message,
    service: "svalinn",
  }));
  Deno.exit(1);
}

function asStringArray(value: unknown, where: string): string[] {
  if (value === undefined) return [];
  if (!Array.isArray(value) || value.some((v) => typeof v !== "string")) {
    fail(`svalinn: ${where} must be a list of strings`);
  }
  return value as string[];
}

/**
 * Load .gatekeeper.yaml, or null when there is none.
 *
 * Path comes from SVALINN_GATEKEEPER_CONFIG, else ".gatekeeper.yaml" in cwd.
 * Returns null ONLY when no file is present. Every other problem exits(1).
 */
export function loadGateConfig(): GateConfig | null {
  const explicit = Deno.env.get("SVALINN_GATEKEEPER_CONFIG");
  const path = explicit && explicit.trim().length > 0
    ? explicit
    : ".gatekeeper.yaml";

  let text: string;
  try {
    text = Deno.readTextFileSync(path);
  } catch (err) {
    // An EXPLICITLY named file that cannot be read is an error; a missing
    // default file just means "not adopted here".
    if (explicit && explicit.trim().length > 0) {
      fail(`svalinn: cannot read ${path}: ${(err as Error).message}`);
    }
    return null;
  }

  let doc: Record<string, unknown>;
  try {
    doc = (parseYaml(text) ?? {}) as Record<string, unknown>;
  } catch (err) {
    fail(`svalinn: ${path} is not valid YAML: ${(err as Error).message}`);
  }

  for (const key of Object.keys(doc)) {
    if (!GATE_TABLES.includes(key)) {
      fail(
        `svalinn: ${path} has unknown top-level key "${key}". Known: ${GATE_TABLES.join(", ")}`,
      );
    }
  }

  const auth = (doc.auth ?? {}) as Record<string, unknown>;
  const limits = (doc.rate_limits ?? {}) as Record<string, unknown>;

  const publicPaths = asStringArray(auth.public, `${path} auth.public`);
  const authenticatedPaths = asStringArray(
    auth.authenticated,
    `${path} auth.authenticated`,
  );
  if (publicPaths.length === 0 && authenticatedPaths.length === 0) {
    fail(
      `svalinn: ${path} lists no paths at all. With default-deny that would ` +
        `reject every request, which is never what a policy file means to say.`,
    );
  }

  const tokenEnv = typeof auth.token_env === "string" && auth.token_env.length > 0
    ? auth.token_env
    : "SVALINN_API_TOKEN";

  const rateWindowMs = typeof limits.window_ms === "number" ? limits.window_ms : 60_000;
  const rateMax = typeof limits.max === "number" ? limits.max : 0;

  return { publicPaths, authenticatedPaths, tokenEnv, rateWindowMs, rateMax };
}

/** Glob match supporting a single trailing `*`, e.g. "/v1/*". */
function pathMatches(pattern: string, pathname: string): boolean {
  if (pattern.endsWith("/*")) return pathname.startsWith(pattern.slice(0, -1));
  if (pattern.endsWith("*")) return pathname.startsWith(pattern.slice(0, -1));
  return pattern === pathname;
}

const rateBuckets = new Map<string, { count: number; resetAt: number }>();

/** Fixed-window per-client limiter. Returns true when the caller is over. */
function rateLimited(key: string, windowMs: number, max: number): boolean {
  if (max <= 0) return false;
  const now = Date.now();
  const bucket = rateBuckets.get(key);
  if (!bucket || now >= bucket.resetAt) {
    rateBuckets.set(key, { count: 1, resetAt: now + windowMs });
    return false;
  }
  bucket.count += 1;
  return bucket.count > max;
}

/**
 * Apply the policy to a request. Returns a Response to send instead of
 * handling it, or null to continue.
 *
 * DEFAULT-DENY: a path matching neither list is refused. That is the whole
 * point of a gate -- an unlisted route is one nobody decided about, and
 * guessing "probably fine" is how edge shields leak.
 */
function applyGatePolicy(
  cfg: GateConfig | null,
  req: Request,
  url: URL,
  clientKey: string,
): Response | null {
  if (!cfg) return null;

  if (rateLimited(clientKey, cfg.rateWindowMs, cfg.rateMax)) {
    return jsonResponse(429, { error: "rate limit exceeded" });
  }

  if (cfg.publicPaths.some((p) => pathMatches(p, url.pathname))) return null;

  if (cfg.authenticatedPaths.some((p) => pathMatches(p, url.pathname))) {
    const expected = Deno.env.get(cfg.tokenEnv) ?? "";
    if (expected.length === 0) {
      // The policy demands auth on this route and no token is configured, so
      // the requirement cannot be enforced. Refuse rather than wave it through.
      return jsonResponse(503, {
        error: `authentication required but ${cfg.tokenEnv} is not set`,
      });
    }
    const header = req.headers.get("authorization") ?? "";
    if (header !== `Bearer ${expected}`) {
      return jsonResponse(401, { error: "unauthorized" });
    }
    return null;
  }

  return jsonResponse(403, { error: "path not permitted by gatekeeper policy" });
}

await initPreflight();

const gateConfig = loadGateConfig();
if (gateConfig) {
  logEvent("info", "gatekeeper policy loaded", {
    publicPaths: gateConfig.publicPaths.length,
    authenticatedPaths: gateConfig.authenticatedPaths.length,
    rateMax: gateConfig.rateMax,
  });
}

const listenPort = Number(Deno.env.get("SVALINN_PORT") ?? "8000");
const listenHost = Deno.env.get("SVALINN_HOST") ?? "0.0.0.0";
logEvent("info", "listening", { hostname: listenHost, port: listenPort });

Deno.serve({ port: listenPort, hostname: listenHost }, async (req, info) => {
  const url = new URL(req.url);

  //  Policy first: nothing below runs for a request the gate refuses.
  const clientKey =
    (info?.remoteAddr as Deno.NetAddr | undefined)?.hostname ?? "unknown";
  const refusal = applyGatePolicy(gateConfig, req, url, clientKey);
  if (refusal) return refusal;
  if (req.method === "GET" && (url.pathname === "/healthz" || url.pathname === "/health")) {
    const strict = url.searchParams.get("strict") === "1";
    if (strict) {
      const checks = await strictHealth();
      const ok = Object.values(checks).every((value) => value === true);
      return jsonResponse(ok ? 200 : 503, {
        status: ok ? "ok" : "degraded",
        checks,
      });
    }
    const ok = preflight.python3 && preflight.openssl && preflight.vordr;
    return jsonResponse(ok ? 200 : 503, {
      status: ok ? "ok" : "degraded",
      checks: preflight,
    });
  }

  if (req.method === "GET" && url.pathname === "/v1/containers") {
    try {
      const payload = await runVordrJson(["ps", "--json"]);
      const containers = normalizeContainers(payload);
      if (containers.length == 0) {
        const fallback = await loadContainersFallback();
        return jsonResponse(200, { containers: fallback });
      }
      return jsonResponse(200, { containers });
    } catch (err) {
      logEvent("error", "containers", { error: err instanceof Error ? err.message : String(err) });
      const fallback = await loadContainersFallback();
      return jsonResponse(200, { containers: fallback });
    }
  }

  if (req.method === "GET" && url.pathname.startsWith("/v1/containers/") && url.pathname.endsWith("/inspect")) {
    const parts = url.pathname.split("/");
    const id = parts.length >= 4 ? parts[3] : "";
    if (!id) {
      return errorResponse(2, "ERR_USAGE", "container id required");
    }
    try {
      const payload = await runVordrJson(["inspect", "--json", id]);
      return jsonResponse(200, { id, data: payload });
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return errorResponse(12, "ERR_RUNTIME_EXEC", message);
    }
  }

  if (req.method === "GET" && url.pathname === "/v1/images") {
    try {
      const payload = await runVordrJson(["image", "ls", "--json"]);
      const images = normalizeImages(payload);
      if (images.length == 0) {
        const fallback = await loadImagesFallback();
        return jsonResponse(200, { images: fallback });
      }
      return jsonResponse(200, { images });
    } catch (err) {
      logEvent("error", "images", { error: err instanceof Error ? err.message : String(err) });
      const fallback = await loadImagesFallback();
      return jsonResponse(200, { images: fallback });
    }
  }

  if (req.method === "POST" && url.pathname === "/verify") {
    try {
      const payload = (await req.json()) as GateRequest;
      const validationError = validateGatePayload(payload);
      if (validationError) {
        return errorResponse(2, "ERR_USAGE", validationError);
      }
      const policyJson = payload.policy ? JSON.stringify(payload.policy) : null;
      const policyHash = policyJson ? await sha256Hex(policyJson) : undefined;
      const result = await runGate(payload);
      logEvent("info", "verify", { policyHash, result });
      return jsonResponse(200, { status: "ok", report: result.report, policyHash });
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      const gateError = (err as Error & { gateError?: { id?: string; details?: Record<string, unknown> } })
        .gateError;
      if (message.includes("bundlePath")) {
        return errorResponse(2, "ERR_USAGE", message);
      }
      if (message.includes("openssl not found")) {
        return errorResponse(11, "ERR_RUNTIME_NOT_FOUND", message);
      }
      if (gateError?.id) {
        return errorResponse(51, gateError.id, message, gateError.details);
      }
      return errorResponse(51, "ERR_POLICY_DENIED", message);
    }
  }

  if (req.method === "POST" && url.pathname === "/run") {
    try {
      const payload = (await req.json()) as RunRequest;
      const validationError = validateRunPayload(payload);
      if (validationError) {
        return errorResponse(2, "ERR_USAGE", validationError);
      }
      if (payload.vordrArgs) {
        const hasRemove = payload.vordrArgs.includes("--rm") || payload.vordrArgs.includes("--remove-on-exit");
        if (payload.removeOnExit && hasRemove) {
          return errorResponse(2, "ERR_USAGE", "removeOnExit conflicts with vordrArgs remove flag");
        }
        if (payload.vordrArgs.includes("--name")) {
          return errorResponse(2, "ERR_USAGE", "vordrArgs must not include --name");
        }
      }
      const policyJson = payload.policy ? JSON.stringify(payload.policy) : null;
      const policyHash = policyJson ? await sha256Hex(policyJson) : undefined;
      const gateResult = await runGate(payload);
      const jobId = enqueueJob(
        payload.imageName,
        payload.profile,
        payload.removeOnExit,
        payload.detach,
        payload.vordrArgs,
        payload.runCommand,
        payload.useCommandSeparator,
        policyHash,
      );
      await tickScheduler();
      const job = jobs.get(jobId);
      if (job?.state === "failed") {
        return errorResponse(
          job.errorCode ?? 12,
          job.errorId ?? "ERR_RUNTIME_EXEC",
          job.lastError ?? "vordr run failed",
        );
      }
      await appendAudit({
        event: "run",
        jobId,
        imageName: payload.imageName,
        imageDigest: payload.imageDigest,
        policyHash,
        report: gateResult.report,
      });
      logEvent("info", "run", { jobId, policyHash, status: job?.state });
      return jsonResponse(202, { jobId, status: job?.state, policyHash });
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      const gateError = (err as Error & { gateError?: { id?: string; details?: Record<string, unknown> } })
        .gateError;
      if (message.includes("bundlePath")) {
        return errorResponse(2, "ERR_USAGE", message);
      }
      if (message.includes("openssl not found")) {
        return errorResponse(11, "ERR_RUNTIME_NOT_FOUND", message);
      }
      if (gateError?.id) {
        return errorResponse(51, gateError.id, message, gateError.details);
      }
      return errorResponse(51, "ERR_POLICY_DENIED", message);
    }
  }

  if (req.method === "GET" && url.pathname.startsWith("/status/")) {
    const jobId = url.pathname.split("/").pop() ?? "";
    const status = jobs.get(jobId);
    if (!status) {
      return errorResponse(71, "ERR_CONTAINER_NOT_FOUND", "unknown job id");
    }
    return jsonResponse(200, {
      jobId,
      status: status.state,
      error: status.lastError,
      policyHash: status.policyHash,
    });
  }

  return jsonResponse(404, { error: "not found" });
});
