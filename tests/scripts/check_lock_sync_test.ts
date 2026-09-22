// SPDX-License-Identifier: MPL-2.0
//
// Behavioural tests for scripts/check-lock-sync.sh. Each test creates a small,
// isolated .github/workflows tree, so the assertions describe the validator's
// contract without depending on the repository's current action inventory.

const REPO_ROOT = new URL("../..", import.meta.url).pathname;
const CHECK_SCRIPT =
  new URL("../../scripts/check-lock-sync.sh", import.meta.url).pathname;
const GATE_WORKFLOW = `${REPO_ROOT}/.github/workflows/lock-sync-gate.yml`;
const decoder = new TextDecoder();

type Files = Record<string, string>;

interface CheckResult {
  code: number;
  output: string;
}

function assert(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(message);
}

function assertIncludes(text: string, expected: string): void {
  assert(
    text.includes(expected),
    `Expected output to include ${JSON.stringify(expected)}:\n${text}`,
  );
}

async function withFixture(
  files: Files,
  test: (root: string) => Promise<void>,
): Promise<void> {
  const root = await Deno.makeTempDir({ prefix: "svalinn-lock-sync-" });
  try {
    for (const [relativePath, contents] of Object.entries(files)) {
      const destination = `${root}/${relativePath}`;
      const parent = destination.slice(0, destination.lastIndexOf("/"));
      await Deno.mkdir(parent, { recursive: true });
      await Deno.writeTextFile(destination, contents);
    }
    await test(root);
  } finally {
    await Deno.remove(root, { recursive: true });
  }
}

async function runCheck(root: string): Promise<CheckResult> {
  const result = await new Deno.Command("bash", {
    args: [CHECK_SCRIPT],
    cwd: root,
    stdout: "piped",
    stderr: "piped",
  }).output();
  return {
    code: result.code,
    output: decoder.decode(result.stdout) + decoder.decode(result.stderr),
  };
}

function workflow(uses: string): string {
  return `name: fixture
on: push
jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
${uses}`;
}

Deno.test("check-lock-sync accepts normalized action and reusable-workflow references", async () => {
  await withFixture({
    ".github/workflows/ci.yaml": workflow(
      `      - uses: Acme/Checkout@v4 # trailing comments are ignored
      - uses: ./actions/local
      - uses: $/actions/local
  reuse:
    uses: Example/Reusable/.github/workflows/verify.yaml@Release-1
`,
    ),
    ".github/workflows/actions.lock": `workflows:
    '.github/workflows/ci.yaml':
        - 'acme/checkout@v4'
        - 'example/reusable@Release-1'
dependencies:
    'acme/checkout@v4':
        metadata: fixture
    'example/reusable@Release-1':
        metadata: fixture
    'unused/tool@v1':
        metadata: harmless
`,
  }, async (root) => {
    const result = await runCheck(root);
    assert(result.code === 0, result.output);
    assertIncludes(
      result.output,
      "actions.lock is in sync and transitively closed",
    );
    assertIncludes(
      result.output,
      "1 dependencies: record(s) are unreferenced - harmless",
    );
  });
});

Deno.test("check-lock-sync rejects a literal ref mismatch even when owner and repository casing differs", async () => {
  await withFixture({
    ".github/workflows/ci.yml": workflow(
      "      - uses: Owner/Action@Release-1\n",
    ),
    ".github/workflows/actions.lock": `workflows:
    '.github/workflows/ci.yml':
        - 'owner/action@release-1'
dependencies:
    'owner/action@release-1':
        metadata: fixture
`,
  }, async (root) => {
    const result = await runCheck(root);
    assert(result.code === 1, result.output);
    assertIncludes(result.output, "refs missing from the lockfile");
    assertIncludes(result.output, "Owner/Action@Release-1");
    assertIncludes(
      result.output,
      "stale lockfile entries, no uses: references them",
    );
    assertIncludes(result.output, "owner/action@release-1");
  });
});

Deno.test("check-lock-sync reports a workflow that has never been added to the lockfile", async () => {
  await withFixture({
    ".github/workflows/ci.yml": workflow(
      "      - uses: owner/action@deadbeef\n",
    ),
    ".github/workflows/actions.lock": `workflows:
dependencies:
    'owner/action@deadbeef':
        metadata: fixture
`,
  }, async (root) => {
    const result = await runCheck(root);
    assert(result.code === 1, result.output);
    assertIncludes(
      result.output,
      "not onboarded: no lockfile entry for this path",
    );
    assertIncludes(result.output, "owner/action@deadbeef");
  });
});

Deno.test("check-lock-sync rejects transitive lockfile edges with no dependency record", async () => {
  await withFixture({
    ".github/workflows/ci.yml": workflow(
      "      - uses: owner/root-action@v1\n",
    ),
    ".github/workflows/actions.lock": `workflows:
    '.github/workflows/ci.yml':
        - 'owner/root-action@v1'
dependencies:
    'owner/root-action@v1':
        uses:
            - 'owner/nested-action@v2'
`,
  }, async (root) => {
    const result = await runCheck(root);
    assert(result.code === 1, result.output);
    assertIncludes(result.output, "FAIL actions.lock: DANGLING EDGES");
    assertIncludes(result.output, "owner/nested-action@v2");
    assertIncludes(result.output, "dependencies:owner/root-action@v1");
  });
});

Deno.test("check-lock-sync rejects stale entries and entries for deleted workflow files", async () => {
  await withFixture({
    ".github/workflows/ci.yml": workflow(
      "      - run: echo no external actions\n",
    ),
    ".github/workflows/actions.lock": `workflows:
    '.github/workflows/ci.yml':
        - 'owner/stale-action@v1'
    '.github/workflows/deleted.yml':
        - 'owner/stale-action@v1'
dependencies:
    'owner/stale-action@v1':
        metadata: fixture
`,
  }, async (root) => {
    const result = await runCheck(root);
    assert(result.code === 1, result.output);
    assertIncludes(
      result.output,
      "stale lockfile entries, no uses: references them",
    );
    assertIncludes(result.output, ".github/workflows/deleted.yml");
    assertIncludes(
      result.output,
      "lockfile entry for a workflow file that does not exist",
    );
  });
});

Deno.test("check-lock-sync fails clearly when its required lockfile is absent", async () => {
  await withFixture({
    ".github/workflows/ci.yml": workflow("      - uses: owner/action@v1\n"),
  }, async (root) => {
    const result = await runCheck(root);
    assert(result.code === 1, result.output);
    assertIncludes(
      result.output,
      "FATAL: no lockfile at .github/workflows/actions.lock",
    );
  });
});

Deno.test("lock-sync gate has no external uses or paths filter that could disable the check", async () => {
  const lines = (await Deno.readTextFile(GATE_WORKFLOW))
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line !== "" && !line.startsWith("#"));

  assert(
    lines.includes("pull_request:"),
    "The gate must run for pull requests",
  );
  assert(
    lines.includes("branches: [main]"),
    "The gate must run for pushes to main",
  );
  assert(
    !lines.some((line) => /(?:^|\s)uses:/.test(line)),
    "The gate must not use an external action",
  );
  assert(
    !lines.some((line) => /^paths:/.test(line)),
    "The gate must not have a paths filter",
  );
  assert(
    lines.includes("./scripts/check-lock-sync.sh"),
    "The gate must invoke the lock-sync validator",
  );
});
