#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CHECKER="$REPO_ROOT/scripts/check-lock-sync.sh"
TEST_ROOT="$(mktemp -d)"
trap 'rm -rf "$TEST_ROOT"' EXIT

total=0
passed=0
failed=0
fixture=""
output=""
status=0

new_fixture() {
  fixture="$TEST_ROOT/$1"
  mkdir -p "$fixture"
}

run_checker() {
  set +e
  output="$("$CHECKER" "$fixture" 2>&1)"
  status=$?
  set -e
}

run_repository_checker() {
  set +e
  output="$("$CHECKER" 2>&1)"
  status=$?
  set -e
}

expect_status() {
  local expected="$1"
  if [[ "$status" -ne "$expected" ]]; then
    printf 'expected exit %s, got %s\n%s\n' "$expected" "$status" "$output" >&2
    return 1
  fi
}

expect_failure() {
  if [[ "$status" -eq 0 ]]; then
    printf 'expected a non-zero exit, got 0\n%s\n' "$output" >&2
    return 1
  fi
}

expect_output() {
  local expected="$1"
  if [[ "$output" != *"$expected"* ]]; then
    printf 'expected output to contain: %s\nactual output:\n%s\n' "$expected" "$output" >&2
    return 1
  fi
}

run_test() {
  local name="$1"
  shift
  total=$((total + 1))
  if "$@"; then
    passed=$((passed + 1))
    printf 'ok %d - %s\n' "$total" "$name"
  else
    failed=$((failed + 1))
    printf 'not ok %d - %s\n' "$total" "$name"
  fi
}

test_accepts_synchronised_workflow() {
  new_fixture synchronised
  cat >"$fixture/ci.yml" <<'YAML'
name: CI
jobs:
  build:
    uses: Example/Reusable/.github/workflows/build.yml@v2
  lint:
    steps:
      - uses: Actions/Checkout/sub-action@v4 # a trailing comment
      - uses: ./local-action
      - uses: $/already-migrated-local-action
YAML
  cat >"$fixture/actions.lock" <<'YAML'
version: 'v0.0.2'
workflows:
    '.github/workflows/ci.yml':
        - 'actions/checkout@v4'
        - 'example/reusable@v2'
dependencies:
    'actions/checkout@v4':
        ref: 'v4'
    'example/reusable@v2':
        ref: 'v2'
YAML

  run_checker
  expect_status 0 &&
    expect_output 'actions.lock is in sync and transitively closed' &&
    expect_output '0 dangling edges'
}

test_accepts_empty_yaml_workflow() {
  new_fixture empty-workflow
  cat >"$fixture/maintenance.yaml" <<'YAML'
name: Maintenance
jobs:
  report:
    steps:
      - run: echo done
YAML
  cat >"$fixture/actions.lock" <<'YAML'
version: 'v0.0.2'
workflows:
    '.github/workflows/maintenance.yaml': []
dependencies:
YAML

  run_checker
  expect_status 0
}

test_rejects_missing_lockfile() {
  new_fixture missing-lockfile
  printf '%s\n' 'name: CI' >"$fixture/ci.yml"

  run_checker
  expect_status 1 && expect_output 'FATAL: no lockfile'
}

test_rejects_directory_without_workflows() {
  new_fixture missing-workflows
  cat >"$fixture/actions.lock" <<'YAML'
version: 'v0.0.2'
workflows:
dependencies:
YAML

  run_checker
  expect_status 1 &&
    expect_output 'FATAL: no workflow files'
}

test_rejects_unonboarded_workflow() {
  new_fixture unonboarded
  cat >"$fixture/ci.yml" <<'YAML'
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
YAML
  cat >"$fixture/actions.lock" <<'YAML'
version: 'v0.0.2'
workflows:
dependencies:
    'actions/checkout@v4':
        ref: 'v4'
YAML

  run_checker
  expect_status 1 &&
    expect_output 'not onboarded: no lockfile entry for this path' &&
    expect_output 'unlocked refs: actions/checkout@v4'
}

test_rejects_ref_missing_from_existing_workflow_entry() {
  new_fixture missing-ref
  cat >"$fixture/ci.yml" <<'YAML'
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
YAML
  cat >"$fixture/actions.lock" <<'YAML'
version: 'v0.0.2'
workflows:
    '.github/workflows/ci.yml': []
dependencies:
    'actions/checkout@v4':
        ref: 'v4'
YAML

  run_checker
  expect_status 1 &&
    expect_output 'refs missing from the lockfile: actions/checkout@v4'
}

test_rejects_stale_workflow_lock_entry() {
  new_fixture stale-entry
  cat >"$fixture/ci.yml" <<'YAML'
jobs:
  build:
    steps:
      - run: echo done
YAML
  cat >"$fixture/actions.lock" <<'YAML'
version: 'v0.0.2'
workflows:
    '.github/workflows/ci.yml':
        - 'actions/checkout@v4'
dependencies:
    'actions/checkout@v4':
        ref: 'v4'
YAML

  run_checker
  expect_status 1 &&
    expect_output 'stale lockfile entries, no uses: references them: actions/checkout@v4'
}

test_rejects_lock_entry_for_deleted_workflow() {
  new_fixture deleted-workflow
  printf '%s\n' 'name: CI' >"$fixture/ci.yml"
  cat >"$fixture/actions.lock" <<'YAML'
version: 'v0.0.2'
workflows:
    '.github/workflows/ci.yml': []
    '.github/workflows/deleted.yml': []
dependencies:
YAML

  run_checker
  expect_status 1 &&
    expect_output 'FAIL .github/workflows/deleted.yml' &&
    expect_output 'lockfile entry for a workflow file that does not exist'
}

test_treats_refs_as_case_sensitive_strings() {
  new_fixture literal-ref
  cat >"$fixture/ci.yml" <<'YAML'
jobs:
  build:
    steps:
      - uses: vendor/action@V1
YAML
  cat >"$fixture/actions.lock" <<'YAML'
version: 'v0.0.2'
workflows:
    '.github/workflows/ci.yml':
        - 'vendor/action@v1'
dependencies:
    'vendor/action@V1':
        ref: 'V1'
    'vendor/action@v1':
        ref: 'v1'
YAML

  run_checker
  expect_status 1 &&
    expect_output 'refs missing from the lockfile: vendor/action@V1' &&
    expect_output 'stale lockfile entries, no uses: references them: vendor/action@v1'
}

test_matches_action_owners_and_repositories_case_insensitively() {
  new_fixture owner-repository-case
  cat >"$fixture/ci.yml" <<'YAML'
jobs:
  build:
    steps:
      - uses: Vendor/Action@v1
YAML
  cat >"$fixture/actions.lock" <<'YAML'
version: 'v0.0.2'
workflows:
    '.github/workflows/ci.yml':
        - 'vendor/action@v1'
dependencies:
    'vendor/action@v1':
        ref: 'v1'
YAML

  run_checker
  expect_status 0 && expect_output '0 dangling edges'
}

test_normalises_quoted_reusable_workflow_refs() {
  new_fixture quoted-reusable-workflow
  cat >"$fixture/ci.yml" <<'YAML'
jobs:
  reusable:
    uses: "Example/Reusable/.github/workflows/build.yml@v2"
YAML
  cat >"$fixture/actions.lock" <<'YAML'
version: 'v0.0.2'
workflows:
    '.github/workflows/ci.yml':
        - 'example/reusable@v2'
dependencies:
    'example/reusable@v2':
        ref: 'v2'
YAML

  run_checker
  expect_status 0 && expect_output '0 dangling edges'
}

test_rejects_dangling_workflow_dependency() {
  new_fixture dangling-workflow-dependency
  cat >"$fixture/ci.yml" <<'YAML'
jobs:
  build:
    steps:
      - uses: vendor/action@v1
YAML
  cat >"$fixture/actions.lock" <<'YAML'
version: 'v0.0.2'
workflows:
    '.github/workflows/ci.yml':
        - 'vendor/action@v1'
dependencies:
YAML

  run_checker
  expect_status 1 &&
    expect_output 'FAIL actions.lock: DANGLING EDGES' &&
    expect_output 'vendor/action@v1' &&
    expect_output 'named by: .github/workflows/ci.yml'
}

test_rejects_dangling_nested_dependency() {
  new_fixture dangling-nested-dependency
  cat >"$fixture/ci.yml" <<'YAML'
jobs:
  build:
    steps:
      - uses: vendor/root@v1
YAML
  cat >"$fixture/actions.lock" <<'YAML'
version: 'v0.0.2'
workflows:
    '.github/workflows/ci.yml':
        - 'vendor/root@v1'
dependencies:
    'vendor/root@v1':
        ref: 'v1'
        uses:
            - 'vendor/leaf@abc123'
YAML

  run_checker
  expect_status 1 &&
    expect_output 'vendor/leaf@abc123' &&
    expect_output 'named by: dependencies:vendor/root@v1'
}

test_accepts_transitively_closed_dependencies() {
  new_fixture closed-dependencies
  cat >"$fixture/ci.yml" <<'YAML'
jobs:
  build:
    steps:
      - uses: vendor/root@v1
YAML
  cat >"$fixture/actions.lock" <<'YAML'
version: 'v0.0.2'
workflows:
    '.github/workflows/ci.yml':
        - 'vendor/root@v1'
dependencies:
    'vendor/root@v1':
        ref: 'v1'
        uses:
            - 'vendor/leaf@abc123'
    'vendor/leaf@abc123':
        ref: 'abc123'
YAML

  run_checker
  expect_status 0 && expect_output '0 dangling edges'
}

test_allows_unreferenced_dependency_record() {
  new_fixture unreferenced-dependency
  printf '%s\n' 'name: CI' >"$fixture/ci.yml"
  cat >"$fixture/actions.lock" <<'YAML'
version: 'v0.0.2'
workflows:
    '.github/workflows/ci.yml': []
dependencies:
    'vendor/unused@v1':
        ref: 'v1'
YAML

  run_checker
  expect_status 0 &&
    expect_output 'note: 1 dependencies: record(s) are unreferenced'
}

test_handles_at_sign_inside_ref() {
  new_fixture at-sign-ref
  cat >"$fixture/ci.yml" <<'YAML'
jobs:
  build:
    steps:
      - uses: vendor/action@release@2026
YAML
  cat >"$fixture/actions.lock" <<'YAML'
version: 'v0.0.2'
workflows:
    '.github/workflows/ci.yml':
        - 'vendor/action@release@2026'
dependencies:
    'vendor/action@release@2026':
        ref: 'release@2026'
YAML

  run_checker
  expect_status 0
}

test_gate_configuration_runs_without_external_actions() {
  local gate="$REPO_ROOT/.github/workflows/lock-sync-gate.yml"

  test -x "$CHECKER" &&
    grep -Eq '^on:[[:space:]]*$' "$gate" &&
    grep -Eq '^  pull_request:[[:space:]]*$' "$gate" &&
    grep -Eq '^  push:[[:space:]]*$' "$gate" &&
    grep -Eq '^    branches: \[main\][[:space:]]*$' "$gate" &&
    ! grep -Eq '^[[:space:]]+paths:' "$gate" &&
    awk '/^[[:space:]]*(-[[:space:]]*)?uses:[[:space:]]*/ { found = 1 } END { exit found }' "$gate" &&
    grep -Fq './scripts/check-lock-sync.sh' "$gate"
}

test_accepts_the_prs_workflows_and_lockfile() {
  run_repository_checker
  expect_status 0 &&
    expect_output 'actions.lock is in sync and transitively closed' &&
    expect_output '0 dangling edges'
}

run_test 'accepts a synchronised workflow and normalises action subpaths' test_accepts_synchronised_workflow
run_test 'accepts an empty .yaml workflow entry' test_accepts_empty_yaml_workflow
run_test 'rejects a missing lockfile' test_rejects_missing_lockfile
run_test 'rejects a directory without workflow files' test_rejects_directory_without_workflows
run_test 'rejects a workflow absent from the lockfile' test_rejects_unonboarded_workflow
run_test 'rejects a missing ref in an existing workflow entry' test_rejects_ref_missing_from_existing_workflow_entry
run_test 'rejects a stale workflow lock entry' test_rejects_stale_workflow_lock_entry
run_test 'rejects a lock entry for a deleted workflow' test_rejects_lock_entry_for_deleted_workflow
run_test 'treats refs as case-sensitive' test_treats_refs_as_case_sensitive_strings
run_test 'matches action owners and repositories case-insensitively' test_matches_action_owners_and_repositories_case_insensitively
run_test 'normalises quoted reusable-workflow refs' test_normalises_quoted_reusable_workflow_refs
run_test 'rejects a dangling workflow dependency' test_rejects_dangling_workflow_dependency
run_test 'rejects a dangling nested dependency' test_rejects_dangling_nested_dependency
run_test 'accepts transitively closed dependencies' test_accepts_transitively_closed_dependencies
run_test 'allows an unreferenced dependency record with a note' test_allows_unreferenced_dependency_record
run_test 'handles an at-sign inside a ref' test_handles_at_sign_inside_ref
run_test 'keeps the gate triggerable and free of external actions' test_gate_configuration_runs_without_external_actions
run_test "accepts this pull request's workflows and lockfile" test_accepts_the_prs_workflows_and_lockfile

printf '1..%d\n' "$total"
printf '# %d passed, %d failed\n' "$passed" "$failed"
[[ "$failed" -eq 0 ]]
