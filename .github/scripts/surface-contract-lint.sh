#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
#
# Surface-contract gate for svalinn's OWN surface.
#
# Contract: exit 0 = pass, exit 1 = fail. It NEVER emits `::warning::` in place
# of a failure, and it has no `|| true` / `continue-on-error` escape hatch.
#
# Inputs (all optional; CI supplies them):
#   CHANGED_FILES_FILE  newline-delimited list of changed paths. If unset the
#                       list is derived from `origin/main...HEAD`.
#   PR_LABELS           comma-separated PR label names.
#   REPO_ROOT           repository root (default: $PWD).
set -euo pipefail

cd "${REPO_ROOT:-$PWD}"

# Declared surface. Compared as LITERAL path prefixes via ${var#"$prefix"} --
# never handed to grep, so a `*` here could never be mistaken for a regex.
SURFACE_PREFIXES=(
  "tools/mvp/svalinn-gate/src/"
  "src/gateway/"
  "src/policy/"
  "spec/schemas/"
)

# Failures MUST reach stdout. The workflow pipes this script through `tee` into
# the job summary, and `tee` copies stdout only -- a message written to stderr
# reaches the step console but leaves the summary panel showing a log with no
# FAIL line in it, i.e. a red job whose own report looks clean.
fail() {
  echo "::error::surface-contract: $*"
  echo "surface-contract: FAIL: $*"
  exit 1
}

# -- Positive control -------------------------------------------------------
# A declared surface path that has been renamed or removed silently disarms the
# detector. Refuse to run rather than report a pass we cannot justify.
for prefix in "${SURFACE_PREFIXES[@]}"; do
  [ -e "${prefix%/}" ] || fail "declared surface path is missing: ${prefix%/} -- update SURFACE_PREFIXES in $0"
done

# -- Resolve the changed-file list ------------------------------------------
if [ -n "${CHANGED_FILES_FILE:-}" ]; then
  [ -r "$CHANGED_FILES_FILE" ] || fail "CHANGED_FILES_FILE is not readable: $CHANGED_FILES_FILE"
  changed_raw=$(cat -- "$CHANGED_FILES_FILE")
else
  git rev-parse --verify --quiet origin/main >/dev/null \
    || fail "origin/main is not resolvable -- refusing to guess a diff base"
  changed_raw=$(git diff --name-only origin/main...HEAD)
fi

mapfile -t CHANGED < <(printf '%s\n' "$changed_raw" | sed '/^[[:space:]]*$/d')
CHANGED_COUNT=${#CHANGED[@]}

# -- Empty-operand guard ----------------------------------------------------
# An empty list makes every downstream test vacuously true. Assert non-zero
# BEFORE comparing anything against it.
[ "$CHANGED_COUNT" -gt 0 ] \
  || fail "the changed-file list is EMPTY -- refusing to report a pass from a vacuous input"

echo "surface-contract: scanned ${CHANGED_COUNT} changed file(s):"
printf '  %s\n' "${CHANGED[@]}"

# -- Detect declared-surface changes (literal prefix match) -----------------
SURFACE_HITS=()
for f in "${CHANGED[@]}"; do
  for prefix in "${SURFACE_PREFIXES[@]}"; do
    if [ "${f#"$prefix"}" != "$f" ]; then
      SURFACE_HITS+=("$f")
      break
    fi
  done
done

if [ "${#SURFACE_HITS[@]}" -eq 0 ]; then
  echo "surface-contract: PASS -- no declared-surface path was touched."
  exit 0
fi

echo "surface-contract: declared-surface change detected in:"
printf '  %s\n' "${SURFACE_HITS[@]}"

# -- Requirements that now apply --------------------------------------------
VIOLATIONS=()

# The entry counts only if it is one of the two files named in the message
# below, at the repository ROOT, and still present after the change.
# Two ways the earlier `case "${f##*/}" in CHANGELOG*)` accepted a non-entry:
#   1. it matched a basename anywhere in the tree with any suffix, so
#      `vendor/junk/CHANGELOG-nonsense.txt` satisfied a documentation rule;
#   2. `git diff --name-only` lists DELETIONS, so removing CHANGELOG.md
#      counted as recording something in it.
# `-f` re-asks the question the consumer actually cares about: is there an
# entry on disk now.
changelog_touched=0
for f in "${CHANGED[@]}"; do
  case "$f" in
    CHANGELOG.adoc|CHANGELOG.md)
      if [ -f "$f" ]; then changelog_touched=1; fi
      ;;
  esac
done
[ "$changelog_touched" -eq 1 ] \
  || VIOLATIONS+=("no CHANGELOG entry: a surface change must be recorded in CHANGELOG.adoc or CHANGELOG.md")

case ",${PR_LABELS:-}," in
  *,surface-change,*) ;;
  *) VIOLATIONS+=("missing label: this PR must carry the 'surface-change' label") ;;
esac

if [ "${#VIOLATIONS[@]}" -gt 0 ]; then
  printf '::error::surface-contract: %s\n' "${VIOLATIONS[@]}"
  printf 'surface-contract: FAIL: %s\n' "${VIOLATIONS[@]}"
  exit 1
fi

echo "surface-contract: PASS -- surface change is documented and labelled."
