<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
# Spec mirrors — NOT evidence that svalinn works

The tests in this directory **do not import or execute a single line of
svalinn**. Each one inline-reimplements the behaviour it checks, then checks
its own reimplementation. Verified mechanically: every import resolves to
`jsr:@std/assert`, `jsr:@hono/hono` or `jsr:@std/path`, and none reads a file
from this repository.

`tests/e2e/gateway_test.js` said so itself, in a comment:

> `Very small policy evaluator that mirrors PolicyEvaluator.res semantics.`

It mirrored a `.res` file that no longer exists.

## So why keep them?

Because they encode the **specified** behaviour, and that is worth having.
Read them as an executable specification: what the gateway is supposed to do
about public paths, authenticated paths, rate limits and policy decisions.

What they must never be read as is **coverage**. A green run here says the
mirror agrees with itself. It says nothing about `tools/mvp/svalinn_gateway.ts`,
which is the code that actually runs.

## The rule

| Directory | Meaning |
|---|---|
| `tests/` | Executes real svalinn code. A pass here is evidence. |
| `tests/spec-mirror/` | Executes a reimplementation. A pass here is documentation. |

If you make one of these exercise real svalinn code, **move it up to
`tests/`** — that is a promotion, and the whole point of the split.

Run them with `just test-spec-mirror`; they are deliberately excluded from
`just test`.
