---
name: guardian-bugfix
description: Hunt and fix implementation bugs — race conditions, null safety, off-by-one, leaks, swallowed errors, flaky behaviour — with the bug_hunt tool and a reproduce → isolate → fix → regression-test method. Not for a bug reported in a project with .specs/ (dev-spec-driven's /spec-bugfix).
---

# Guardian Bugfix

Find the implementation bugs generic SAST misses, prove each one, fix it minimally and pin it with a
test. Respond in the user's language.

## A reported bug in a dev-spec-driven project

If the project has a `.specs/` folder and dev-spec-driven's tools are available, a bug the user
*reported* belongs to its bugfix flow: call `spec_next_action { name: "<feature>" }` for the feature
this branch implements (`spec_status {}` lists them), then `/spec-bugfix` — root cause, the approved
`bug.md`, a failing regression test, then the fix. There this skill is its reproduce-and-isolate
tool: `bug_hunt` scoped to the files involved. A hunt for bugs nobody has reported yet stays here.

## Bug classes

Null / undefined safety · race conditions (a missing `await`, unsynchronised state, duplicate
callbacks) · off-by-one and boundaries · resource leaks (handles, connections, listeners, timers,
subscriptions) · swallowed errors · type coercion · dates and time zones · encoding · input edge
cases (empty, negative, odd Unicode) · stale caches · pagination that drops or repeats records ·
stale closures and mutated props.

## Method

1. **Scope.** A specific bug (ask for the repro steps) or a sweep of the critical paths?
2. **Reproduce.** See it fail — a failing test whenever possible.
3. **Isolate.** Shrink to the smallest failing case: mock dependencies, reduce the input.
4. **Diagnose.** Read the code asking "what can go wrong here?", not "this looks fine". Logs, a
   debugger, the tests with coverage (uncovered lines are suspects), a race detector where the
   language has one (`go test -race`).
5. **Fix** the minimum. No refactor in the same change — that comes after, with `guardian-quality`.
6. **Regression test** that fails without the fix — non-negotiable, and watch it fail first. No test
   framework yet? Propose the minimal one (pytest, vitest / jest, …).

## `bug_hunt`

`bug_hunt { project_path: "<project>" }` runs Semgrep's `p/r2c-bug-scan` and `p/security-audit`
plus the plugin's local bug packs. Narrow it with `scope`:
`bug_hunt { project_path: "<project>", scope: { paths: ["src/orders"] } }`, or
`scope: { diff: { base: "main" } }` / `scope: { since: "v1.2" }`. `categories` (e.g.
`["race_condition"]`) filters the response only — every finding is still recorded;
`include_language_packs: true` adds per-language security bundles, not bug classes.

| Language | Local rules | Not covered — read the code |
| --- | --- | --- |
| JS / TS | 13 | `while` loops, cached lengths, lifecycles other than `useEffect`, a named `find` predicate |
| Python | 10 | a forgotten `await` on your own coroutine, a compiled pattern's `.match`, handles kept on `self` |
| Go | 9 | hung goroutines, loop-variable capture, a nil map received as a parameter |
| Java | 7 | `Integer ==`, `Deque` / `Queue` / custom collections, closeables other than `FileInputStream` |
| C# | 11 | `IDisposable` leaks, `Task.Run(...).Result` |
| PHP | 6 | resource leaks (no rule) |
| Rust | 1 | all but a blocking sleep in an `async fn` — recommend `cargo clippy` lints |
| Ruby | 0 | everything — recommend RuboCop and the `p/ruby` registry pack |

Before you say a class is covered, read [`references/coverage.md`](references/coverage.md): what
each rule misses, and what it flags wrongly.

Reading the result:

- A scanner in `missing_tools`, or a `tools_run` entry that did not run, is a gap — never "0 bugs".
- The rules match syntax, not dataflow: a quiet result is not a bug-free project, and a guard one
  function away is invisible to them.
- Most local rules are `WARNING` heuristics (reported as `medium`); a handful are `ERROR` (`high`).
  Confirm each finding in the code before you report it.

## Fixing

`create_fix_pr` cannot fix these findings, at any `severity_min`: it applies only a fix the scanner
itself emitted (`fix_available`), and no local bug rule ships one — its `filtered_reason` says so.
For each bug, `suggest_fix { project_path: "<project>", finding_fingerprint: "<fingerprint>" }`
gathers the context; write the patch yourself and show the diff. `/guardian-fix --pr` is for
dependency bumps and Semgrep autofixes.

- Never apply a fix without asking.
- Apply with confirmation: mechanical fixes (a null check, a missing `await`, an effect cleanup).
- Only suggest: anything that changes business behaviour (how a payment is processed, …) — the
  user decides.

## Common fixes

```js
const name = user?.profile?.name ?? "Anonymous";          // was: user.profile.name

useEffect(() => {                                         // a late response overwrote a newer one
  let cancelled = false;
  fetch(`/api/search?q=${query}`).then((r) => { if (!cancelled) setResults(r); });
  return () => { cancelled = true; };
}, [query]);

useEffect(() => {                                         // the listener outlived the component
  window.addEventListener("resize", onResize);
  return () => window.removeEventListener("resize", onResize);
}, []);
```

```python
try:
    do_thing()
except SpecificError:                     # was: except Exception: pass
    logger.exception("do_thing failed")   # then decide: retry, re-raise or fall back
```

## "Sometimes it works, sometimes it doesn't"

Check in this order: a race condition · a flaky external dependency (network, database, API) ·
specific data (an odd character, a null record) · time zone or date (everything breaks at
midnight) · a stale cache (the first request works, the second does not) · memory or resources
(fine at first, failing later).

## Don'ts

- A `try/catch` added only to silence an error hides the next bug.
- Don't "fix" a bug by changing the expected behaviour — confirm what should happen first.
- No debug logging in the final commit.
- Don't trust a test you just wrote until you have seen it fail without the fix.

After the fix, suggest the `guardian-quality` skill (no new smells) and `/guardian-fix --verify`
(re-scan and confirm the delta).
