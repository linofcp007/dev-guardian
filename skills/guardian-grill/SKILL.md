---
name: guardian-grill
description: Understanding gate on a diff/PR — the AI grills YOU about the domain-significant decisions the code introduced, before you merge. Complements the other quality gates: linters check style, Semgrep checks security, tests check behaviour, and guardian-grill checks that a HUMAN still understands the branches and rules the diff added. For the long autonomous loops where you no longer read every line. EN triggers — use when the user says "guardian grill", "grill me on this diff/PR", "do I understand this change?", "I didn't read all this code", "quiz me before I merge", "understanding check", "am I merging blind?". PT triggers — usa quando disserem "guardian grill", "sabatina ao diff/PR", "será que percebo esta mudança?", "não li este código todo", "questiona-me antes do merge", "estou a fazer merge às cegas?". ES triggers — úsala cuando digan "guardian grill", "interrógame sobre este diff/PR", "¿entiendo este cambio?", "no leí todo este código", "pregúntame antes del merge", "¿estoy haciendo merge a ciegas?". Trilingual EN/PT/ES — respond in the user's language.
---

# Guardian Grill — the understanding gate

The other Guardian gates check the *code*. This one checks the *human*. In long autonomous loops you
stop reading every line — so the risk isn't just a bug the tools miss, it's that **you no longer
understand the rules the AI wrote into your product**. `guardian-grill` closes that gap: it reads the
diff, finds the decisions that carry domain meaning, and grills you on them before merge.

It is the diff-time adapter of the **dev-grill** engine. The interrogation *method* lives in the
`dev-grill` skill; this skill only decides **what to feed it** (the diff) and **where the answer
goes** (a merge verdict). If `dev-grill` is installed, load it in `diff` mode with output contract =
`gate`. If not, run the same loop inline using the method below.

## When this gate is the right one

- After an agent ran for a while and produced a chunk of code you didn't read line by line
- Before merging a PR whose logic you want to be sure you actually understand
- Pairs with `guardian-review` (which checks the code) — run both for a full pre-merge gate

For style, security, or test coverage, use `guardian-review` / `guardian-security` / `guardian-quality`.

## Flow

### 1. Get the diff

```bash
git diff origin/main...HEAD     # PR
git diff --staged               # pre-commit
git diff <last-tag>..HEAD       # pre-release
```

### 2. Extract the significant decisions

Scan the diff for what carries **domain meaning or risk**, not style. Build a short list of:

- New / changed business-rule branches (`if`, `switch`, guard clauses)
- Validation rules and their failure paths
- State changes, side effects, ordering, retries, idempotency
- Error handling choices (specific vs swallow-all; what the caller sees)
- New boundaries, invariants, or "this must never happen" assumptions
- Anything with a magic number, threshold, or hard-coded policy
- **Hot-path / performance decisions** — a query or network call added inside a loop (N+1), a new
  blocking/sync call on a request path, an unbounded query/list/payload, a removed cache or index, or
  anything that could push an endpoint's p95 or a bundle over its `perf-budget.yml`
- **Security-significant decisions** — a new trust boundary or input path, auth/permission logic, a
  raw query / shell / HTML sink, a disabled defence (CSP/CORS/validation), a new secret or token flow,
  or a new external dependency. Grill *why it's safe*, not just what it does. (Live 🔴/🟠 vulns are not a
  grill — they block; hand to `guardian-security`/`guardian-leak`.)
- **Deletions in the diff** — code/exports/deps being removed. Grill that it's truly unreachable:
  nothing calls it via reflection, dynamic route/DI, public API, or a feature flag. An unsafe delete
  is a silent breakage the tests may not catch.

Ignore formatting, renames, and anything a linter/quality gate already owns.

### 3. Grill — one question at a time

Run the dev-grill loop over that list. For each significant decision, ask whether the human can
explain **what it does and why it's there**. Push on vague answers ("why this threshold?", "what
happens when this validation fails?", "is this branch reachable concurrently?"). ONE question at a
time — never a questionnaire.

This is the inversion: you're not reviewing the code *for* them, you're checking that *they* still
own the domain logic the AI generated.

### 4. Verdict

End with the Shared Understanding summary (language-agnostic) and a one-line merge gate:

```markdown
## Understanding gate: 🟡 Understood with gaps

🟢 Understood — every significant branch explained
🟡 Understood with gaps — <list the branches the human couldn't fully account for>
🔴 Not understood — <major decisions unexplained; do not merge blind — read these files first>
```

A 🟡/🔴 is a finding, not a failure: it points exactly at the code worth reading before merge, so you
read 30 lines instead of 10k.

## Persist the verdict (feeds the quality gate)

Always record the verdict so the quality gate can include the understanding dimension. Write a short
line to `.guardian/last-grill.md`:

```text
<ISO date> · <branch/scope> · 🟢|🟡|🔴 · <one-line note> · gaps: <n>
```

`guardian-status` and `guardian-report` read this file and show an **Understanding gate** row next to
Coverage / Duplication / Violations — so "Passed" means the code metrics passed **and** a human
understood the change. A stale entry (older than the current diff) counts as 🔴 until re-run.

Also offer to append the full Shared Understanding summary to the PR description or to
`docs/understanding/<branch>.md`, so the rationale survives past the merge — the same source-of-truth
idea as an RFC, produced as a by-product instead of written up front.

## Rules of conduct

- One question at a time. Grill decisions and rationale, never style.
- Never answer your own questions to speed up — the point is to extract the human's understanding.
- Never emit a 🟢 you didn't earn. A false 🟢 defeats the whole gate.
- Don't block on anything outside the diff's scope.
- Mirror the user's language (EN/PT/ES).
