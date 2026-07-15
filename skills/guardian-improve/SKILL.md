---
name: guardian-improve
description: Turn measured tech debt into improvement specs — the bridge from dev-guardian's findings to dev-spec-driven's backlog. Takes the ROI-ranked hotspots, quality-rule violations, oversized files, duplication fragments and coverage gaps that the quality gate reports, and drafts each top item as an improvement spec seed — problem, affected files, current metric → target metric, draft EARS acceptance criteria — so it can be grilled, specced and fixed with proof. Closes the loop: measure → spec → fix → re-measure. EN triggers — use when the user says "guardian improve", "turn the debt into specs", "what should I refactor next and how", "make specs from the violations", "plan the cleanup", "spec the tech debt", "clean this up properly". PT triggers — usa quando disserem "guardian improve", "transforma a dívida em specs", "o que refatoro a seguir e como", "cria specs das violações", "planeia a limpeza", "especifica a dívida técnica", "limpa isto como deve ser". ES triggers — úsala cuando digan "guardian improve", "convierte la deuda en specs", "qué refactorizo y cómo", "crea specs de las violaciones", "planifica la limpieza", "especifica la deuda técnica". Trilingual EN/PT/ES — respond in the user's language.
---

# Guardian Improve — from debt to specs

The quality gate tells you *what* is wrong (403 violations, 16 oversized files, 24% branch
coverage). This skill turns that into *plans you can execute with proof*: it converts the worst,
highest-ROI findings into **improvement spec seeds** ready to hand to `dev-spec-driven`. It's the
bridge that closes the loop — measure (guardian) → spec (spec-driven) → fix → re-measure (guardian).

## When this is the right skill

- After a `guardian-quality` / `guardian-debt` / gate run, when the user asks "ok, now what — and how do I fix it cleanly?"
- When violations/oversized files/low coverage keep showing up and you want a *plan*, not another scan
- Before a cleanup sprint, to produce a prioritized, spec-backed backlog

For just measuring, use `guardian-quality` / `guardian-debt`. This skill assumes the measuring is done.

## Flow

### 1. Gather the findings

Pull the current picture (reuse what's already in `.guardian/guardian.db`; don't rescan unless stale):

- **Hotspots by ROI** — same ranking as `guardian-debt` (`risk_score` = defect density × severity × churn).
- **Quality-rule violations** — grouped by rule and by file.
- **Oversized files** and **oversized functions** — the ones over the project's budget.
- **Duplication fragments** — clusters that appear ≥ 2×.
- **Coverage gaps** — modules well below the project's coverage floor.
- **Performance regressions & over-budget hot paths** — from `guardian-performance` / `perf_check`:
  endpoints over their p95/p99 budget, Core Web Vitals over budget, oversized bundles, and measured
  hot-path smells (N+1, blocking I/O, slow regex). Only what is **measured over budget** — profile
  first, never speculative optimization (mirrors `guardian-performance`'s "don't optimize what isn't hurting").
- **Security — systemic/hardening class only** — from `guardian-security` (`scan_sast` / `scan_secrets`
  / `scan_deps` / `scan_iac`). See the routing rule below: a live 🔴/🟠 finding is **not** a backlog
  item. Only recurring, systemic weaknesses become improvement specs (e.g. "parameterize all queries in
  `orders`", "add a central input-validation layer", "remove `any`-typed request bodies").
- **Dead code & unused surface** — per stack: TS/JS `knip` / `ts-prune` / `depcheck`, Python `vulture`,
  Go `deadcode`, Rust `cargo-udeps`; plus unused exports, unreachable branches, and dependencies with
  near-zero usage (`guardian-debt` already flags 🗑️ candidates). High-ROI clean-code win — but deletion
  needs the safety grill (see step 3).

### 2. Cluster into improvement units

Don't emit one spec per violation — that's noise. Group findings that share a root cause or a file
into a small number of **improvement units** (typically 3–7). A unit is one coherent piece of work,
e.g. "split the 900-line `checkout` module and cover its branches", not 40 separate line items.

Rank units by ROI: biggest metric move for the smallest, safest change. Favour modularization
(splitting oversized files/functions) — per the project's own budget rules, that's what drags the
other metrics up too.

### 3. Draft each unit as an improvement spec seed

For each unit, produce this seed. Keep it **language-agnostic** and metric-anchored:

```markdown
## Improvement: <short title>

**Why now (ROI):** <biggest impact / smallest risk in one line>
**Affected:** <files / modules>
**Current → Target (the acceptance test):**
- <metric>: <current> → <target>   e.g. branch coverage of `checkout`: 24% → 45%
- <metric>: <current> → <target>   e.g. no function > 60 lines in `checkout` (currently 3)
- <metric>: <current> → <target>   e.g. p95 latency of `/api/checkout`: 820ms → 400ms (perf-budget)

**Draft acceptance criteria (EARS):**
- WHEN the `checkout` module is built, THE SYSTEM SHALL contain no file over <N> lines.
- WHEN tests run, branch coverage of `checkout` SHALL be ≥ <target>%.
- THE refactor SHALL NOT change observable behaviour (characterization tests stay green).

**Suggested track:** core (+tdd if behaviour must be pinned before refactor)
**Grill first:** yes — run /grill or /guardian-grill on the current code so you understand the
branches before you move them.
```

The **Current → Target block is the spec's success criterion**: the same gate that found the problem
re-measures at the end and proves the fix. Don't write improvement specs whose "done" can't be
re-measured by the gate — vague cleanup isn't a spec.

### Where the targets come from (per project, per stack — never fixed)

The numbers in the seed above (60 lines, 300 lines, 45%) are **examples, not defaults**. Real targets
must be *derived from this project*, in this order:

1. **The project's declared budgets** — read `.guardian/budgets.yml` (quality) and
   `.guardian/perf-budget.yml` (performance: p95/p99 per endpoint, Core Web Vitals, bundle KB), plus
   `guardian-budget`'s config (`lighthouserc`, `size-limit`, `package.json` `performance`). If a
   max-file-lines / max-function-lines / max-complexity / coverage-floor / latency / bundle budget is
   declared, that IS the target. The gate already enforces it.
2. **The stack** — call `detect_stack` and pick sane budgets for *that* project type. A Rust systems
   crate, a React app, and a billing service do not share thresholds. If `.guardian/budgets.yml` has no
   quality budget yet, propose stack-appropriate ones and offer to write them (same as `guardian-budget`).
3. **The baseline, as a floor** — read `set_baseline` / the latest gate delta. When no absolute target
   is sensible, the target is **relative**: "improve the baseline by X%" or "no metric worse than
   baseline". Never invent a magic absolute number the project never agreed to.

Rule: if you can't trace a target to a declared budget, the stack, or the baseline, don't assert it —
ask the user or propose it explicitly as a new budget to add. The budget file is the single source of
truth shared by the gate and by these specs, so tuning happens per project, in one place.

### 4. Hand off to dev-spec-driven

For each seed, add it to the backlog so it shows in the roadmap:

- Preferred: `spec_backlog` MCP tool — `dev-spec backlog add "<title>" "<one-line note + target metric>"`.
- Then offer to scaffold the chosen one into a full feature with `spec_create` / `/spec`, carrying
  the seed's EARS criteria into `requirements.md`.

If `dev-spec-driven` isn't installed, write the seeds to `docs/improvement-specs/<title>.md` and tell
the user they can feed them to any spec workflow.

### 5. Recommend order and stop

Present the units as a short ordered list (ROI-sorted) with the target metric next to each. Suggest
tackling the top 1–2 this cycle, not all. Remind the user of the loop: grill → spec → fix →
re-run the gate to confirm the delta.

## Routing: what does NOT become an improvement spec

- **Live security findings (🔴 critical / 🟠 high)** — secrets in the repo, injection, auth bypass,
  a vulnerable dependency with a known exploit. These **block and get fixed now** via
  `guardian-review` / `guardian-leak` / `guardian-panic` / `guardian-deps` — never parked in a
  backlog. Only the *systemic* pattern behind repeated findings becomes a hardening spec.
- **Dead-code deletion is not automatic.** A "dead" symbol may be reached via reflection, a dynamic
  route/DI, a public API, a feature flag, or another package. Before a removal spec is real, it must
  pass the deletion safety grill (`/guardian-grill` on the removal) — see below.

## Guardrails

- Never propose a mass rewrite. Smallest move, biggest metric gain.
- Security: criticals block, hardening specs. Never turn an active vulnerability into backlog.
- Dead code: prove it's unreachable (grill for reflection / dynamic dispatch / public API / flags)
  before spec'ing a deletion. When unsure, spec a *deprecation* (mark + log + wait), not a delete.
- Every seed must have a re-measurable target — if the gate can't verify it, it's not a spec.
- Refactors must pin behaviour first (characterization tests) so "clean code" never means "broke it cleanly".
- Don't invent AC IDs — `dev-spec-driven` owns those.
- Mirror the user's language (EN/PT/ES).
