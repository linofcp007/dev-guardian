---
name: guardian-improve
description: Turn measured tech debt into improvement specs — the bridge from dev-guardian's findings to the dev-spec-driven backlog. Takes the ROI-ranked hotspots, quality findings, duplication, over-budget metrics and systemic security weaknesses, and drafts each top item as an improvement spec seed (problem, affected files, current metric → target metric, draft EARS acceptance criteria) that the same scans can re-measure. Closes the loop measure → spec → fix → re-measure. EN triggers — "turn the debt into specs", "what should I refactor next and how", "make specs from the violations", "plan the cleanup", "spec the tech debt". PT — "transforma a dívida em specs", "o que refatoro a seguir e como", "cria specs das violações", "planeia a limpeza", "especifica a dívida técnica". ES — "convierte la deuda en specs", "qué refactorizo y cómo", "crea specs de las violaciones", "planifica la limpieza", "especifica la deuda técnica". Respond in the user's language.
---

# Guardian Improve — from debt to specs

The scans tell you *what* is wrong (403 quality findings, 16 oversized files, 24% branch
coverage). This skill turns that into *plans you can execute with proof*: it converts the worst,
highest-ROI findings into **improvement spec seeds** ready to hand to `dev-spec-driven`. It's the
bridge that closes the loop — measure (guardian) → spec (spec-driven) → fix → re-measure (guardian).

## When this is the right skill

- After a `guardian-quality` skill run or `/guardian-report debt`, when the user asks "ok, now what — and how do I fix it cleanly?"
- When the same quality findings keep showing up and you want a *plan*, not another scan
- Before a cleanup sprint, to produce a prioritized, spec-backed backlog

For just measuring, use the `guardian-quality` skill or `/guardian-report debt`. This skill assumes the measuring is done.

## Flow

### 1. Gather the findings

Pull the current picture from what is already stored — rescan only when the latest scan is stale:

- **Hotspots by ROI** — the same ranking as `/guardian-report debt`: `prioritize_findings { project_path: "<project>", limit: 50 }` for the weighted open findings, `risk_score { project_path: "<project>" }` for the project-level picture, and git churn (`git log --since="6 months ago" --name-only --format=`). No tool ranks files — you combine findings per file × severity × churn.
- **Quality findings** — `quality_check { project_path: "<project>" }` (duplicate / complexity / smell / naming), grouped by rule and by file. A stale scan is re-run; a fresh one is read back.
- **Duplication fragments** — jscpd clusters that appear ≥ 2×, from the same `quality_check`.
- **Over-budget metrics** — the budgets in `.guardian/budgets.yml` that `quality_check` (duplication %, complexity) and `perf_check` (Core Web Vitals, page weight) report as exceeded.
- **Oversized files and functions, coverage gaps** — measured by you (line counts, the project's own coverage report). They are not `budgets.yml` fields, so no tool enforces a limit on them: use them as targets only when the user agrees on the number.
- **Performance hot paths** — measured only: `perf_check` results, k6 thresholds the project's scripts fail, and profiled hot-path smells (N+1, blocking I/O, slow regex). Never speculative optimization (mirrors the `guardian-performance` skill's "don't optimize what isn't hurting").
- **Security — systemic/hardening class only** — from the `guardian-security` scans (`scan_sast` / `scan_secrets` / `scan_deps` / `scan_iac`). See the routing rule below: a live 🔴/🟠 finding is **not** a backlog item. Only recurring, systemic weaknesses become improvement specs (e.g. "parameterize all queries in `orders`", "add a central input-validation layer", "remove `any`-typed request bodies").
- **Dead code & unused surface** — per stack: TS/JS `knip` / `ts-prune` / `depcheck`, Python `vulture`, Go `deadcode`, Rust `cargo-udeps` (none of these run through the MCP tools — suggest them); plus unused exports, unreachable branches, and dependencies with near-zero usage (`/guardian-report debt` flags 🗑️ candidates). High-ROI clean-code win — but deletion needs the safety grill (see step 3).

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
- <metric>: <current> → <target>   e.g. p95 latency of `/api/checkout`: 820ms → 400ms (k6 threshold)

**Draft acceptance criteria (EARS):**
- WHEN the `checkout` module is built, THE SYSTEM SHALL contain no file over <N> lines.
- WHEN tests run, branch coverage of `checkout` SHALL be ≥ <target>%.
- THE refactor SHALL NOT change observable behaviour (characterization tests stay green).

**Suggested track:** core (+tdd if behaviour must be pinned before refactor)
**Grill first:** yes — run /grill or /guardian-grill on the current code so you understand the
branches before you move them.
```

The **Current → Target block is the spec's success criterion**: the same measurement that found the
problem re-measures at the end and proves the fix — the same tool (`quality_check`, `bug_hunt`,
`perf_check`, …) compared with `diff_scans`, or the same count taken the same way. Don't write
improvement specs whose "done" can't be re-measured — vague cleanup isn't a spec.

### Where the targets come from (per project, per stack — never fixed)

The numbers in the seed above (60 lines, 300 lines, 45%) are **examples, not defaults**. Real targets
must be *derived from this project*, in this order:

1. **The project's declared budgets** — `.guardian/budgets.yml`, the one budget file dev-guardian
   reads: `quality.duplication_pct` and `quality.complexity` (checked by `quality_check`), and
   `perf.lcp_ms`, `perf.inp_ms`, `perf.cls`, `perf.tbt_ms`, `perf.bundle_size_kb` (checked by
   `perf_check` on a Lighthouse run). A declared budget IS the target, and the tool that found the
   problem re-measures it. The project's own `lighthouserc`, `size-limit` config and k6 thresholds
   count too — their own tools enforce them.
2. **The stack** — call `detect_stack` and pick sane values for *that* project type. A Rust systems
   crate, a React app, and a billing service do not share thresholds. If `.guardian/budgets.yml` has no
   budget yet, propose stack-appropriate ones and offer to write them (the `guardian-quality` skill has
   the file format).
3. **The baseline, as a floor** — `diff_scans { project_path: "<project>", from: "baseline" }` shows
   where the project stands against its accepted baseline. When no absolute target is sensible, the
   target is **relative**: "no metric worse than the baseline", "N fewer findings of rule X". Never
   invent a magic absolute number the project never agreed to.

Rule: if you can't trace a target to a declared budget, the stack, or the baseline, don't assert it —
ask the user or propose it explicitly as a new budget to add. File size, function size and coverage
are not `budgets.yml` fields: a target on them is fine when the user agrees, but say that the proof
at the end is your measurement or the project's coverage report, not a dev-guardian scan.

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
`/guardian-fix --verify` to re-run the measurement and confirm the delta.

## Routing: what does NOT become an improvement spec

- **Live security findings (🔴 critical / 🟠 high)** — secrets in the repo, injection, auth bypass,
  a vulnerable dependency with a known exploit. These **block and get fixed now** via `/guardian-fix`,
  `/guardian-incident leak`, `/guardian-incident panic` or the `guardian-deps` skill — never parked in
  a backlog. Only the *systemic* pattern behind repeated findings becomes a hardening spec.
- **Dead-code deletion is not automatic.** A "dead" symbol may be reached via reflection, a dynamic
  route/DI, a public API, a feature flag, or another package. Before a removal spec is real, it must
  pass the deletion safety grill (`/guardian-grill` on the removal) — see below.

## Guardrails

- Never propose a mass rewrite. Smallest move, biggest metric gain.
- Security: criticals block, hardening specs. Never turn an active vulnerability into backlog.
- Dead code: prove it's unreachable (grill for reflection / dynamic dispatch / public API / flags)
  before spec'ing a deletion. When unsure, spec a *deprecation* (mark + log + wait), not a delete.
- Every seed must have a re-measurable target — if nothing can re-measure it, it's not a spec.
- Refactors must pin behaviour first (characterization tests) so "clean code" never means "broke it cleanly".
- Don't invent AC IDs — `dev-spec-driven` owns those.
- Mirror the user's language (EN/PT/ES).
