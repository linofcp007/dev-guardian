---
description: Performance + cost + complexity budgets — am I within them? Budgets. Presupuestos.
---

Check whether the project is **within its declared budgets**. Different from `guardian-perf` (which actively measures) — this is a budget *audit*.

The skill should look for budget declarations in:

- `lighthouserc.json` / `.lighthouserc.cjs` (Lighthouse CI performance budgets)
- `package.json` `"performance"` field, `"size-limit"` config
- `.guardian/budgets.yml` (if the project uses Guardian's own format)
- Custom backends: response-time SLOs in code comments / CI config

For each declared budget, check the latest measurement against it. For AI-powered features, additionally check:

- **Cost-per-inference budget** (USD/call or tokens/call) — flag prompts that drift over the cap.
- **Latency budget** for LLM responses.
- **Token-context budget** — features consuming >X% of model context window.

Also audit **code-quality budgets** (these are the same thresholds `guardian-improve` uses as spec targets and the gate uses to block regressions), stored in `.guardian/budgets.yml`:

- **max file lines** / **max function lines** — the size budget that forces modularization.
- **max cyclomatic complexity** per function.
- **max duplication %**.
- **coverage floor** (lines / branches).

These are **per project type**. Call `detect_stack` first and propose defaults appropriate to *that* stack (a Rust crate, a React app and a billing service should not share limits) — don't apply one global default. `.guardian/budgets.yml` is the **single source of truth**: the quality gate reads it to pass/fail, and `guardian-improve` reads it to set improvement-spec targets, so tuning is per project and lives in one place.

For projects with **no declared budgets**, propose sensible stack-based defaults and offer to write `.guardian/budgets.yml`. If the project isn't ready to commit to absolute numbers, seed the budgets from the current baseline ("no worse than today") so improvement is still measurable.

Verdict: ✅ within budget / ⚠️ over budget but close / 🔴 significantly over budget (with the specific number and threshold).

Budget category hint (e.g. "perf", "cost", "complexity"): $ARGUMENTS
