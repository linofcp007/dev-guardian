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

For projects with **no declared budgets**, propose sensible defaults based on the stack and offer to write the config file.

Verdict: ✅ within budget / ⚠️ over budget but close / 🔴 significantly over budget (with the specific number and threshold).

Budget category hint (e.g. "perf", "cost", "complexity"): $ARGUMENTS
