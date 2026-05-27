---
description: AI/LLM-feature audit — prompt injection, key exposure, eval gaps, cost. Foco AI. Foco AI.
---

Run the **AI / LLM-focused** Guardian flow. Use when the project calls an LLM API (Anthropic, OpenAI, Google, open models via Ollama/vLLM/etc.) or embeds an agent / RAG / chatbot.

The skill should:

1. **Key exposure** — grep for API keys, search history for leaked keys, verify keys are loaded from env / secret manager not hardcoded.
2. **Prompt injection surface** — find every spot where user input flows into a model prompt unescaped. Flag missing input sanitisation, missing system-prompt isolation, untrusted tool-call arguments.
3. **Eval gaps** — does the project have an eval suite for the LLM feature? Flag features without evals as 🟡, autonomous agents without evals as 🔴.
4. **Hallucination blast radius** — for each LLM-driven action, classify: display-only (low), database write (high), external API call (critical).
5. **Token / cost guardrails** — verify max-tokens, retry budgets, per-user quotas, model-routing (cheap model when sufficient).
6. **Model lifecycle** — pin model versions, check for retired-model usage, plan upgrade path.

Defer to the `ai-product-spec-scale` skill for new AI features and `claude-api` skill for Anthropic SDK specifics — those are the spec-driven flows.

Feature hint (e.g. "the chatbot in /api/ask", "the RAG ingestion pipeline"): $ARGUMENTS
