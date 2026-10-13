# AI / LLM features inside the app

`/guardian-scan` covers part of it: `scan_sast` — and so `security_scan_full` and `review_pr` — always runs the
plugin's LLM pack (Python and JS/TS, `local_only` too): model output reaching `eval` / `exec`, a shell or SQL; a
model-chosen tool name used without an allow-list; `trust_remote_code=True`; unsafe `torch.load`; HTTP request
data in the system prompt; OpenAI calls with no token limit (the full list is in `guardian-security`).

What the pack does not see — prompt injection arriving through documents or tool results, model output with
other side effects (database writes, external calls), quotas and unbounded agent loops, evals — is reviewed by
reading, with the "AI / LLM features" section of `guardian-review`'s checklist. Say so to the user instead of
implying full coverage.
