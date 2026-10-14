# Model verification — `llm_scan` (`step`: start, task, submit)

When the user wants **your model** to check what the scanners found ("verify these findings", "what do the
scanners miss?"). It comes after the triage and does not replace it. The server calls no model: you do the
reasoning, one task at a time.

1. `llm_scan { step: "start", project_path: "<project>", modes: ["verify"] }` (`"hunt"` too, after
   `map_attack_surface`). Show the user the token estimate and `token_limit_note` **before** going on. Above
   `max_estimated_tokens` the plan asks for `confirm: true` — pass it only after the user agrees. `confirm` opens
   the gate; the limit stays a ceiling.
2. `llm_scan { step: "task", plan_id: "<plan_id>" }` returns one task with a `brief` and a `lease_token` (a
   20-minute lease).
3. **One task per fresh subagent**: start an `Agent` with the brief and nothing else from this conversation
   (several in parallel is fine), and submit its JSON answer with
   `llm_scan { step: "submit", plan_id: "<plan_id>", task_id: "<task_id>", lease_token: "<lease_token>", independence: "subagent", payload: <the JSON answer> }`.
   The payload is the answer object alone: `step` and the ids stay out of it.
4. Repeat until step `task` says `done`; `llm_scan { step: "start", plan_id: "<plan_id>" }` returns the report
   (coverage is `full` only when every task closed).

Declare independence truthfully: an answer you gave yourself, in your own context, is
`independence: "same_context"` — shown in the report, but it never demotes or confirms a finding. Never declare
`subagent` for your own answer. Other hosts follow dev-guardian's rules file (Codex spawns subagents only when
asked; Cline and Claude Desktop run the tasks one after another with `same_context`).
