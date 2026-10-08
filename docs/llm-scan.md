# LLM-assisted scan

`llm_scan_start`, `llm_scan_task` and `llm_scan_submit` let **your host's model**
do two jobs scanners do badly:

- **verify** — check each scanner finding against the code and say whether an
  attacker can exploit it, quoting the line that decides it;
- **hunt** — look for the vulnerabilities scanners do not see (broken access
  control, business logic, data exposure), starting from the routes
  `map_attack_surface` found.

The server calls no model and holds no API key. It plans the work, hands out
one self-contained brief at a time, validates every answer against a schema and
against the files on disk, and keeps the plan in the project database so it
survives a restart. The reasoning is done by the model you already use, and the
result depends on that model: the report says so.

## The loop

1. `llm_scan_start { project_path, modes }` plans the scan. `modes` is
   `["verify"]` (the default), `["hunt"]` or both. It answers with `plan_id`,
   `tasks_total`, what was left out and why (`not_eligible`, `set_aside`), and a
   token `estimate`. **Show the user the estimate before going on.**
2. `llm_scan_task { plan_id }` hands out one task: `task_id`, a `lease_token`, the
   `brief` and its `response_schema`. The lease lasts 20 minutes; after that the
   task goes to whoever asks next. Tasks may be leased in parallel.
3. Run the brief where your host's recipe says (below), then
   `llm_scan_submit { plan_id, task_id, lease_token, independence, payload }` with
   the JSON answer. An invalid answer is refused with the reason and can be sent
   again; the third invalid answer closes the task as `undetermined`.
4. Repeat until `llm_scan_task` answers `{ done: true, report }`.
   `llm_scan_start { plan_id }` returns the report at any time.

A verify answer is `verdict` (`real`, `not_real`, `undetermined`),
`attacker_input` (`file:line`, or `none`), `operation` (`file:line`),
`decisive_line` (`file:line — reason`) and `reasoning` (at most 120 words). A
hunt answer is `entry_points_reviewed` and up to 50 `findings`, each with `file`,
`line`, `class`, `title`, `attacker` and `evidence` (at most 60 words, citing a
`file:line`). Every `file:line` must exist inside the project, or the answer is
refused.

## Independence: who ran the brief

Every answer declares how it was produced:

| `independence` | Meaning | Effect |
| --- | --- | --- |
| `subagent` | a fresh context ran the brief and nothing else of the conversation | demotes or confirms |
| `sampling` | the server ran it through the client's model (`execute: "sampling"`) | demotes or confirms |
| `same_context` | the model that holds the conversation answered it itself | **shown only**: never demotes, never confirms |

Declare it honestly. A `same_context` answer has read everything else in the
conversation, so in hosts without subagents the scan is advisory. Claiming
`subagent` for an answer you gave yourself corrupts the report.

### Recipe per host

The rules file `mcp-config` writes for each host carries this recipe:

- **Claude Code** — one fresh subagent per task (parallel is fine), declared
  `subagent`. The `guardian-security` skill does this.
- **Codex** — it starts a subagent only when asked to, so ask explicitly: "spawn
  a subagent for each `llm_scan_task` brief, one task per subagent". Otherwise
  it answers in its own context: `same_context`.
- **Cline**, **Claude Desktop / Cowork chat** — no subagent that can use MCP: the
  tasks run sequentially in the same context, declared `same_context`.
- **A client that declares MCP sampling** (VS Code Copilot does) —
  `llm_scan_task { plan_id, execute: "sampling" }` runs the verify tasks inside
  the server through the client's model. Hunts need tools, so they are never
  sampled. Without the capability the call answers `sampling_unavailable`.
- **Any other host** — a fresh subagent per task when one can call the tools,
  otherwise sequential with `same_context`.

## What the verdicts change

Verdicts are stored as `finding_validations` with provider `llm`: `real` as
`exploitable`, `not_real` as `not_exploitable`. Only an independent verdict
acts on a finding:

- **`not_real` on a scanner finding** demotes it. Triage lists it among the
  likely false positives with the decisive line as the reason, and the report
  shows the verdict and the reasoning. It is **never suppressed or deleted**: it
  stays in the open set, marked. A credential finding stays `keep` whatever the
  verdict, and a suppression made earlier stays in force.
- **A hunt finding** is stored as an `llm-hunt` finding of the plan's `llm_scan`
  scan, with a verify task of its own. It counts — in the open set, triage,
  `risk_score`, `regression_alert`, `diff_scans`, the dashboard, the scan
  resources and the release gates — only once an independent verify answer
  says `real`. Until then, and after a `not_real`, it is a candidate: the
  report lists it in a section of its own and no total counts it.
- **A file changed** between the plan and the answer: the task closes as
  `stale`, and its verdict demotes nothing.

The severity of a hunt finding comes from its class. Injection (SQL, NoSQL,
command, code, template), deserialization, XXE, SSRF, path traversal, broken
access control, authentication and secrets are `high`; every other class is
`medium`. A verdict decides whether a hunt finding counts, never its severity.

## Limits

| Limit | Value | When it is reached |
| --- | --- | --- |
| Tasks handed out per plan | `max_tasks`, default 200 | delivery stops with `limit_reached`; coverage `partial`, the undelivered tasks named |
| Estimated tokens | `max_estimated_tokens`, default 500 000 | above it the plan says `needs_confirm`, and nothing is handed out until `llm_scan_start { plan_id, confirm: true }` |
| Planned tasks | 1 000 | the rest is listed with `overflow: true`; coverage `partial` |
| Open plans per project | 5 | `too_many_open_plans`, with the open `plan_id`s to resume |
| Lease | 20 minutes | the task goes to whoever asks next |
| Invalid answers per task | 3 | the task closes `undetermined` (`invalid_submissions`) |
| Answer size | 64 KiB serialized | `too_large`, before anything else is read |
| Hunt findings per answer | 50 | the whole answer is refused |
| Brief | 20 000 estimated tokens | the brief is cut to fit; a verify brief is about 1 500 in practice |
| One `execute: "sampling"` call | 50 s | no request starts after it; the call returns its progress |

**`confirm` opens the gate; it never raises the ceiling.** `max_estimated_tokens`
stays a hard limit on what is handed out. Above it the answer gives
`deliverable_within_token_limit` — how many tasks fit — and a fixed
`token_limit_note`. To cover the whole plan, start again with a larger
`max_estimated_tokens`. The estimate counts the host's own overhead per task
(`per_task_overhead`, default 60 000 tokens for a subagent). Only the host knows
the real token use, and the report says so.

**Abandoned plans.** A plan with no activity for 7 days stops counting toward the
five open plans, and stays resumable by its `plan_id`. Retention marks it
`abandoned` at 30 days; resuming it then answers `plan_abandoned`.

**A brief the host's model refuses.** Briefs quote security-relevant code, and a
provider's safeguards sometimes refuse one before the model answers (in the evals,
3 runs in 175, also on briefs with nothing injected, and rarely twice in a row).
Nothing is submitted, so nothing changes: the task's lease expires after 20
minutes and the task is handed out again. Run it again in a new subagent, or
leave it: the report names it among the tasks not closed with a valid answer,
and coverage stays `partial`.

## Errors

| Code | Meaning |
| --- | --- |
| `needs_surface` | a hunt needs `map_attack_surface` first, or again (the project changed since the last snapshot) |
| `nothing_to_plan` | no finding with a file and line to verify, and nothing to hunt |
| `too_many_open_plans` | five active plans already; the answer lists them |
| `needs_confirm` | the estimate is above `max_estimated_tokens` and the plan is not confirmed |
| `limit_reached` | `max_tasks` or the token ceiling stopped delivery |
| `bad_lease` | plan, task and lease token do not match (no hint which) |
| `already_closed` | the task has its answer already; the first one stands |
| `too_large` | the answer is over 64 KiB |
| `plan_abandoned` | the plan is older than 30 days without activity; start a new one |
| `sampling_unavailable` | `execute: "sampling"` from a client without the capability |
| `store_failed` | the answer could not be stored; nothing changed and the task is still yours |

## Safety

The scanned repository is untrusted. It can hold text aimed at the model: a
comment that says "verified safe", or a string that says "ignore your
instructions". The scan is built around that:

- the code in a brief sits between two copies of a random marker, and the brief
  says that everything between them is data;
- a secret the existing detectors find is replaced by `‹rule line n›` before it
  reaches a brief;
- an answer is validated against a closed schema, and every `file:line` it cites
  is checked on disk, inside the project, through the contained reader. A path
  outside the project is refused without being opened;
- nothing in an answer is executed, opened or followed;
- model-written text in a report is escaped, so it can never become markup.

What remains: a model steered by the repository can still give a wrong verdict
within the schema. That is why a `not_real` demotes a finding but never hides
it. The checked threat model is in
[`mcp/src/llmscan/constraints.md`](../mcp/src/llmscan/constraints.md).

**Privacy.** dev-guardian sends nothing anywhere. The code in each brief goes to
your host's model provider, as it does whenever that host reads your files.
