# LLM-assisted scan

`llm_scan` lets **your host's model** do two jobs scanners do badly:

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

One tool, three steps (`step`); each step takes its own arguments, and a
parameter of another step is refused with `invalid_input`.

1. `llm_scan { step: "start", project_path, modes }` plans the scan. `modes` is
   `["verify"]` (the default), `["hunt"]` or both. It answers with `plan_id`,
   `tasks_total`, what was left out and why (`not_eligible`, `set_aside`), and a
   token `estimate`. **Show the user the estimate before going on.**
2. `llm_scan { step: "task", plan_id }` hands out one task: `task_id`, a
   `lease_token`, the `brief` and its `response_schema`. The lease lasts 20
   minutes; after that the task goes to whoever asks next. Tasks may be leased in
   parallel.
3. Run the brief where your host's recipe says (below), then
   `llm_scan { step: "submit", plan_id, task_id, lease_token, independence, payload }`
   with the JSON answer as `payload`. An invalid answer is refused with the
   reason and can be sent again; the third invalid answer closes the task as
   `undetermined`. A call with no `payload` is refused before the task is
   touched, and costs no try.
4. Repeat until step `task` answers `{ done: true, report }`.
   `llm_scan { step: "start", plan_id }` returns the report at any time.

The three steps were three tools before 3.4.0: `llm_scan_start`,
`llm_scan_task` and `llm_scan_submit` still answer `tools/call` with the same
arguments, but are no longer listed. A plan keeps the prompt version it was
made with, so the briefs of a plan made before 3.4.0 (prompt v5) still say
`llm_scan_submit`; answer them through `llm_scan { step: "submit" }` or that
name, either works.

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
  a subagent for each `llm_scan` task brief, one task per subagent". Otherwise
  it answers in its own context: `same_context`.
- **Cline**, **Claude Desktop / Cowork chat** — no subagent that can use MCP: the
  tasks run sequentially in the same context, declared `same_context`.
- **A client that declares MCP sampling** (VS Code Copilot does) —
  `llm_scan { step: "task", plan_id, execute: "sampling" }` runs the verify tasks inside
  the server through the client's model. Hunts need tools, so they are never
  sampled. Without the capability the call answers `sampling_unavailable`.
- **Any other host** — a fresh subagent per task when one can call the tools,
  otherwise sequential with `same_context`.

Run end to end on a real host so far: Claude Code (20 findings verified, every
tool call under 300 ms) and Codex CLI 0.165.0 (2026-11-19, with reservations: the
20 tasks it was handed were closed over two plans and a resume, no call took
longer than 3.6 s, 8 of the 20 verdicts were `undetermined`, and 9 of the 20
answers spoke of a summary or of code the subagent could not see). The Cursor
and VS Code Copilot recipes follow what those hosts document and have not yet
been run on them.

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
  `risk_score`, `diff_scans` (both modes), the dashboard, the scan
  resources and the release gates — only once an independent verify answer
  says `real`. Until then, and after a `not_real`, it is a candidate: the
  report lists it in a section of its own and no total counts it.
- **A file changed** between the plan and the answer: the task closes as
  `stale`, and its verdict demotes nothing.

The severity of a hunt finding comes from its class. Injection (SQL, NoSQL,
command, code, template), deserialization, XXE, SSRF, path traversal, broken
access control, authentication and secrets are `high`; every other class is
`medium`. A verdict decides whether a hunt finding counts, never its severity.

## The plan's scan record

Every plan writes one scan record of type `llm_scan`, completed as soon as the
plan starts: it is the `scan_id` of `start`'s answer, and a hunt's findings are
stored in it as its answers are accepted. What the record says it measured
decides how the project's history reads it.

**A verify-only plan** (no `hunt` in `modes`) analyses no code; its verdicts are
stored on the findings of the scan it checked. Its record is never "the latest
scan" and never a source of the open set: `report_export {}`, `set_baseline {}`,
`diff_scans` without ids (both modes), `risk_score`, `prioritize_findings` and
the dashboard answer as they would without it, and
`diff_scans { scan_type: "llm_scan" }` compares the two newest hunts that ran. Named as
the newer side of `diff_scans { from_scan_id, to_scan_id }`, it measured
nothing: the other side's findings are `not_remeasured`, never resolved. Named
as the older side, the newer scan's findings are new.

**`verify_source`.** The answer of `start` for a plan with `verify` in `modes`
says which input chose the findings and which scans they came from:
`{ from, scan_ids, scan_ids_total }`, with `from` one of `scan` (the `scan_id`
passed), `fingerprints` or `open_set`. `scan_ids` are the scans of the findings
that got a verify task when the plan was made, each once (at most 100 named; the
total is exact). It is kept in the plan record's metadata, so `start { plan_id }`
gives it again; a plan made before it existed, or whose record is gone, has no
`verify_source`. The `scan_id` of the answer stays the plan record's.

**A hunt plan's** record counts what was hunted: its hunt and cross-cutting
tasks with a valid answer, and its entry points. A task closed as not delivered
(a limit stopped delivery), or after its three invalid answers, does not count.

| Hunt and cross-cutting tasks with a valid answer | The record's coverage | How the history reads it |
| --- | --- | --- |
| none, or the plan has none | `none` | passed over like a scanner that did not run, and named in `skipped`; `set_baseline` refuses it |
| some — or all, with an entry point set aside or not visited | `partial` | the earlier hunts' confirmed findings stay open, `not_remeasured`, never resolved |
| all, and no entry point set aside or not visited | `full` | it resolves what it did not find again |

The verify tasks do not hold the record back — open, or closed stale, not
delivered or after three invalid answers — nor does a finding left out of a
full plan, nor a hunt by groups of code files in a project whose attack surface
has no entry points: the plan's own report may still say `partial` for each of
these, the record does not. It is brought up to date as answers are taken, when
delivery stops and when the plan's status is read; its finish date does not
move.

A record stays `partial` for good when one of its hunt or cross-cutting tasks
was closed as not delivered or after three invalid answers, or when an entry
point was set aside — and a route whose handler file is outside the project is
set aside by **every** hunt of that project, so none of them resolves anything
there. The earlier hunts' confirmed findings such a hunt does not find again
stay open, `not_remeasured`. The way out today is a verdict:
`llm_scan { step: "start", modes: ["verify"], fingerprints: [<the finding's fingerprint>] }`,
answered `not_real` by a fresh context, takes a hunt finding out of the open set.

So a hunt that was only started is passed over and named, and `risk_score` and
`prioritize_findings` say coverage `partial` until a later hunt answers every
task — for good, if none does. The findings of a hunt compared with one that
never ran are `not_previously_measured`, not new.

**What stays the same.** A record is still reached by its `scan_id`
(`report_export { scan_id }`, `diff_scans` by ids, `set_baseline { scan_id }`).
`health_status.last_scan` and `guardian://scans/latest` show the latest
activity, a plan's record included, and the dashboard can show a hunt that was
only started as its scan. A baseline already set on a verify-only record stays
(baselines are per scan type) and still reads: compared from it, the hunt's
findings are new. The CI gate (`scan`) reads the history another way and runs no
`llm_scan`.

**Records of earlier versions.** There is no migration. A verify-only plan's
record is recognised as it is read. A hunt's record said `full` from the plan's
start: the record of a plan still open is corrected the next time the plan is
read or answered, and the record of a plan that is no longer open — abandoned,
or complete after a limit stopped delivery — keeps saying `full`.

## Limits

| Limit | Value | When it is reached |
| --- | --- | --- |
| Tasks handed out per plan | `max_tasks`, default 200 | delivery stops with `limit_reached`; coverage `partial`, the undelivered tasks named |
| Estimated tokens | `max_estimated_tokens`, default 500 000 | above it the plan says `needs_confirm`, and nothing is handed out until `llm_scan { step: "start", plan_id, confirm: true }` |
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
`token_limit_note`. A plan's limits are fixed when it is made: to cover the
whole plan, start a new plan, without `plan_id`, with a larger
`max_estimated_tokens`. With `plan_id`, `start` takes only `project_path` and
`confirm`; any other parameter is refused with `invalid_input`. The estimate counts the host's own overhead per task
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
| `nothing_to_plan` | no finding with a file and line to verify, and nothing to hunt; with no `scan_id` the reason names the open set, which a scoped scan is never part of: pass its `scan_id` to verify it |
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
