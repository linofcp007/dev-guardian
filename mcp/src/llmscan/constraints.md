# llm-scan: threat model checked against the code

The design's STRIDE model (`.specs/llm-scan/design.md`, "[SEC] Modelo de
Ameaças") read against what shipped. Each row names the code that holds the
line and the test that fails if it stops holding. Reviewed for task 8 on
2026-10-08, at commit `22184267` plus the task 8 changes.

**Trust boundaries.** The scanned repository flows to the server as excerpts.
The server sends briefs to the host's model. The model sends submissions back
to the server. All three are untrusted: the repository can hold text aimed at
the model, and the model can be steered by it.

## STRIDE

| Threat | What stops it | Code | Test |
| --- | --- | --- | --- |
| **Spoofing:** a submission for another plan's task, or for a task someone else holds | `plan_id`, `task_id` and the lease token must all match, with no hint which one did not. Every lease is a fresh `randomUUID`. Every write to a task is guarded by `lease_token = ? AND status = 'leased'`. | `service.ts#submitAnswer`, `llmScanRepo.ts` (`claimTask`, `closeTask`, `recordInvalidSubmission`, `releaseLease`) | T-32; `llmScanRepo.test.ts` (two `Storage` instances on one file) |
| **Tampering:** instructions planted in the analysed code | The excerpt sits between two copies of a random 24-hex boundary, redrawn if the data contains it. The brief says everything inside is data. The answer must match a closed schema. Every `file:line` it cites is checked on disk. | `briefs.ts` (`randomBoundary`, `renderBrief`), `submission.ts` | T-02, T-16 (text aimed at the model is judged on its citations only); adversarial evals A-I (task 11) |
| **Tampering:** model output acted on | Nothing in a submission is executed, opened or followed, except the contained `file:line` reads. A sampled reply goes only to the same validator, and a retry prompt quotes validator errors only. | `submission.ts`, `sampling.ts#payloadOf` | T-16; `llmScanSampling.test.ts` |
| **Tampering:** model text rendered as markup in a report | The markdown report puts model-written text on one line, escapes markdown and HTML and caps the length (`mdInline`). The HTML report escapes everything. | `tools/reportExport.ts` | `llmScanCounting.test.ts` |
| **Tampering:** an unconfirmed hunt finding moving a gate | An `llm-hunt` finding counts only with an INDEPENDENT `exploitable` verdict. This holds in the open set and in every path that reads a scan's rows directly: `regression_alert`, `diff_scans`, the dashboard deltas, `guardian://scans/{id}` and `report_export`. | `history/openSet.ts` (`splitHuntCandidates`, `countableFindings`) | T-21; `llmScanCounting.test.ts` |
| **Repudiation:** a verdict nobody can trace | Each task records the prompt version, the declared independence, attempts, delivery and close times, the close reason, and brief and answer sizes. Each verdict row carries the prompt version and independence. | `llmScanRepo.ts`, `submission.ts#toFindingValidation` | T-05, T-31 |
| **Repudiation:** a host claiming independence it did not have | Independence is declared, and only `sampling` proves it. A `same_context` verdict is shown but never demotes or confirms. The host recipe says to declare honestly. | `history/openSet.ts` (`isDemoting`, `isConfirming`), `hostsetup/rulesTemplate.ts` | T-07, T-25 |
| **Information disclosure:** a secret in an excerpt | The existing detectors (`scanForSecrets`) replace each line holding a secret with `‹rule line n›`, in the excerpt, the message, the snippet and the listed findings, before anything reaches a brief. | `briefs.ts` | T-13 |
| **Information disclosure:** file content in an error | Validation errors are fixed phrases plus field paths. An unknown key never enters a path, and is named in the problem only when it is a short identifier. A sampling failure reports a coarse kind, never the client's message. | `submission.ts`, `sampling.ts#failureOf` | `submissionBounds.test.ts` ("error paths never reproduce submitted text") |
| **Denial of service:** oversized or endless input | A submission over 64 KiB is refused before anything else. A hunt is held to 50 findings and 100 distinct cited files, each read once with a 1 MiB cap. Briefs are held to 20 000 tokens for the host (25 000 for any response). There are at most 5 active plans per project, 1 000 planned tasks, `max_tasks` and `max_estimated_tokens` on delivery, and 3 invalid answers per task. | `submission.ts`, `briefs.ts`, `service.ts`, `tools/responseBounds.ts` | T-15, T-23, T-27, T-29, T-30; `submissionBounds.test.ts`, `planLimits.test.ts` |
| **Denial of service:** a tool call past the host's 60 s | Sampling counts its 50 s budget from the tool's entry. No request or retry starts past it. A task cut short gives its lease back. | `sampling.ts` | T-27; `llmScanSampling.test.ts` |
| **Denial of service:** abandoned plans blocking new ones | A plan inactive for 7 days stops counting toward the limit. Retention abandons it at 30 days, and it then stops protecting its scan (D-2). | `llmScanRepo.ts` (`PLAN_INACTIVE_DAYS`, `PLAN_ABANDON_DAYS`, `abandonStalePlans`), `storage/maintenance.ts` | T-28; `llmScanRepo.test.ts` |
| **Elevation of privilege:** a path out of the project | A cited path is judged lexically before any read: absolute paths, drives, UNC, `..` after normalisation, NUL, `:` (alternate data streams) and Windows device names are rejected unread. Inside the root it is read only through `readProjectText`, which refuses a link out of the project. | `submission.ts#containedPath`, `platform/projectFs.ts` | T-14 (including a junction out of the project), `submissionBounds.test.ts` ("Windows spellings are never read") |

## Constraints (NFR-1, NFR-3, NFR-4)

- **No model provider, no key, no network (NFR-1).** No file in `src/llmscan/`
  or the three tools imports a provider SDK, an agent framework or a network
  module, calls `fetch`, or reads a key from the environment. Sampling goes
  through the MCP client's `createMessage`, never to a provider. Tested by
  T-34.
- **No new runtime dependency (NFR-1).** `package.json` still has exactly the
  five runtime dependencies. Tested by T-34.
- **Tool descriptions of at most 1500 characters (NFR-3).** Tested by T-34
  and `descriptionLimits.test.ts`.
- **Versioned prompt templates with their provenance (NFR-4).** Each file in
  `configs/llm-scan/prompts/v1/` opens with
  `<!-- provenance: written from .specs/llm-scan (D-1) -->`. The renderer
  strips that line, so the model never sees it and the prompt is unchanged.
  Tested by T-34.

## dev-guardian on its own new code

- `scan_secrets` (gitleaks 8.30.1) found 0 findings in 19 files, with full
  coverage. Scope: `mcp/src/llmscan/`, the three tools, `llmScanRepo.ts`,
  migration 017, `openSet.ts`, `reportExport.ts`, `triageFindings.ts` and
  `configs/llm-scan/`.
- `scan_sast` ran in its default mode: registry rules plus the plugin's
  `web-js.yml` and `llm.yml`, with Semgrep 1.176.1. It covered the 16 code
  files above with full coverage. It found 12 findings, all
  `web-js-sql-template`, all in `storage/llmScanRepo.ts`, and all false
  positives. Each one interpolates a module constant of fixed SQL text
  (`PLAN_COLUMNS`, `TASK_COLUMNS`, `LEASABLE_SQL`), and every value goes as
  a bound parameter. The same rule flags 31 more sites of the same kind
  elsewhere in `mcp/src/storage/`. That is a precision question for the
  `web-js` pack (its US-1.AC-2 exempts only a choice between literals), not
  a defect here.
- `bug_hunt` (the plugin's bug-class packs) covered the same 16 files with
  full coverage and found 0 findings.
- `scan_sast` with `local_only: true` reports `skipped`. This repo has no
  Semgrep rules of its own, and the tool refuses to call that clean.

## Residual risk

- **Declared independence.** Independence is declared by the host and proven
  only for sampling. A host that claims `subagent` for its own answer corrupts
  the report. The report shows the split, and the recipe asks for honesty.
- **A steered verdict inside the schema.** A model steered by the repository
  can still give a wrong verdict within the schema. Two things contain this.
  The adversarial evals measure it (task 11). A `not_exploitable` demotes a
  finding and never suppresses or deletes it.
- **Secrets the detectors miss.** A secret the existing detectors do not
  recognise reaches the brief, as it reaches the host whenever the host reads
  the file itself.
