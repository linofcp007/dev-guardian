# The model-facing prose — skills, commands, rules files, evals

> Maintainer notes. Not loaded into sessions: read this file before you change a skill, a command, a description,
> the host rules template or the eval suite.

Everything here is read by a model as an instruction, and most of it costs context in every session. Keep it to
what the model needs **now**; history goes to `CHANGELOG.md` and the rule packs' comments.

## Budgets (tested)

| Surface | Budget | Test |
| --- | --- | --- |
| A skill's `description` | ≤ 300 characters: what it does, when, and "Not for …" (the overlapping intent and its owner) | `descriptionLimits.test.ts` |
| A command's `description` | ≤ 100 characters | same |
| The listing — every model-invocable entry's name + description | ≤ 4 000 characters in all | same |
| `SKILL.md` | ≤ 12 KB; the router ≤ 6 KB, `guardian-bugfix` ≤ 8 KB, `guardian-security` ≤ 10 KB | same |
| `skills/<name>/references/*.md` | ≤ 6 KB each, and linked from its `SKILL.md` | same |
| `host-rules/AGENTS.md` (the rendered body) | ≤ 8 000 bytes — Codex reads 32 KiB of AGENTS.md in all, dev-spec-driven's block included | `hostRulesDrift.test.ts` |
| The Windsurf rule | ≤ 11 000 characters — Windsurf truncates at 12 000 | same |

When a number is about to break, move what only some runs need into the skill's `references/` (the model reads it
on demand), or into `docs/`. Never raise a budget to fit.

## Descriptions and invocation

- One owner per intent, and the description of every overlapping skill says "Not for X (owner)": a deploy go /
  no-go is `/guardian-release`; a diff before a merge is `guardian-review`; "is my code secure?" is
  `guardian-security`; smells are `guardian-quality`; licences and SBOM are `guardian-compliance`; a bug reported
  in a `.specs/` project is dev-spec-driven's.
- The descriptions are English and intent-based — Claude matches a PT / ES request against them; no per-language
  trigger lists. "Respond in the user's language" is said once, in each body (tested), never in a description.
- `g`, `guardian-grill`, `guardian-improve` and `guardian-init` are user-started (`disable-model-invocation:
  true`); prose that points at them tells the user to run the slash command.

## Bodies

- New and rewritten skill bodies and references are English; the older ones are European Portuguese (AO90,
  accented — `ptPtSpelling.test.ts`). Commands and the rules template are English.
- No release history in an instruction: no dev-guardian version number, no "before 3.1", no "earlier versions
  said" (`versionHistory.test.ts`). Data version numbers pass (`lodash@4.17.20`, `>= 22.13`, `SARIF 2.1.0`,
  `dev-spec-driven 1.29+`). Its `KNOWN` list (tool descriptions the tool-description pass rewrites) only shrinks.
- Every tool call written as `tool { key: … }` is checked against the registered schema, and every tool must be
  named by a skill, a reference or a command and by the rules template (`docReferences.test.ts`,
  `toolReach.test.ts`).
- A CLI line the model gives the user is runnable: `node "<plugin root>/cli/dev-guardian.mjs" …`
  (`${CLAUDE_PLUGIN_ROOT}` in a command), or `node .specs/guardian.cjs …` from a dev-spec-driven project — a plugin
  install puts no `dev-guardian` on `PATH`.
- Never advise `baseline update` to accept one finding: it accepts every current finding. One reviewed finding
  takes an inline suppression with a reason, or a baseline rebuilt on the base commit.

## dev-spec-driven

The sibling plugin owns a feature's lifecycle in a `.specs/` project. `guardian-review`, `guardian-grill` and
`guardian-bugfix` call `spec_next_action` first there; the review's verdict covers security and quality and points
to `/spec-finish`; requirements are grilled with `/clarify --grill`; a reported bug goes to `/spec-bugfix`, with
`bug_hunt` as its reproduce-and-isolate tool. `guardian-improve` lists the backlog first, reuses exact names (≤ 6
words, no numbers; metrics in the note) and replaces a note (`rm`, then `add`). The finish gate is named with
"dev-spec-driven 1.29+". Every dev-spec-driven name the prose cites is held to `devSpecNames.ts`
(`devSpecNames.test.ts`); juridico-pt's to `juridicoPtNames.test.ts`.

## Plugin evals (`evals/`)

`claude plugin eval` cases — triggering (EN / PT / ES), near-misses, a two-plugin routing case and behavioural
cases with fixtures. `evals/README.md` has the cases and the run lines; `evalSuite.test.ts` holds the suite to
the plugin offline (grader types, compiling patterns, real names, no user-started skill expected to fire). When you
change a description, add a case for a new trigger or exclusion, and run the triggering suite before relying on it.
