# Working with dev-spec-driven

In a project with a `.specs/` folder, dev-spec-driven owns the feature's lifecycle: its requirements, its tasks
and closing it. dev-guardian answers the security and quality half.

- **Where the feature stands.** `spec_next_action { name: "<feature>" }` for the feature the current branch
  implements (`spec_status {}` lists them) — before a review, a grill or a bug fix on that branch.
- **Reviewing a diff.** `guardian-review`'s verdict covers security and quality only. Closing the feature is
  dev-spec-driven's `/spec-finish`, which runs the project's checks — dev-guardian's gate among them when it is on.
- **Grilling the requirements** (before there is a diff) is dev-spec-driven's `/clarify --grill`; `/guardian-grill`
  grills a diff.
- **A reported bug** goes to `/spec-bugfix`; `bug_hunt` is its reproduce-and-isolate tool.

## The finish gate (dev-spec-driven 1.29+)

dev-spec-driven 1.29 or later can run dev-guardian's gate as a project check: `spec_init { guardian: true }` in a
session, or `node "<dev-spec-driven plugin root>/cli/dev-spec.js" init --guardian` in a terminal. It runs
`scan --fail-on high` against the committed `.guardian/baseline.json`: only a finding new to the baseline, at
`high` or above, blocks the finish, and exit 2 is an incomplete scan — never a pass. From that project the
runnable line is `node .specs/guardian.cjs <arguments>` (the launcher forwards every argument); elsewhere,
`node "<plugin root>/cli/dev-guardian.mjs" <arguments>` — a plugin install puts no `dev-guardian` on `PATH`.

Record the baseline on the base branch, before the feature's code, when the check is turned on:
`node .specs/guardian.cjs baseline update --project .`, then commit `.guardian/baseline.json`. That is the
user's decision, not yours.

When the gate blocks, show the finding. To accept **one** reviewed finding, use a suppression its scanner reads,
with a reason — `nosemgrep: <rule> -- <reason>`, `# nosec`, a `.trivyignore` or `.gitleaksignore` entry, reviewed
like code — or rebuild the baseline on the base commit. **Never `baseline update` to accept one finding**: it
accepts every current finding, the feature's own included. Never force the finish past the gate. A
`suppress_finding` does not reach it: the gate's `scan` works in a throwaway database.
