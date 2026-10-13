# Plugin evals (maintainers)

Behaviour tests for the plugin's model-facing prose, run with Claude Code's `claude plugin eval`. The vitest suite
holds the prose to the code (tool names, parameters, sizes); these cases check what a model actually **does** with
it. They are maintainer-side and local only — no CI.

- **Triggering** (tag `triggering`): the right skill or command fires on a request in English, Portuguese or
  Spanish. The descriptions are English and intent-based; the PT / ES cases check that they still fire.
- **Negative** (tags `negative`, `near-miss`): nothing from dev-guardian fires on a request that only shares a word
  with a trigger ("log", "set up the project", "this smells bad", a GDPR fine, a general question).
- **Routing** (tag `routing`): a reported bug in a `.specs/` project goes to dev-spec-driven, which owns it.
- **Behavioural** (tag `behavior`): once a skill fires, the agent keeps the rules that matter most — a scanner
  that could not run is a gap, `db adopt` is the user's, `create_fix_pr` runs as a dry run first.

## Triggering and negative cases

| Case | Expects |
| --- | --- |
| `trigger-security-en` / `trigger-secrets-pt` | `guardian-security` or `/guardian-scan` on "is my code secure?" / a secret scan |
| `trigger-deps-es` | `guardian-deps` on "update the dependencies, any CVEs?" |
| `trigger-review-en` | `guardian-review` on "review my changes before I merge" |
| `trigger-quality-pt` | `guardian-quality` on "is this clean? much tech debt?" |
| `trigger-perf-es` | `guardian-performance` on a slow endpoint |
| `trigger-scanskill-en` | `guardian-scanskill` on "is this GitHub skill safe to install?" |
| `trigger-compliance-pt` | `guardian-compliance` on "does the code comply with GDPR? personal data in the logs?" |
| `trigger-bugfix-en` | `guardian-bugfix` or `/guardian-fix` on a bug hunt |
| `trigger-release-en` | `/guardian-release` on "we deploy tonight, can this go out?" — the one owner of that intent |
| `trigger-checkup-pt` | the `guardian` router on "full checkup" |
| `trigger-incident-es` | `/guardian-incident` (or the router) on "production is down" |
| `no-trigger-git-logs` | nothing on "show me the git log" (observability stays silent) |
| `no-trigger-vite` | nothing on "set up the project with Vite and React" (`/guardian-init` is user-started) |
| `no-trigger-smells-security` | the security scan stays silent on "this smells bad — rename these variables" |
| `no-trigger-legal-pt` | nothing on "what fine do I risk for breaching GDPR?" (a legal question) |
| `no-trigger-unrelated` | nothing on a general-knowledge question |

`g`, `guardian-grill`, `guardian-improve` and `guardian-init` are user-started (`disable-model-invocation`), so no
case expects them to fire.

## Routing and behavioural cases

| Case | Fixture (`fixture.sh`) | Graders — what the agent must (not) do |
| --- | --- | --- |
| `route-reported-bug-specs-en` | shop-app with dev-spec-driven's `.specs/` and a `checkout` feature, on `feat/checkout`; **both plugins** loaded | dev-spec-driven's skill or tools are reached · `src/cart.js` is not edited in this run (the fix waits for the bug.md approval) |
| `behavior-gap-not-clean-en` | shop-app: a `package.json` and no lockfile | a dependency scan runs · *(judge)* the reply names the gap, never "clean" |
| `behavior-no-db-adopt-en` | shop-app with a `.guardian/guardian.db` from before database ids (`storage_warning`) | `health_status` · no shell command runs `db adopt` · *(judge)* the command is handed to the user |
| `behavior-fixpr-dry-run-en` | shop-app on `main`, no scans yet | `create_fix_pr` is called · never with `apply: true` |

`fixture.sh` sources `fixtures/lib.sh` and copies `fixtures/shop-app/` (a small Express app whose `orderTotal`
calls `reduce` with no initial value — a TypeError on an empty cart). Its manifest is stored as
`package.json.fixture` and renamed on copy, so this repository carries no vulnerable `package.json` of its own. The routing case builds `.specs/` with
dev-spec-driven's own CLI from the sibling checkout `../dev-spec-driven` (next to this repository) and loads that
checkout as a second plugin (`plugins: ["../..", "../../../dev-spec-driven"]`); without it the scaffold fails and
says why.

## Run (local only)

```bash
# Triggering + negative (cheap: 4 turns, only the Skill tool)
claude plugin eval . --ablation none --tag triggering negative --trust-plugin --no-publish --max-cost-usd 6

# Behavioural — fixtures, the real MCP server (mcp/dist/server.js) and write tools
claude plugin eval . --ablation none --tag behavior --scaffold --allow-real-servers --trust-plugin --no-publish \
  --allow-tools Write Edit "mcp__plugin_dev-guardian_dev-guardian__*" --max-cost-usd 6 -j 2

# Routing — both plugins (needs ../dev-spec-driven)
claude plugin eval . --ablation none --tag routing --scaffold --allow-real-servers --trust-plugin --no-publish \
  --allow-tools Write Edit "mcp__plugin_dev-guardian_dev-guardian__*" "mcp__plugin_dev-spec-driven_spec-driven__*" \
  --max-cost-usd 4
```

- `--ablation none` matters: the default adds a no-plugin baseline arm, under which `tool_used: Skill` graders stop
  counting toward the score.
- No shell is granted (the harness refuses Bash / PowerShell without its OS sandbox, which native Windows lacks):
  the cases are written for a shell-less agent. `behavior-no-db-adopt-en`'s command grader only bites where a
  shell is granted (macOS / Linux / WSL2, `--allow-tools "Bash(*)"`); its judge grader holds everywhere.
- The behavioural cases scan for real: Semgrep, Trivy and gitleaks are used when installed, and their absence is
  part of what `behavior-gap-not-clean-en` grades. A scan can take a few minutes (`timeout_seconds: 420`).
- Results land in `evals/results/` (git-ignored).

When you change a skill's or a command's `description`, add a case for any new trigger or exclusion before relying
on it, and keep the near-miss cases passing.
