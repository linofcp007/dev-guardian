---
name: guardian
description: dev-guardian's router — a full project checkup (security, bugs, quality, dependencies, compliance) or the right dev-guardian command when it is unclear which fits; also "production is down", "we leaked a key", "project health". Not for one clear task another guardian skill owns.
---

# Guardian — router

Route the request to the right command or skill. Respond in the user's language (EN, PT or ES); keep terms
such as SAST, CVE or secrets in English.

## Invariants

1. **Use the dev-guardian MCP tools**, never a scanner run by hand: they keep baselines, deltas, suppressions and
   history in `.guardian/guardian.db`. A raw scanner run is only the fallback when the MCP server is down — say so.
   A scanner that did not run is a gap, never "0 findings".
2. **Fix only with confirmation**, showing the diff — except a live secret, which you flag at once.
3. **Never run `db adopt` yourself.** On a `storage_warning` (the project's `.guardian/guardian.db` is not used),
   tell the user and give them the command to run in their own terminal:
   [`references/storage.md`](references/storage.md).

## Commands

| Command | Modes / arguments | What it does |
| --- | --- | --- |
| `/guardian-scan` | none, `--staged`, `--uncommitted`, `--unpushed`, `--branch`, `--since`, `--incoming`, paths | Security scan, whole or only what changed |
| `/guardian-fix` | hint, fingerprint, `--pr [--apply]`, `--verify` | Find and fix bugs, scanner fixes as PRs, prove a fix |
| `/guardian-report` | `exec`, `handoff`, `trend`, `debt`, `changelog`, `soc2` | Reports from the scans and the history |
| `/guardian-incident` | `panic`, `leak`, `rollback`, `postmortem` | Incident response |
| `/guardian-release` | `predeploy`, `prerelease` | Go / no-go before a deploy or a release |
| `/guardian-status` | — | One-page health dashboard |
| `/guardian-infra` | `docker`, `iac` | Containers and IaC |
| `/guardian-wp` | path or URL | WordPress audit |
| `/guardian-dotnet` | path | C# / .NET audit |
| `/g` | — | Shortcut to this router |

## Skills

| Skill | When |
| --- | --- |
| `guardian-security` | "is my code secure?" — whole-project scan and triage |
| `guardian-bugfix` | find unknown bugs, reproduce → isolate → fix |
| `guardian-review` | review pending changes before a PR or merge |
| `guardian-quality` | smells, complexity, duplication, tech debt, budgets |
| `guardian-deps` | CVEs, upgrades, vetting a package, Renovate |
| `guardian-compliance` | GDPR in the code, licences, SBOM, audit evidence |
| `guardian-performance` | slow pages and endpoints, Lighthouse, k6 |
| `guardian-observability` | logging, metrics, error tracking, alerts |
| `guardian-scanskill` | vet a third-party skill / MCP server / plugin before installing |
| `/guardian-init` | first setup in a project (user-started, as the next two) |
| `/guardian-grill` | the human explains the diff's decisions before merge |
| `/guardian-improve` | measured debt → dev-spec-driven improvement specs |

## Workflow moments

| The user says | Route to |
| --- | --- |
| "before push" | `/guardian-scan --unpushed` |
| "check my diff" / "scan this branch" | `/guardian-scan --staged`, `--uncommitted` or `--branch` |
| "what changed since v1.2?" | `/guardian-scan --since v1.2`, then `/guardian-report changelog` |
| "I pulled main" / "check this file" | `/guardian-scan --incoming` / `/guardian-scan <file>` |
| "before the PR / merge" | `guardian-review`; for the domain decisions, `/guardian-grill` |
| "close this feature" in a `.specs/` project | dev-spec-driven's `/spec-finish` — see [`references/dev-spec.md`](references/dev-spec.md) |
| "can I install X?" / "adding this dependency" | `vet_packages { ecosystem: "npm", packages: ["X"] }` before the install (`guardian-deps`) |
| "I just installed deps" | `guardian-deps` (post-install) |
| "fixed it, confirm" | `/guardian-fix --verify` |
| "before deploy" / "can this go to production?" | `/guardian-release predeploy` |
| "before the release / tag" | `/guardian-release prerelease` |
| "production is down" / "a secret leaked" | `/guardian-incident panic` / `leak` |
| "is a rollback safe?" / "post-mortem" | `/guardian-incident rollback` / `postmortem` |
| "handing the project over" / "are we improving?" | `/guardian-report handoff` / `trend` |
| "how much tech debt?" | `/guardian-report debt`, then `/guardian-improve` |
| "within budget?" | `guardian-quality` and `guardian-performance` |
| "executive report" / "SOC 2 evidence" | `/guardian-report exec` / `soc2` |
| "check the Dockerfile / Terraform" | `/guardian-infra docker` / `iac` |
| "is the agent config / `.mcp.json` safe?" | `audit_agent_config { project_path: "<project>" }` |
| "are MCP server X's tools safe?" | `guardian-security` → `audit_mcp_tools { servers: ["X"] }` (it starts X) |
| "have a model verify the findings" | `guardian-security` → `llm_scan_start` |
| AI / LLM features in the app | `/guardian-scan` — see [`references/llm-apps.md`](references/llm-apps.md) |

When the request is ambiguous, ask one short question — never assume silently.

## Full checkup

"Full checkup", "check everything", "audit the project": `audit_executive { project_path: "<project>" }`
(security, quality, dependencies, compliance — stack-aware) plus `bug_hunt { project_path: "<project>" }`, in
one consolidated report. `local_only: true` keeps Semgrep on the rules on disk (and skips `scan_wordpress`);
Trivy, `deps_audit` and a .NET restore still reach the network — the result lists them in `local_only_gaps`.

## General flow

1. `detect_stack { project_path: "<project>" }` (stacks and scanners: [`references/stacks.md`](references/stacks.md)).
2. Respect what is already configured (`.semgrep.yml`, `.gitleaks.toml`, `renovate.json`, `.pre-commit-config.yaml`).
3. Route (tables above).
4. Report by priority — 🔴 blocks deploy / merge · 🟡 fix before release · 🟢 backlog · ℹ️ info — and offer
   the fix (`/guardian-fix`), with confirmation.

No scan for a design chat with no code, a project that does not exist yet, or "explain this file".
