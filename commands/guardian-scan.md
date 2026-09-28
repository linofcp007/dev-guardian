---
description: Security scan — the whole project, or only what changed (staged, uncommitted, unpushed, branch, since a ref, incoming) or given paths. Scan de segurança. Escaneo de seguridad.
argument-hint: "[--staged | --uncommitted | --unpushed | --branch [base] | --since <ref> | --incoming | <path>…]"
---

Run a Guardian security pass. With no argument it scans the whole project; with a flag or paths it scans only that part, so it finishes in seconds. Every run is persisted in `.guardian/guardian.db` (baselines, deltas, suppressions) — never shell out to Semgrep, gitleaks or Trivy directly.

Arguments: $ARGUMENTS

## 1. Pick the mode

| Argument | What gets scanned | `scope` for the scan tools |
| --- | --- | --- |
| *(none)* | the whole project | none — use section 2 |
| `--staged` | the files staged in the index | `{ diff: { staged: true } }` |
| `--uncommitted` | every uncommitted change: staged, unstaged, untracked | `{ diff: {} }` |
| `--unpushed` | the commits not on the upstream branch yet | `{ diff: { base: "@{upstream}" } }` |
| `--branch [base]` | this branch against its base (default: the remote's default branch, `origin/<default>`) | `{ diff: { base: "<base>" } }` |
| `--since <ref>` | what changed since a tag, a SHA or a date (`2026-01-31`, `2 weeks ago`, `yesterday`) | `{ since: "<ref>" }` |
| `--incoming` | what the last pull or merge brought in | `{ diff: { base: "HEAD@{1}" } }` |
| `<path>…` | those files, directories or globs | `{ paths: ["<path>"] }` |

Resolve the refs before calling anything:

- `--branch` with no base: the remote's default branch, `git symbolic-ref --short refs/remotes/origin/HEAD` (for example `origin/main`) — prefer the remote-tracking ref, because a local `main` can be stale or missing. Without `origin/HEAD`, try `origin/main`, then `origin/master`, and only then a local `main` / `master` (`git rev-parse --verify --quiet <ref>` tells which exist). A base the user names is used as given. On the default branch itself there is no branch diff — say so and offer `--unpushed` or a full scan.
- `--unpushed`: `git rev-parse --abbrev-ref @{upstream}` must name a branch. With no upstream, say so and offer `--branch`.
- `--since` with no value: the last tag, `git describe --tags --abbrev=0`.
- `--incoming`: show `git log --oneline HEAD@{1}..HEAD` first — `HEAD@{1}` is where HEAD was before the last pull, merge or checkout, so confirm with the user when the reflog says otherwise.
- `project_path` is always the project root; a file goes in `scope.paths`, never in `project_path`.

## 2. Whole project (no argument)

Call `security_scan_full { project_path: "<project>" }`. It runs `scan_sast`, `scan_secrets` (git history and uncommitted files), `scan_deps` and `scan_iac` as child scans and returns their merged findings. Add `local_only: true` when nothing may leave the machine (the Semgrep registry sends usage metrics otherwise), and `severity_min: "high"` only to shorten the response — every finding is still recorded.

## 3. A scoped scan (any flag or path)

Call these three with the same `scope`:

1. `scan_sast { project_path: "<project>", scope: <scope> }`
2. `scan_secrets { project_path: "<project>", scope: <scope> }` — for `diff.base` and `since` it reads exactly those commits, not all history.
3. `bug_hunt { project_path: "<project>", scope: <scope> }`

Also, for `<path>…`: `quality_check { project_path: "<project>", scope: <scope> }`.

When the change set touches a dependency manifest or lock file, add `scan_deps { project_path: "<project>", packages: ["<added or bumped package>"] }` — Trivy reads the whole project, and the response is narrowed to those packages (`package_filter.not_found` names any it had nothing on).

A scoped scan is recorded with `meta.scope`: it never becomes a baseline and never replaces a whole-project scan in the open findings. Its silence about files outside the scope says nothing about them.

Per mode, on top of the scans:

- `--unpushed`: if anything is 🔴, ask whether to abort the push before it happens.
- `--incoming`: list the new commits per author, call out anything under security-sensitive paths (auth, payments, crypto, env handling, migrations), and mark bot authors (`dependabot[bot]`, `renovate[bot]`) — code nobody reviewed deserves a closer read. Offer `create_github_issues { project_path: "<project>", dry_run: true }` for the 🔴 / 🟡 findings.
- More than ~50 changed files: suggest a full review with the `guardian-review` skill instead.

## 4. Is a found secret still live?

Only when the user asks, or a secret was found and they want to know how urgent it is: `scan_secrets { project_path: "<project>", verify_live: true }` (add the same `scope` for a scoped run). It sends each GitHub, GitLab, Slack, Stripe, OpenAI, Anthropic, npm or SendGrid secret to that provider's own read-only API — and nowhere else — and marks the finding `live` (raised to critical, with where to revoke it), `revoked` or `unknown`. It is **off by default** because the secret leaves the machine: say so before turning it on. `security_scan_full` never verifies, `GUARDIAN_OFFLINE=1` sends nothing, and `unknown` is never "revoked".

## 5. Report

Triage with the `guardian-security` skill's rules (real severity, false-positive demotion, correlation across scanners), then show:

- 🔴 Critical / 🟡 High / 🟢 Medium-Low / ℹ️ Info counts and the top findings with `file:line`;
- coverage: a scanner in `tools_run` that was `skipped` or `failed`, or `missing_tools`, means the result is partial — say which scanner and what it leaves out, never "0 findings";
- `exclusions` when the project has a `.guardianignore`.

Offer `/guardian-fix` for the fixable ones. Never apply a fix without confirmation.

Respond in the user's language (EN/PT/ES).
