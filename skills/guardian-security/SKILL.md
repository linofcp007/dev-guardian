---
name: guardian-security
description: Whole-project security scan with real-severity triage — SAST, secrets, dependency CVEs, IaC and containers, optional DAST and reachability. Use for "is my code secure?" or a vulnerability or secret scan. Not for a pending diff (guardian-review) or code smells (guardian-quality).
---

# Guardian Security

A deep security scan that correlates the scanners' findings, demotes the obvious false positives and
ranks by real risk — rather than dumping raw tool output. Respond in the user's language.

## What runs

| Kind | Finds | MCP tool |
| --- | --- | --- |
| SAST | application code flaws | `scan_sast` (Semgrep; Bandit for Python; gosec for Go; cppcheck for C/C++; the SDK analyzers for .NET) |
| Secrets | keys, tokens, passwords in the code and the git history | `scan_secrets` (gitleaks) |
| Dependencies | CVEs in libraries | `scan_deps` (Trivy); `deps_audit` adds npm audit / pip-audit / govulncheck |
| Containers / IaC | Dockerfile, image, compose, Terraform, Kubernetes, Helm | `scan_containers` (Trivy + hadolint; cosign for the image signature), `scan_iac` (Trivy) |
| DAST (optional) | a running app, probed at runtime | `scan_dast` (+ nuclei) |

No Brakeman, CodeQL or Checkov run — never claim them.

## Flow

### 1. Prerequisites

`check_toolchain {}` lists each scanner's version, known-compromised versions and this system's install
command. If something is missing, `install_toolchain { dry_run: true }` shows the plan; a project with no
dev-guardian configs yet starts with `/guardian-init` — suggest it; the user runs it.

### 2. Scan

Run the full scan — don't ask which kind first: `security_scan_full { project_path: "<project>" }`. It runs
`scan_sast`, `scan_secrets`, `scan_deps` and `scan_iac`, each as its own scan (`meta.parent_scan_id`), and
stores the merged findings on the parent, listing the children in `child_scans`. A scanner that did not run
or failed shows in `tools_run` and makes coverage `partial` / `none` — never a clean "0 findings".

- Only part of the project (the diff, a branch, a file): `/guardian-scan` and its flags pass `scope` to
  `scan_sast`, `scan_secrets` and `bug_hunt`.
- Semgrep's registry mode, the default, sends usage metrics to Semgrep Inc. (it cannot run with
  `--metrics=off`). `local_only: true` avoids it: rules on disk only — the project's `.semgrep.yml`, rules
  registered with `register_custom_rules` and the plugin's LLM pack — with fewer rules; without project rules
  that part is reported as skipped, not clean. Trivy's database and a .NET restore still reach the network.
- Every `scan_sast` run (and so `security_scan_full` and `review_pr`), `local_only` or not, also runs the
  plugin's LLM-application pack for Python and JS/TS: model output reaching `eval` / `exec`, a shell or SQL;
  a model-chosen tool name used without an allow-list; `trust_remote_code=True` without a pinned revision;
  unsafe `torch.load`; HTTP request data in the system prompt; OpenAI calls with no token limit. Findings are
  `security` with an `llm-*` subcategory and the OWASP Top 10 for LLM category. It does not see prompt
  injection through documents or tool results, model output with other side effects, quotas or unbounded
  agent loops — `guardian-review`'s AI checklist covers those by reading.
- No MCP server at all? [`references/manual-fallback.md`](references/manual-fallback.md) has the raw
  commands, and the user must hear that there is then no baseline, delta or history.

### 3. Triage

Never dump the raw results. For each finding:

1. **Real severity** (not the CVSS alone):
   - 🔴 Critical — RCE, SQL injection, a live production secret, auth bypass
   - 🟡 High — XSS / CSRF / SSRF, a CVE with a public PoC, a vulnerable dependency with no patch
   - 🟢 Medium — residual-risk smells, secrets in test or example files
   - ℹ️ Low / Info — best practice, likely false positives
2. **Demote common false positives**: secrets under `examples/`, `*test*`, `fixtures/`, `*.md` → Low (still
   mention them); CVEs in dev / test dependencies → one level down; a Semgrep rule known to be noisy in this
   context → say so; `console.log` / `print` of data → Info.
3. **Correlate** across scanners: Semgrep's "use of crypto X" plus Trivy's CVE in library X is one problem
   with more weight, not two.

### 4. Report

Highest priority first:

```markdown
# Security report — <project>
<date> · <duration> · <files scanned>

## 🔴 Critical (N) — blocks deploy
### 1. Exposed secret: AWS access key
- File: src/config/aws.js:14 — key AKIA… committed 3 days ago (commit abc123)
- Now: revoke it in the AWS console; remove it from history (`git filter-repo --invert-paths --path src/config/aws.js`); move it to an environment variable; treat it as compromised

## 🟡 High (N) — fix before release
## 🟢 Medium (N) — backlog, grouped by category
## ℹ️ Demoted as likely false positives (N) — expand on request
```

### 5. Offer fixes

For obvious, reversible fixes, offer to apply — always showing the diff and asking first:

- Dependency upgrades with a fixed version: `/guardian-fix --pr` (`create_fix_pr` with `sources: ["deps"]`,
  a dry run first) — applies `deps_update_plan`'s plan in an isolated worktree, proved by a re-scan and the tests.
- Autofixes the Semgrep rule itself ships: `/guardian-fix --pr` (`sources: ["semgrep"]`).
- Code changes (`crypto.createCipher` → `crypto.createCipheriv`), a secret moved to `.env`, `.env.example` and
  `.gitignore`.

In an emergency — a live production key exposed — interrupt and say so plainly: "⛔ STOP — this key looks live
and in production. Revoke it now: <the provider's revocation page>. Then we fix the rest."

## Paranoid mode

Only when the user asks for "paranoid" or "full deep":

- Secrets in the history of every ref: `scan_secrets { project_path: "<project>", log_opts: "--all" }`.
- Is a found secret still valid? `scan_secrets { project_path: "<project>", verify_live: true }` sends each
  GitHub, GitLab, Slack, Stripe, OpenAI, Anthropic, npm or SendGrid secret to that provider's own read API
  (nowhere else) and marks it `live` (raised to critical), `revoked` or `unknown`. The secret leaves the
  machine: ask the user first. `security_scan_full` never verifies; `unknown` never means revoked.
- Per-language Semgrep security packs: `bug_hunt { project_path: "<project>", include_language_packs: true }`.
- No `severity_min`: show the medium and low findings too.
- Stricter configs: `init_project { project_path: "<project>", profile: "paranoid", apply: false }` shows what
  would change.
- Licences: `compliance_check { project_path: "<project>" }`, then `license_compatibility { project_path: "<project>" }`.
- A quick STRIDE pass over the entry points `map_attack_surface` finds (your reasoning — no tool does it).
- DAST, if the app is a web app and is running.

## On request

- **DAST** ("DAST scan", "pen test the running app"): [`references/dast.md`](references/dast.md) —
  `map_attack_surface`, then `scan_dast` against an app that is already running.
- **Is this finding reachable?** [`references/reachability.md`](references/reachability.md) —
  `validate_finding`, context for the triage, never a reason to suppress.
- **Are the project's MCP servers safe?** [`references/mcp-servers.md`](references/mcp-servers.md) —
  `audit_agent_config` reads; `audit_mcp_tools` starts the servers the user names.
- **Have a model verify the findings, or hunt what the scanners miss:**
  [`references/llm-scan.md`](references/llm-scan.md) — `llm_scan` (`step`: start, task, submit).

## When not to run a full scan

- A trivial 1–2 line commit: the pre-commit hooks are enough.
- An experimental / spike branch: warn that the results may be noise.
- A huge monorepo: offer `/guardian-scan --branch` (only the diff against the base branch).

## History

Every scan is stored in `.guardian/guardian.db`, raw reports in `.guardian/reports/`. To measure progress,
`diff_scans { project_path: "<project>", from: "baseline" }` and `/guardian-report trend` — never compare JSON
files by hand. A finding under an active suppression is counted apart (`suppressed_findings`,
`summary.suppressed`), never as resolved. Each `tools_run` entry names the project files that decided part of
the scan (`honoured_config`: `.trivyignore`, `.gitleaks.toml`, `.gitleaksignore`, `.bandit`, `.semgrepignore`,
`.guardianignore`) and what `.trivyignore` suppressed (`suppressed_by_repo_config`) — tell the user when one
of them weighs on the result.
