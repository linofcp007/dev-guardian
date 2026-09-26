---
description: Incident response — panic (prod broke), leak (secret exposed), rollback (is it safe?), postmortem. Incidente. Incidente.
argument-hint: "<panic | leak | rollback | postmortem> [symptom, suspected secret, rollback target or incident description]"
---

Incident mode. The first word of the arguments picks the mode; the rest is the context. With no mode, ask one short question — which of the four — and nothing else.

| Mode | When |
| --- | --- |
| `panic` | production just broke: what changed, what could have caused it |
| `leak` | a credential, key, token or `.env` may have been committed or pushed |
| `rollback` | before rolling back: is it safe for data, migrations and config? |
| `postmortem` | after the incident: a structured, evidence-backed document |

Arguments: $ARGUMENTS

## `panic` — triage

Terse and operational — the user is on fire, every extra word costs. In this order, no preamble:

1. **What changed**: `git log --since="24 hours ago" --oneline --stat`, the last tag or deployed SHA, recently merged PRs.
2. **Open 🔴 findings**: `prioritize_findings { project_path: "<project>", limit: 10 }` and `guardian://findings/critical`.
3. **Regression**: `regression_alert { project_path: "<project>" }` — the latest scan against its baseline.
4. **Secrets in play**: `scan_secrets { project_path: "<project>", scope: { since: "1 day ago" } }` — in case a key leaked with the change.
5. **Suppressions**: the `status` CLI (`node "${CLAUDE_PLUGIN_ROOT}/cli/dev-guardian.mjs" status --project .`) shows active and soon-expiring ones; no tool lists when a suppression was added, so say so rather than guess.
6. **Likely culprits, ranked by confidence**, each with its evidence, and a rollback target when one exists (then `/guardian-incident rollback <target>`).

## `leak` — secret exposure

High stakes: clear, ordered, urgent without drama.

1. `scan_secrets { project_path: "<project>", log_opts: "--all" }` — gitleaks over the history of every ref, plus the files not committed yet. Secrets are redacted in the output.
   To learn which secrets still work, ask the user first — each secret is sent over the network to its own provider — then re-run with `verify_live: true`: `scan_secrets { project_path: "<project>", log_opts: "--all", verify_live: true }`. A `live` finding is rotated first; `revoked` means the provider refused it; `unknown` (unsupported provider, self-hosted instance, offline, rate limit) means "rotate anyway".
2. For each finding: the commit that introduced it (`git show -s --format="%h %an %ad" <commit>`) and whether it reached a remote (`git branch -r --contains <commit>`).
3. Classify each secret by provider (AWS key, GitHub token, Stripe key, JWT signing key, generic) and give a **rotation checklist per provider**: where to revoke, what to regenerate, what depends on it. **Rotation is mandatory**; treat a pushed secret as already seen by someone else.
4. History rewrite (`git filter-repo`, BFG) is best-effort only — forks, clones, caches and CI logs keep the old objects. Offer it; never present it as the fix.
5. Prevention: `init_project { project_path: "<project>", apply: false }` shows the gitleaks config and pre-commit hook it would install, and `precommit_install { project_path: "<project>" }` wires the hooks into git; add GitHub push protection where the repository lives there.

## `rollback` — is it safe?

Code rolls back easily; data and migrations do not. Mostly a checklist over git, plus one tool for EF Core.

1. Target: the argument (tag or SHA), else the previous tag or the previous deployed SHA. `git diff --stat <target>..HEAD`.
2. **Migrations** added since the target (`git diff --name-only --diff-filter=A <target>..HEAD`, filtered to migration directories). For each: schema-only and reversible → safe; adds a `NOT NULL` column → safe forward, broken backward; drops a column or table → destructive, the rollback loses data. For an EF Core project, `dotnet_efcore_audit { project_path: "<project>" }` flags `DropTable`, `DropColumn` and non-nullable `AlterColumn` without a default.
3. **Lock files**: major version bumps whose API the old code may not expect.
4. **Configuration**: new required environment variables production may not have (`.env.example`, config schemas).
5. **API contracts**: diff OpenAPI / GraphQL / protobuf schemas; removed fields break clients that already upgraded.
6. Verdict: ✅ safe rollback / ⚠️ possible with caveats (listed) / 🔴 do not roll back without a data migration or manual schema fix.

## `postmortem` — the document

Produce the document itself, ready to paste into the incident tracker — not a summary.

1. **Timeline** from commit timestamps, deploy SHAs, merged PRs and the incident time in the arguments.
2. **Root cause**: a best-effort hypothesis from `git log` and the findings — `diff_scans { project_path: "<project>", from: "baseline" }` for what appeared since the accepted baseline, `prioritize_findings { project_path: "<project>" }` for what was open.
3. **Impact**: the blast radius of the offending change's diff.
4. **Detection gaps**: from `guardian://scans/history`, which scanners were skipped or failed around the incident, and which findings were suppressed.
5. **Action items** — owned, dated, each mapped to the command that prevents a recurrence (for example `/guardian-release predeploy` before every deploy, `/guardian-scan --unpushed` before every push).

Respond in the user's language (EN/PT/ES).
