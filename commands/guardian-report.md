---
description: Reports from Guardian's scans and history — exec (default), handoff, trend, debt, changelog, soc2. Relatórios. Informes.
argument-hint: "[exec | handoff | trend | debt | changelog | soc2] [audience, period or reference]"
---

Produce a report. The first word of the arguments picks the mode; anything after it is the hint for that mode. No mode → `exec`.

| Mode | For |
| --- | --- |
| `exec` | a stakeholder-ready report on security, quality, dependencies and compliance |
| `handoff` | someone else picking up the project |
| `trend` | are we improving over the last N scans? |
| `debt` | what to attack next, ranked by ROI |
| `changelog` | release notes since a reference |
| `soc2` | an auditor's evidence pack (SOC 2 / ISO 27001 / GDPR) |

Arguments: $ARGUMENTS

## `exec` — executive report (default)

1. `audit_executive { project_path: "<project>" }` runs `security_scan_full`, `quality_check`, `deps_audit` and `compliance_check` in sequence and returns severity counts, the top 10 findings and the delta against the previous executive audit.
2. Write the report for people who do not read code — no rule ids, no scanner names, findings translated into outcomes:
   1. **Executive summary** — three sentences: where the project is, the biggest risk, the next move.
   2. **Security posture** — 🔴 / 🟡 / 🟢 counts and the trend against the previous audit.
   3. **Compliance** — licence posture, policy documents found, SBOM availability.
   4. **Quality** — debt described in business terms, plus an **Understanding gate** line from `.guardian/last-grill.md` (the latest `guardian-grill` verdict; missing or older than the current diff shows ⚪ "not run for these changes").
   5. **Dependencies** — vulnerable and outdated counts, supply-chain risks.
   6. **Next 5 actions**, in plain language, by impact.
3. Say plainly when coverage is partial: a scanner that did not run is a gap in the report, not a clean area.
4. Output: the Markdown inline. To keep a file, `report_export { project_path: "<project>", content_markdown: "<the markdown>" }` writes `report.md`; for something to send or print to PDF, `report_export { project_path: "<project>", format: "html", content_markdown: "<the markdown>", title: "<title>", lang: "<en or pt or es>" }` — `lang` in the user's language. For code-scanning upload instead, `report_export { project_path: "<project>", format: "sarif" }`.

## `handoff` — project handoff snapshot

1. `node "${CLAUDE_PLUGIN_ROOT}/cli/dev-guardian.mjs" status --project .` — risk band, open findings, deltas, hotspots, missing scanners, active and expiring suppressions. Quote it verbatim.
2. `risk_score { project_path: "<project>" }` for the score, its breakdown and `coverage_caveat`; `prioritize_findings { project_path: "<project>", limit: 5 }` for the top five, with their KEV/EPSS weighting.
3. `detect_stack { project_path: "<project>" }` and `check_toolchain {}` — the stack, and which scanners are installed here versus expected.
4. Open work from git: `git branch --no-merged <default branch>`, and `gh pr list` when the GitHub CLI is available.
5. One Markdown document: current state, open commitments, active suppressions (no tool lists individual suppressions — give the counts `status` shows), hotspots, toolchain map, and the **top 3 next actions** for whoever picks it up.

## `trend` — findings over time

1. Read `guardian://scans/history` (the 50 most recent scans of every type). Default window: the last 10 scans of each type, or the window in the hint.
2. For each consecutive pair of the same type: `diff_scans { project_path: "<project>", from_scan_id: "<older>", to_scan_id: "<newer>" }` — `new`, `resolved`, and `not_remeasured` (a scanner that did not run, never a resolution).
3. `regression_alert { project_path: "<project>", scan_type: "<type>" }` — the latest scan of that type against its baseline.
4. Show a table per severity with ↑ worse / ↓ better / → flat, the **chronic** findings (still `unchanged` across most of the window), the wins that stayed resolved, and a rough **debt half-life** from the resolution rate. This is a snapshot: for what to do next, `debt`.

## `debt` — hotspots ranked by ROI

1. `risk_score { project_path: "<project>" }` and `prioritize_findings { project_path: "<project>", limit: 50 }`; `triage_findings { project_path: "<project>" }` to set likely false positives aside.
2. When the latest quality scan is stale: `quality_check { project_path: "<project>" }`.
3. Churn: `git log --since="6 months ago" --name-only --format=`. No tool ranks files — you do: findings per file × severity × churn.
4. The **top 10 hotspots**, each with a one-line why, one move (🛠️ refactor / 🧪 add tests / 📚 document the gotcha / 🗑️ delete) and an effort-versus-impact estimate. Favour small moves; never a mass rewrite; if the project is clean, say so.
5. To turn the top items into improvement specs, hand over to the `guardian-improve` skill.

## `changelog` — release notes

Checklist — no automation: git does the work, no MCP tool is involved.

1. Reference: the hint (tag, SHA or "since last release"), else `git describe --tags --abbrev=0`.
2. `git log <ref>..HEAD`, grouped by conventional-commit prefix: 🚨 breaking (`!:` or `BREAKING CHANGE`), 🔒 security (CVE fixes, secret remediation), ✨ `feat`, 🐛 `fix`, 🛠️ internal (`chore`, `refactor`, `test`, `docs`). Classify unprefixed commits from their diff; link PR numbers.
3. Keep-a-Changelog Markdown. Offer to prepend it to `CHANGELOG.md`.

## `soc2` — audit evidence pack

1. When the latest compliance scan is stale: `compliance_check { project_path: "<project>" }`.
2. `compliance_evidence { project_path: "<project>", framework: "soc2" }` — or `framework: "iso27001"` / `framework: "gdpr"` when the hint names one. It assembles this project's latest compliance scan, licence summary, CVE counts, baseline status and suppressions. When the hint names OWASP or NIST, use `framework: "owasp-top10-2025"` or `framework: "nist-csf-2.0"`: per-category evidence, where a category counts only when a scanner able to detect it ran ok — carry its "NOT COVERED" lines into the pack as gaps, never drop them. The NIST CSF mapping is dev-guardian's own; say so.
3. Extend it with evidence from the project: CC6.1 logical access (auth code paths, missing-auth findings), CC6.6 vulnerability management (`guardian://scans/history` dates, `risk_score`), CC7.1 detection (logging, metrics, error tracking — the `guardian-observability` skill), CC7.2 incident response (post-mortems in the repo), CC8.1 change management (reviews, branch protection, pre-commit hooks); for ISO 27001, map findings to Annex A controls.
4. End with the caveat: this is supporting evidence, not a control list — the audit firm decides what is sufficient.

Respond in the user's language (EN/PT/ES).
