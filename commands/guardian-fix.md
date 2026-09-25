---
description: Find and fix bugs, apply scanner-produced fixes as PRs, and verify a fix (re-scan + delta). Corrige e verifica. Corrige y verifica.
argument-hint: "[<hint or path> | <finding fingerprint> | --pr [--apply] | --verify [<fingerprint or description>]]"
---

Fix what Guardian found, then prove the fix. Four modes — pick from the argument, ask when it is ambiguous:

| Argument | Mode |
| --- | --- |
| *(none)*, a hint, a failing test or a path | find and fix bugs |
| a finding fingerprint (64 hex characters) | fix that one finding |
| `--pr`, `--pr --apply` | apply the fixes scanners already produced, as pull requests |
| `--verify [<fingerprint or description>]` | prove an applied fix worked and regressed nothing |

Every fix you write by hand ends with the `--verify` steps — a fix that was not re-measured is not done.

Arguments: $ARGUMENTS

## `<hint>` — find and fix bugs

Load the `guardian-bugfix` skill (Skill tool, `dev-guardian:guardian-bugfix`) and follow its method: reproduce → isolate → diagnose → fix.

1. Run `bug_hunt { project_path: "<project>" }` — or, for a path hint, `bug_hunt { project_path: "<project>", scope: { paths: ["<path>"] } }`. Narrow the response with `categories: ["null_safety", "race_condition"]` when the user named a class. The local rule packs match syntax, not dataflow: a quiet result is a first pass, not a verdict, so read the code the hint points at as well.
2. For each bug: explain **why** it is a bug, show the minimal patch, and apply it only after the user approves it. Add a regression test when the project has a test suite.
3. Then run `--verify`.

## `<fingerprint>` — fix one finding

1. `suggest_fix { project_path: "<project>", finding_fingerprint: "<fingerprint>", context_lines: 30 }` returns the snippet, the surrounding code, the rule's metadata and prior suppressions of the same rule. It never calls an LLM — you write the patch from it.
2. Propose the patch with the reasoning, apply it after approval, then run `--verify` on that fingerprint.
3. A false positive is not fixed, it is suppressed: `suppress_finding { finding_fingerprint: "<fingerprint>", reason: "<why>" }`, with `expires_at` for a temporary snooze.

## `--pr` — scanner-produced fixes as pull requests

`create_fix_pr` applies only fixes a scanner itself produced: dependency upgrades from `deps_update_plan` and Semgrep autofixes. It applies them in an isolated git worktree, re-runs the same scanner and the test suite to prove each one, and opens one pull request per ecosystem or scanner.

1. Always start with the dry run: `create_fix_pr { project_path: "<project>", apply: false }`. Narrow with `sources: ["deps"]` or `sources: ["semgrep"]`, `severity_min` (default `high`) and `max_prs` (default 3).
2. Show `groups` (what would change and how it verified), `deferred`, and `filtered` / `filtered_reason` — every open finding that did not become a candidate, and why. Findings from the local `bugfix-*.yml` packs carry no autofix, so they appear as `no_fix_available` at any `severity_min`: fix those in the default mode instead.
3. Only after an explicit yes: `create_fix_pr { project_path: "<project>", apply: true }` — that is what commits, pushes and runs `gh pr create`.

## `--verify` — prove the fix

1. Identify the finding(s): the fingerprint, or the description matched against `guardian://findings/open`. Note the scan type that reported each one.
2. Re-run the tool that found it, fresh, over the whole project (a scoped scan can never become a baseline):

   | Scan type | Re-run |
   | --- | --- |
   | `sast` | `scan_sast { project_path: "<project>", force: true }` |
   | `bugs` | `bug_hunt { project_path: "<project>", force: true }` |
   | `secrets` | `scan_secrets { project_path: "<project>", force: true }` |
   | `deps` | `scan_deps { project_path: "<project>", force: true }` |
   | `deps_audit` | `deps_audit { project_path: "<project>", force: true }` |
   | `quality` | `quality_check { project_path: "<project>", force: true }` |
   | `iac` | `scan_iac { project_path: "<project>", force: true }` |
   | `containers` | `scan_containers { project_path: "<project>", dockerfile_path: "<same as the original>", image: "<same as the original>", force: true }` |
   | `wordpress` | `scan_wordpress { project_path: "<project>", force: true }` |
   | `wp_vuln_check_source` | `wp_vuln_check_source { project_path: "<install root>", force: true }` |
   | `security_full` | `security_scan_full { project_path: "<project>", force: true }` |

   `scan_containers` must be re-run with the same `dockerfile_path` and/or `image` the original scan used (pass only the ones it had) — a different target is a different scan, and its silence says nothing about the original finding.

3. `diff_scans { project_path: "<project>", scan_type: "<type>", from: "previous" }` — or `from: "baseline"` to compare against the accepted reference. Read `resolved` (the fix), `new` (regressions of the same category) and `not_remeasured` (a scanner that did not run this time — not a resolution).
4. Verdict: ✅ fix verified, no regressions / ⚠️ verified, but N new findings / 🔴 the original finding is still there.
5. When clean, offer `set_baseline { project_path: "<project>", scan_type: "<type>", note: "<fix>" }` so this becomes the reference.

Respond in the user's language (EN/PT/ES).
