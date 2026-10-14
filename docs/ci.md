# Running dev-guardian in CI

The CLI runs the same tool handlers an MCP session does — no Claude Code, no MCP connection — against a throwaway database, and gates the result against a baseline you commit.

## The short version

Run the CLI from the project you want to scan, by the absolute path of a dev-guardian clone (see [hosts.md](hosts.md#1-clone-once) — `ci-init` needs 3.0.0 or later) or of the installed plugin:

```text
node ~/tools/dev-guardian/cli/dev-guardian.mjs ci-init github --write      # or gitlab, bitbucket
node ~/tools/dev-guardian/cli/dev-guardian.mjs baseline update --project .  # once, locally
git add .github/workflows/dev-guardian.yml .guardian/baseline.json
```

`ci-init` writes a pipeline for the project you are in (never for dev-guardian's own repository); `baseline update` records today's findings so the gate only fails on new ones. The examples below write `dev-guardian.mjs` for that same path.

## `scan` and `baseline update`

```text
node dev-guardian.mjs scan --project . --fail-on high --sarif results.sarif
node dev-guardian.mjs baseline update --project .
```

`scan` runs, in this order: `detect_stack`, `security_scan_full` (which runs `scan_sast`, `scan_secrets`, `scan_deps` and `scan_iac`), `license_compatibility`, `map_attack_surface`, then `scan_dast` (only with `--base-url`) and `validate_finding`. A step that fails is recorded as a coverage gap and the rest still run. `quality_check` and `.guardian/budgets.yml` are not part of the CI gate.

| Flag | Meaning |
| --- | --- |
| `--project <path>` | project to scan (default: current directory) |
| `--fail-on <severity>` | `info`, `low`, `medium`, `high` (default) or `critical`: a finding new to the baseline at or above it fails the gate |
| `--format human\|json` | report on stdout — the JSON keys: [below](#the-json-verdict) |
| `--compact` | with `--format json`: `new_findings` holds only the blocking findings, beside `new_findings_count` and `new_findings_by_severity` — the same keys, small enough to hand to a tool call (623 KB of JSON for 487 new findings did not). Without `--format json` it is a usage error (exit 3) |
| `--sarif <path>` | also write SARIF 2.1.0, its URIs relative to the repository root (a `--project` below the root is put in front, so `packages/api` annotates `packages/api/src/…`). Written after the verdict is printed: a write that fails is an error on stderr, and exit 3 only when the gate itself passed |
| `--local-only` | Keeps Semgrep local: only rules on disk — the project's own and the plugin's packs (the LLM-application pack still runs) — with `--metrics=off`: no registry download, no Semgrep metrics, fewer rules. It needs Semgrep rules of the project's own (a committed `.semgrep.yml`, or rules registered with `register_custom_rules`; the `init_project` MCP tool installs dev-guardian's base ruleset as `.semgrep.yml`): without them Semgrep is skipped — the plugin's packs alone are not a SAST scan — and every scan exits 2 until you add rules or drop the flag. It is not "nothing leaves the machine": Trivy still fetches its vulnerability database and a .NET project is still restored and built, which contacts its NuGet feeds — see [SECURITY.md](../SECURITY.md#network-egress). Semgrep's own version check is off on every run |
| `--base-url <url>` + `--authorized-target` | include `scan_dast` against a running app you are authorized to test |
| `--start-command <cmd> [args…]` | start the app for the DAST pass (argv, never a shell) and kill its whole process tree afterwards; requires `--base-url`. **Command line only** — a `start_command` in `.guardian/ci.json` or any other repository file makes the CLI refuse, because a fork's pull request could edit that file and run code on your runner. |
| `--accept-partial-parse <path>` | repeatable: accept that Semgrep could parse this file only in part — see [below](#files-semgrep-can-only-partly-parse). **Command line only**, like `--start-command`: an `accept_partial_parse` in `.guardian/ci.json` makes the CLI refuse. `baseline update` takes it too. A per-file Semgrep timeout is accepted in [`.guardian/scan.yml`](#scan-settings-guardianscanyml) instead |
| `--baseline-ref <ref>` | read `.guardian/baseline.json` from the commit `<ref>` names, never from the checkout — see [below](#a-pull-request-cannot-gate-itself) |
| `--rules-ref <ref>` | read the project's Semgrep rules, `.guardianignore`, `.trivyignore`, `.bandit` and `.guardian/scan.yml` from `<ref>` — see [below](#a-pull-request-cannot-gate-itself) |
| `--reset-exclusions-from <ref>` | in CI only (`CI=true`): put every `.semgrepignore`, `.gitleaksignore` and `.gitleaks.toml` back to `<ref>`'s before scanning — see [below](#a-pull-request-cannot-gate-itself) |

| Exit code | `scan` | `baseline update` |
| ---: | --- | --- |
| 0 | pass | written, full coverage (accepted gaps and notes aside) |
| 1 | gate failed | — |
| 2 | **incomplete scan**: an expected scanner did not run — never read this as a pass | written, but a scanner did not run, so the baseline may under-represent findings |
| 3 | usage or configuration error — an unreadable `.guardian/baseline.json` or an invalid `.guardian/scan.yml` included | usage or configuration error — the same two included: an unreadable baseline is never rebuilt from nothing |

Every other command's usage error is 3 too (`check` and `mcp-config` used 2 before 3.3.0), and so is an unknown command — a launcher calling an older or newer dev-guardian never reads "gate failed" for it.

`baseline update` is the only command that writes `.guardian/baseline.json`; `scan` never does. It accepts **every** finding of the scan it runs, the newest included, so it is a human decision, made on the base commit — before a change, never to accept one finding: for that, suppress the finding where its scanner reads suppressions, with a reason (`nosemgrep: <rule> -- <reason>`, `# nosec`, a `.trivyignore` or `.gitleaksignore` entry), reviewed like code. A plugin install puts no `dev-guardian` on `PATH`; the command is `node "<plugin root>/cli/dev-guardian.mjs" baseline update --project .`, which every message of the CLI prints in full.

The file keeps `version: 1`; entries carry a line-independent `identity` next to the fingerprint, so a finding that merely moved down a line is not "new". Since 3.3.0 they also carry a `match_id` the gate matches on when the identity does not: a dependency finding keyed without its installed version (an upgrade that fixes some CVEs of a package no longer turns the others into new findings), a secret keyed without the commit that saw it (a squash merge, a whitespace commit, an uncommitted edit of its file, a comment added to its line or a move to another line no longer makes it new — but a **new** secret is new, wherever it is put: since 3.4.0 the gate reads each secret's value — cut from its line, at the commit or in the working tree, where gitleaks' redacted report locates it — and compares the values in memory under a key the run draws and never writes; a file's secrets are numbered by value in the order they came in, by commit, then line, so a secret added above a baselined one, or one replacing it, never takes its place, while another copy of a baselined value in the same file shares its number and is not new (a move must pass, telling a copy from a move would take tracking deletions, and the copy exposes nothing the baseline did not already accept — in another file it is new: the path is part of the key); and an entry is matched once: an exact match takes it first, and a `match_id` match may take only an entry nothing else took. 3.3.0 numbered a file's secrets by line and let a `match_id` match take no entry: a secret added above a baselined one passed), and the path the file had when the baseline was written (a file renamed since — `git diff -M` between the baseline's commit, or `--baseline-ref`, and the working tree — matches its old entries; that one works with an older baseline too). An older baseline gains `match_id` the next time `baseline update` runs, keeping every `added` date. A 2.0.x build still reads a file written by this one, and this one reads a 2.0.x file. A baseline that is there but not readable — merge-conflict markers, a wrong shape — is exit 3 naming the error, never "no baseline".

### Files Semgrep can only partly parse

Semgrep sometimes reads a file only in part and says so with a warning — PHP's legal `const NAMESPACE`, common in WordPress plugins, is one on Semgrep 1.176.1. The file's other code is still analysed, but findings (or routes) in the unreadable span are missing. `scan_sast`, `map_attack_surface` and the batched scoped runs report that as **partial** coverage: Semgrep ran, is also listed missing, and the file is named. The gate exits 2 for it, and the gap line names the file:

```text
coverage gaps:
  - security_scan_full: semgrep ran with reduced coverage (partial: 1 file(s) only partly parsed — … (PartialParsing: wp/rest-controller.php)) — not accepted: wp/rest-controller.php (--accept-partial-parse <path> accepts one file, matched exactly)
    fix: Review the named file; if the gap is acceptable, pass `--accept-partial-parse <path>` on the scan command line (never from a repository file).
```

Every gap line is followed by its `fix:` — the same remedy the JSON carries in `coverage_gap_details` ([below](#the-json-verdict)).

Once you have looked at the file and decided the gap is acceptable, name it:

```text
node dev-guardian.mjs scan --project . --accept-partial-parse wp/rest-controller.php
```

- When **every** file a Semgrep step only partly parsed is accepted, that gap prints under `accepted (not gating):`, one line per file, naming `--accept-partial-parse`, and no longer forces exit 2 (JSON: `accepted_gaps`, an `accepted_gap_details` entry per line, and a `coverage_gap_details` entry with `gating: false`). A path you accepted that nothing reported is printed as unused (JSON: `unused_partial_parse_acceptances`).
- A run with accepted files says so on the line under its verdict, so a pass never reads as a pass over every file: `dev-guardian CI: PASS (exit code 0)`, then `1 file(s) not analysed (accepted), 1 file(s) only partly parsed (accepted) — listed under "accepted (not gating)"` — distinct files, a timeout counted as not analysed (3.4.0 and later).
- Coverage still reads `partial` — in the human report, the JSON and the SARIF (`executionSuccessful: false`). Accepting a gap is not measuring it.
- Paths are relative to `--project` and matched exactly: `/` or `\` separators and a leading `./` are fine; no globs, no directories, no case folding. An absolute path or one with `..` is a usage error (exit 3).
- A YAML target is a file like any other: a GitHub Actions workflow whose `run:` block a rule reads as shell (`typescript@${{ env.X }}`) is a `PartialParsing` on that workflow, not a failed Semgrep.
- Bandit is judged the same way: a Python file it cannot parse (`syntax error while parsing AST from file`) makes Bandit partial, the file named with type `Syntax error`, which you can accept; any other Bandit error on a file is named as `Bandit error`, which you cannot.
- Only a **parse** problem can be accepted here: Semgrep's `PartialParsing`, `Syntax error` or `Lexical error` on a file you named. A per-file `Timeout` (Semgrep gave up on the file for one rule) is accepted only by the project's committed [`.guardian/scan.yml`](#scan-settings-guardianscanyml); until it is, it exits 2 and the gap line names the type (`not accepted: Timeout on wp/rest-controller.php`). A taint **fixpoint** timeout is never a gap at all: it is a note, [below](#scan-settings-guardianscanyml).
- A Semgrep that was skipped, failed (a rule or config error, an unclean exit), or scanned nothing, a run that also missed files over the size limit, a submodule or rules that did not load, and any partly parsed file you did not name, still exit 2.
- With `--base-url`, the DAST step's `guardian-dast:partial-surface` gap is accepted with the same files, unless the surface has another gap (its route recovery failed). Accepting it means accepting that **routes in the unparsed spans were never in the inventory, so DAST never probed them** — not only that their static findings may be missing.
- The findings an earlier scan reported inside an accepted file stay in the open set (`findings/open`, `risk_score`, the dashboard) marked `not_remeasured`: no scan has looked at them again, so none is ever read as fixed.

### Scan settings: `.guardian/scan.yml`

How Semgrep runs, and which of its per-file timeouts the gate accepts, is the project's own, committed file — reviewed like code, and read from the `--rules-ref` commit when that flag is given, so a pull request cannot accept the timeout its own change causes:

```yaml
semgrep:
  timeout: 30            # whole seconds per rule per file — Semgrep's --timeout (0: no limit)
  timeout_threshold: 0   # rules that may time out on a file before Semgrep drops the
                         # whole file — --timeout-threshold (0: never drop it)
  accept_timeouts:       # files whose per-file Timeout the gate accepts, after review
    - src/generated/parser.js
```

- Without the file, every Semgrep scan dev-guardian runs passes `--timeout 30 --timeout-threshold 0` (Semgrep's own defaults are 5 s and 3). At 5 s a mid-size repository never passed the gate: dev-spec-driven's own tree had two files time out on every run (`cli/commands.js`, `engine/guards.js`); at 30 s neither did, and the scan took no longer (100 s and 96 s, Semgrep 1.176.1). A threshold of 0 matters for acceptance: at 3, three timeouts on one file made Semgrep drop the file for every rule still to run and name none of them, so a "timeout" under-stated what was lost.
- `accept_timeouts`: paths relative to the project, matched exactly like `--accept-partial-parse` (`/` or `\`, a leading `./`). An accepted timeout prints under `accepted (not gating):` naming `.guardian/scan.yml`, and no longer forces exit 2; coverage still reads `partial`. What an entry covers, precisely:
  - **One file, every rule — as it was when the acceptance was reviewed (3.4.0 and later).** Any per-file `Timeout` Semgrep reports on that file is accepted, whichever rule timed out — but only while the file's content is what it was at the commit that stands for the review: with `--baseline-ref` or `--rules-ref`, that ref; without one — a local scan, and dev-spec-driven's finish gate, which runs `scan` without a ref — the last commit that changed `.guardian/scan.yml` (committing an acceptance is what reviews it). The content is compared, the tree's file hashed as git would store it against the blob at that commit — committed and uncommitted changes alike, and the index's `assume-unchanged` / `skip-worktree` flags ignored (each hid a change from `git diff`); a file that commit does not have, or that is no longer a regular file, counts as changed. A timeout on a listed file that changed is not accepted, and exits 2 — `not accepted: Timeout on src/big.js, listed in .guardian/scan.yml semgrep.accept_timeouts, but changed since BASE` (without a ref: `since the last commit of .guardian/scan.yml (…)`); its `coverage_gap_details` entry carries `cause: "accepted_file_changed"` and a remedy of its own, since "list it under accept_timeouts" says nothing to someone who did. Before, a pull request appended a command injection to an accepted file, the rule that would have caught it timed out on the file like the others, and the gate passed. A comparison git cannot make (a ref it does not know, a repository where no commit holds `.guardian/scan.yml` yet) accepts nothing; outside a git repository there is nothing to compare with, and an entry covers the file whatever it holds — review a change to an accepted file as if no SAST ran on it. Prefer a larger `semgrep.timeout`, which keeps every rule. Why not a content hash in the entry: the commit already is the reviewed content, and a hash would have to be edited by hand on every change of the file. `baseline update` applies the entries as written.
  - **Until removed.** An entry never expires. One that no step reported a `Timeout` on is named on every run — `note: .guardian/scan.yml semgrep.accept_timeouts <path>: no step reported a Timeout on it (unused — remove it)`, and `unused_timeout_acceptances` in the JSON (3.4.0 and later) — so a stale acceptance does not sit in the file unnoticed.
  - **No patterns.** An entry holding `*` or `?`, or ending in `/`, is refused (exit 3): before 3.4.0 it was compared as a file name and matched nothing, in silence. `[` and `{` are read as written — `pages/[id].js` is a file.
  - **Timeouts only.** `accept_timeouts` never accepts a `PartialParsing` or a `Syntax error`, and `--accept-partial-parse` never a `Timeout`.
- A file that is there but not valid — bad YAML, an unknown key, a negative or fractional timeout (Semgrep takes whole seconds only: `--timeout 1.5` made every scan exit 2 without naming this file), an absolute path, a glob — is exit 3 before anything runs, naming `.guardian/scan.yml` (the MCP tools warn and use the defaults); a typo never reads as a setting that silently never applies.
- **Who may change it.** No dev-guardian hook guards `.guardian/scan.yml` (nor `baseline.json`) against an assistant's edit: the hooks guard the hook configuration, which turns guards off, while this file only widens what one gate run accepts, and every change to it is a reviewable diff. In CI, `--rules-ref` reads it from the base commit, so a pull request cannot accept the timeout its own change causes. Locally, dev-spec-driven 1.30 or later treats `.guardian/` as guarded while its `guardian` finish check is on. Put the file under CODEOWNERS, like the pipeline file ([below](#a-pull-request-cannot-gate-itself)).
- **Taint fixpoint timeouts** — Semgrep's dataflow analysis giving up on one function (`time.fixpoint_timeouts`; no setting tunes it) — are reported and never gate: they print under `notes (not gating):` and appear in the JSON as `coverage_notes` and as `coverage_gap_details` entries of kind `taint_timeout` with `gating: false`. Taint findings inside those functions may be missing; coverage reads `partial`. They used to count like a per-file `Timeout`, and nothing could accept them: dev-spec-driven's tree had them in 49 files on every run.
- What dev-guardian writes in the project's root `.guardian/` — `reports/`, the database, `dashboard.html`, `last-grill.md` and its `.gitignore` — is never a scan target (Semgrep, gitleaks' working-tree pass, the attack-surface map): a project whose `.gitignore` lacked the lines had Semgrep read its own old reports. Only those paths, matched exactly: a `.guardian` folder below the root (`lib/.guardian/`) is the project's code and is scanned — 3.3.0 left out every folder of that name, so a pull request hiding a command injection in `lib/.guardian/handler.js` passed with exit 0. A file git tracks among those generated paths is a gap (exit 2, kind `other`) that no flag accepts: dev-guardian never commits its output, so stop tracking it (`git rm --cached`).

### The JSON verdict

`--format json` prints the gate's verdict for a program; dev-spec-driven's finish gate (1.29 or later) parses it. The keys are only ever added to:

| Key | What it holds |
| --- | --- |
| `tool_version` | the dev-guardian version that judged (3.3.0 and later) |
| `exit_code` | 0 pass · 1 gate failed · 2 incomplete · 3 usage or configuration error |
| `coverage` | `full`, `partial` or `none` — over every gap, accepted ones and notes included |
| `coverage_gaps` | one line per gap that gates, as the human report prints it (a string array) |
| `coverage_gap_details` | the same gaps as data, same order — `tool`, `kind`, `detail` (the line), `remedy` (one English sentence: what clears it), `gating`, and `cause` only where the kind alone would mislead (3.4.0 and later: `accepted_file_changed`, a `file_timeout` on a file `semgrep.accept_timeouts` lists, refused because it changed since its acceptance was reviewed) — then the accepted gaps and the notes, with `gating: false` |
| `coverage_notes` | reported and never gating: taint fixpoint timeouts, and baseline entries that could not be read (a line of `coverage_gaps` before 3.4.0, which holds only the gaps that gate) |
| `accepted_gaps` | gaps accepted by `--accept-partial-parse` or `.guardian/scan.yml`, one line per file (since 3.4.0) |
| `accepted_gap_details` | one per `accepted_gaps` line, same order (3.4.0 and later): `tool` (the scanner), `kind` (`file_timeout` — not analysed by the rules that timed out — or `partial_parse`), `file` (project-relative) and `reason` (what was reported and what accepted it, in English) — count accepted files from this, never by parsing the lines |
| `new_findings`, `new_findings_count`, `new_findings_by_severity` | the findings new to the baseline (with `--compact`, only the blocking ones), how many there are, and per severity |
| `blocking_findings` | new findings at or above `--fail-on` — each with `file_path`, `line_start`, `severity`, `rule_id`, `title` |
| `baseline_absent`, `baseline_status` | no baseline was read (`absent`) or one was (`present`); an unreadable one never gets here — it is exit 3 |
| `baseline_source`, `rules_source`, `exclusions_reset`, `suppressed_by_repo_config`, `unused_partial_parse_acceptances`, `unused_timeout_acceptances` | where the baseline and the rules came from, what was reset, what the repository's own `.trivyignore` suppressed, acceptances nothing used (`--accept-partial-parse`, and since 3.4.0 `semgrep.accept_timeouts`) |

A gap's `kind` says what it is, so a reader can say the right thing about it — only a `missing_tool` is "install something":

| `kind` | The gap | What clears it |
| --- | --- | --- |
| `missing_tool` | a scanner is not installed | install it (the `install_toolchain` MCP tool can) |
| `no_lockfile` | Trivy found a manifest it cannot resolve (`no_supported_manifest`) | commit the ecosystem's lockfile |
| `partial_parse` | Semgrep or Bandit read a file only in part | review it; `--accept-partial-parse <path>` |
| `file_timeout` | Semgrep gave up on a file for a rule | a larger `semgrep.timeout`, or `semgrep.accept_timeouts`, in `.guardian/scan.yml` |
| `taint_timeout` | the taint analysis of some functions gave up (a note, never gating) | nothing, for the gate |
| `path_too_long` | Windows: a file at a path of 260 characters or more was never opened | enable long paths, or a shorter project path — [below](#windows-paths-too-long) |
| `scanner_failed` | a scanner or its rules failed | the cause the detail names |
| `skipped` | a scanner had nothing it could run on (`--local-only` with no project rules, say) | what the detail says |
| `other` | everything else — a shallow clone, files over Semgrep's size limit, a submodule, a step that did not run | the remedy names it |

### Windows: paths too long

With Windows' default `LongPathsEnabled=0`, a scanner that is not long-path aware cannot open a file whose absolute path is 260 characters or more. Semgrep skipped such a file with no error at all — a JavaScript file at a 301-character path holding `exec('ls ' + req.query.dir)` was missing from its `paths.scanned`, and the gate read coverage full, exit 0. Every such file Semgrep would read and its report does not list as scanned is now a gap of kind `path_too_long`, named per file, which no flag accepts: enable long paths (`LongPathsEnabled=1` under `HKLM\SYSTEM\CurrentControlSet\Control\FileSystem`, then restart) or scan from a shorter path.

### A shallow checkout exits 2

Most CI checkouts are shallow by default — GitHub's `actions/checkout` fetches one commit (`fetch-depth: 1`), GitLab uses `GIT_DEPTH: 20` / 50, Bitbucket clones 50 commits. The secrets pass reads git history, and on a shallow clone that history ends at the boundary the checkout fetched: a secret committed before it and removed since is invisible. So `scan` on a shallow checkout names the gap — `gitleaks … history truncated at <commit> — a shallow clone: the commits before it were not scanned` — and **exits 2** (incomplete), never 0.

The fix is to fetch the whole history:

| CI | Setting |
| --- | --- |
| GitHub Actions | `actions/checkout` with `fetch-depth: 0` |
| GitLab CI | `variables: { GIT_DEPTH: "0" }` |
| Bitbucket Pipelines | `clone: { depth: full }` |

The pipelines `ci-init` writes already do this. With the MCP tools rather than the CLI, a history scan limited to commits you did fetch is complete too: `scan_secrets` with `log_opts: "<base>..HEAD"` reads only that range, and a range that stays above the shallow boundary is not truncated (`--all`, or no `log_opts`, reaches the boundary and is).

### What the repository's `.trivyignore` suppressed

A `.trivyignore` in the scanned repository is honoured — accepted risks are the project's call — but never in silence. Trivy 0.50.0 or newer lists what it suppressed, and the gate names it without counting it:

```text
suppressed by the repository's own configuration (not counted by the gate):
  - security_scan_full: trivy: 7 findings suppressed by the repository's .trivyignore: CVE-2020-8203, …
```

The JSON carries the same under `suppressed_by_repo_config` (step, scanner, file, count, ids and the first findings), and the SARIF carries each suppressed finding as a result with `suppressions: [{ "kind": "external", "justification": "suppressed by the repository's .trivyignore" }]`. They change neither the exit code nor coverage. `trivy config` (the IaC pass) cannot list what it suppressed; the line then says so instead of a count, as it does for a Trivy older than 0.50.0. Review changes to `.trivyignore` like code: `review_pr` warns when a diff edits it.

### A pull request cannot gate itself

A pull request's checkout holds the pull request's own `.guardian/baseline.json` and its own scanner configuration. Read from there, the change under review decides how it is judged: a fork adds its new finding to the baseline, deletes the rule that would catch it from `.semgrep.yml`, or lists the file in `.guardianignore` — and the gate passes. Two flags take those files from a commit the pull request does not control, its base:

```text
node dev-guardian.mjs scan --project . --baseline-ref "$BASE_SHA" --rules-ref "$BASE_SHA" --reset-exclusions-from "$BASE_SHA"
```

- `--baseline-ref <ref>` reads `.guardian/baseline.json` with git from the commit `<ref>` names (size-checked first, at most 32 MiB), never from the working tree. None at that commit means no baseline: every finding is new. A `<ref>` that names no commit — a shallow clone, a base branch the checkout never fetched — is exit 3, never "no baseline" and never the checkout's copy. So is an empty value: `--baseline-ref "$BASE"` with `BASE` unset.
- **Under `--baseline-ref` (else `--rules-ref`), the files the pull request changed are read whole for secrets (3.4.0 and later).** gitleaks reads history as `git log -p -U0` hunks — the added lines alone — and a multi-line secret needs every line in one: a private key replaced in place, or added directly above a baselined one, kept its BEGIN / END lines out of every hunk, matched nothing, and the gate passed. So one more `scan_secrets` step runs right after `security_scan_full`, scoped to every regular file that is not, at HEAD or in the working tree, what it was at the ref (`scope.paths`, at most 1,000 files a step): no history pass, each file read whole. Only its matches over several lines are taken: a one-line secret is whole in the hunk that adds it, and the history pass has judged it. They gate like the others; one that repeats a secret another pass reported in the same file (same rule, same value) is listed once, and one the project's `.gitleaksignore` accepts by its history fingerprint (`<commit>:<file>:<rule>:<line>`, the form gitleaks prints for a history finding, which a files pass does not read) stays accepted while the file holds the same lines from some line on — moved or re-indented, not replaced. A `.gitleaks.toml` allowlist of commits does not apply to it. A listing git cannot make is a failed step — exit 2, never a pass. A secret that was already in a changed file but that no pass could see when the baseline was written (hidden the same way in an earlier commit) is reported as new when a pull request touches the file.
- `--rules-ref <ref>` copies these files from `<ref>` into a temporary directory and hands the scanners that copy; the checkout's are not read. A file the ref does not have is read from nowhere — the scan runs as the project would without it.

  | File | Read by | From the ref as |
  | --- | --- | --- |
  | `.semgrep.yml`, `.semgrep.yaml`, and the rule files the ref's `.dev-guardian/configs.json` records | Semgrep (`scan_sast`) | `--config=<copy>`; findings keep the rule id a scan of the checkout stores, so the baseline still matches |
  | `.guardianignore` | every scan | the ref's patterns, applied to the checkout's files — also for which submodules and oversized files are named as gaps, and which languages the project counts |
  | `.trivyignore` | Trivy (`scan_deps`, `scan_iac`) | `--ignorefile <copy>` |
  | `.bandit` | Bandit (`scan_sast`) | `--ini <copy>` (an empty one when the ref has none) |
  | `.guardian/scan.yml` | every Semgrep scan (its timeouts), and the gate (`semgrep.accept_timeouts`) | the ref's settings; a pull request cannot accept the timeout its own change causes ([above](#scan-settings-guardianscanyml)) |

  A file the ref has but that cannot be copied — over 8 MiB, a directory, a link leaving the repository, a manifest entry outside the project — stops the scan (exit 3): leaving it out would run fewer rules than the ref says. Without Semgrep on `PATH` the Docker fallback is not used (it would read the checkout's rules): Semgrep is a named gap and the scan exits 2.

- **The rest stays the checkout's, and is named.** Some configuration no flag can take from a ref:
  - `.semgrepignore` — Semgrep reads every one in the tree it scans; the only flags that would change that are marked internal and unstable in Semgrep 1.176.1.
  - `.gitleaks.toml` and `.gitleaksignore` — gitleaks 8.30.1 does take its config from `--config`, but reads `<source>/.gitleaksignore` whatever `--gitleaks-ignore-path` says (measured). A fingerprint there hides a secret as surely as an allowlist, so taking one file from the ref and not the other would protect nothing.
  - actionlint's and zizmor's configuration — the workflows they audit are the pull request's own anyway.
  - the .NET build's `.editorconfig`, `.globalconfig`, `Directory.Build.props`/`.targets` and NuGet configuration — the build reads them from the tree it compiles.

- `--reset-exclusions-from <ref>` closes the first two of those in CI. A pull request adding a `.semgrepignore` (at any depth) or a `.gitleaksignore` otherwise passes: named in the log, nothing else. Since no scanner flag reads them from elsewhere, and a CI checkout is disposable, the files themselves are put back before the scan — every `.semgrepignore` Semgrep reads for the project (below it, and in each directory above it up to the repository root), and the project's `.gitleaksignore` and `.gitleaks.toml` — restored to `<ref>`'s bytes, deleted where `<ref>` has none. The report says what it reset (`exclusions_reset` in the JSON). It rewrites tracked files, so it runs only where the environment says CI — `CI=true` (or `1`), which GitHub Actions, GitLab CI and Bitbucket Pipelines all set, else `GITHUB_ACTIONS=true`, `GITLAB_CI=true` or a `BITBUCKET_BUILD_NUMBER`. Anywhere else it exits 3 before touching anything (`--reset-exclusions-from rewrites tracked files and runs only in CI (CI=true); outside CI, review the PR's exclusion-file changes instead`): on your own clean checkout it would revert your own exclusion files. In CI it still refuses (exit 3) a checkout with any change, one of those files git does not track or ignores (no fresh checkout holds one, and deleting it could not be undone), and a path through a link; an exclusion file that is itself a link is unlinked and replaced, never written through. Never pass it where you work.

  Every one of the files above that the pull request adds, changes or deletes against `<ref>` — a `.gitleaksignore` git ignores included, since gitleaks reads it anyway — is listed under `read from the scanned tree although it differs from <ref>`, and every file of the table above it changes under `changed in the scanned tree, not applied`. Neither changes the exit code: a pull request may legitimately edit its `.editorconfig`, and a reviewer decides.

The report always says where both came from — `baseline:` and `rules and configuration:` lines in the human output, `baseline_source` and `rules_source` in the JSON (with `tree_differences`: path, change, which copy was applied, and which scanners read it). A pull-request run that says `in the scanned tree (no --baseline-ref)` is gating the pull request against itself.

The pipelines `ci-init` writes pass all three on a pull-request pipeline and nothing on a push, where the committed files are the gate:

| CI | Base passed | Fetch |
| --- | --- | --- |
| GitHub Actions | `github.event.pull_request.base.sha`, through the step's `env:` | none: `fetch-depth: 0` already fetched the base branch |
| GitLab CI | `CI_MERGE_REQUEST_TARGET_BRANCH_SHA` in a merged results pipeline, else `CI_MERGE_REQUEST_DIFF_BASE_SHA`; a merge request pipeline with neither stops (exit 3) | the target branch, only when that commit is missing |
| Bitbucket Pipelines | `origin/$BITBUCKET_PR_DESTINATION_BRANCH` | that branch, first |

**What this does not cover: the pipeline file itself.** GitHub's `pull_request` workflows, GitLab's merge request pipelines and Bitbucket's pull-request pipelines all run the pipeline definition from the pull request's own branch, so a pull request can edit it to drop the flags. Require review of that file (CODEOWNERS on `.github/workflows/`, `.gitlab-ci.yml` or `bitbucket-pipelines.yml`, and a required approval), and read the `baseline:` line of a pull request's report.

### Things a green pipeline does not tell you

- **SARIF carries one bit of coverage.** `invocation.executionSuccessful` turns `false` when coverage is not full, but SARIF has no field for *which* scanner was missing. That is in exit code 2 and the human/JSON output. Treat an uploaded SARIF with zero results as inconclusive until you have checked the exit code.
- **An incomplete scan's SARIF is not uploaded.** GitHub code scanning closes as fixed every open alert of a scanner an upload does not contain, whatever `executionSuccessful` says — so after an incomplete scan the missing scanner's findings would read as resolved. That is every exit 2, and an exit 1 too when a blocking finding outranked a scanner that did not run. The generated GitHub workflow uploads after exit 0, or after exit 1 only when every run in the SARIF says `executionSuccessful: true` (coverage full); the scan step records the decision as `steps.scan.outputs.upload-sarif` and the exit code as `exit-code`. A workflow of your own that uploads on `if: always()` should do the same. GitLab and Bitbucket keep the SARIF as a plain artifact, which closes nothing, so their templates keep it either way.
- **CWE and OWASP tags say what a result is, not what was tested.** A result and its rule carry `external/cwe/cwe-<n>` and `owasp-2025-a<nn>` tags when the scanner named a CWE (Semgrep rule metadata, Trivy, Bandit) or the finding is one weakness by definition (a vulnerable dependency is CWE-1395, a committed secret CWE-798). A result without tags is unmapped, not harmless, and no OWASP category is clean because it has no results: which categories a scan actually tested — judged per source language of the project, since a rule set tests only the languages it has rules for — is in `report_export`'s "OWASP Top 10:2025 coverage" table and in `compliance_evidence` with `framework: "owasp-top10-2025"`.
- **Code-scanning upload needs a public repository, or GitHub Code Security on a private one.** Otherwise the upload step fails for a reason unrelated to findings; drop it and use `--format json` plus the exit code.
- **A run leaves `.guardian/` in the workspace** (`security_scan_full` and `map_attack_surface` write raw reports under `.guardian/reports/`; the last 3 report sets of each kind are kept — `GUARDIAN_KEEP_REPORTS`, [env.md](env.md)). The CLI writes `.guardian/.gitignore` when there is none: everything in `.guardian/` ignored, itself included — so `git status` stays clean — but the files a team shares, which stay committable: `baseline.json`, `budgets.yml`, `hooks.config.json`, `hooks-allowlist.json` and `scan.yml`. It never rewrites that file, nor the project's own `.gitignore` (a tracked file a scan rewrote would make the tree dirty). The MCP server writes the same rule into the project's `.gitignore` whenever it starts in a project:

  ```text
  **/.guardian/*
  !**/.guardian/baseline.json
  !**/.guardian/budgets.yml
  !**/.guardian/hooks.config.json
  !**/.guardian/hooks-allowlist.json
  !**/.guardian/scan.yml
  ```

  A bare `.guardian/` line would stop you committing the baseline: git cannot re-include a file inside an excluded directory. Without the `**/` the lines match at the repository root only, and a sub-project's `.guardian/` (a scan pointed at `packages/api`) shows up untracked. Before 3.3.0 the block re-included `baseline.json` only, so `budgets.yml` and `hooks.config.json` were ignored, and a check read different budgets on each machine and in CI; the server adds the missing lines below an existing block.

## `ci-init`

```text
node dev-guardian.mjs ci-init <github|gitlab|bitbucket> [--project <path>] [--branch <name>] [--write] [--force] [--attest]
```

| Target | File written |
| --- | --- |
| `github` | `.github/workflows/dev-guardian.yml` |
| `gitlab` | `.gitlab-ci.yml` |
| `bitbucket` | `bitbucket-pipelines.yml` |

Without `--write` the pipeline is printed. `--write` creates the file atomically and refuses to replace an existing one unless `--force` is given; it never writes through a symlink that leaves the project. `--branch` (default `main`) is the GitHub push trigger. Exit codes: 0 done, 1 an existing file refused, 3 an unknown target or another usage or configuration error.

What the generated pipeline does:

- checks out the project with **full history** (`fetch-depth: 0` / `GIT_DEPTH: "0"` / `clone: depth: full`), so gitleaks attributes each secret to the commit that introduced it rather than to a shallow boundary that moves on every push; on GitHub with `persist-credentials: false`. A shallow checkout is scanned, but its history pass names the boundary it stopped at and the scan is incomplete (exit 2), never clean;
- clones dev-guardian at the release tag named in `.claude-plugin/plugin.json`, **resolved to its commit SHA when you ran `ci-init`** and verified again with `git rev-parse HEAD` after cloning — a tag that moved since is refused. The clone goes to `$RUNNER_TEMP` / `/tmp`, outside the checkout, so dev-guardian's own source is never scanned as part of your project; then `npm ci --omit=dev` in its `mcp/`;
- installs Trivy, gitleaks and actionlint pinned by version and sha256 (verified against each tool's GitHub release), and bandit, Semgrep and zizmor pinned by exact version through pipx — into a scratch directory, never the checkout. Every pinned value lives in [`configs/ci/pinned.json`](../configs/ci/pinned.json); every GitHub Action is pinned by full commit SHA;
- on GitHub, installs the .NET SDK only when the project has a root `.csproj`, `.fsproj`, `.sln` or `.slnx`; the GitLab and Bitbucket templates document that requirement instead (without the SDK, a .NET project's scan exits 2);
- runs `dev-guardian scan --fail-on high` against the committed baseline — on a pull request, the base commit's baseline and rules ([above](#a-pull-request-cannot-gate-itself)) — and uploads SARIF to code scanning on GitHub — only for a complete run (exit 0, or exit 1 with coverage full), never after an incomplete one — or keeps it as a build artifact on GitLab and Bitbucket (neither ingests raw SARIF).

Resolving the tag needs `git`: from the local checkout's tags when they are there, otherwise over the network with `git ls-remote`.

### Attesting the reports (`--attest`, GitHub only)

`ci-init github --attest` makes the pipeline prove where its reports came from. On a push to the branch:

- the scan step also writes the JSON report (`--format json`, through `tee` under `pipefail`, so the log still shows it and the scan's exit code still decides the step), and the scan job keeps `dev-guardian-report.json` and `dev-guardian-results.sarif` as the `dev-guardian-reports` artifact;
- a separate `attest` job downloads them, refuses a report that is empty or not a report (`tee` creates the file even when the scan crashed before writing one), and signs a SLSA build-provenance attestation for both with `actions/attest-build-provenance` — Sigstore keyless, with the workflow's own OIDC identity, stored in the repository's attestations. Every action involved is pinned by commit SHA in [`configs/ci/pinned.json`](../configs/ci/pinned.json).

The `attest` job runs **even when the gate failed**: an attestation proves where a report came from — this workflow, this commit, this run — never that the gate passed. Read the report for that.

On a **public repository** this exposes the results: the full JSON report (every new finding, with its file and line) is printed to the public job log, and the `dev-guardian-reports` artifact — SARIF and JSON — can be downloaded by any signed-in GitHub user while it is retained. Secrets stay redacted in both, as everywhere else.

Permissions: the `attest` job holds `id-token: write` and `attestations: write` and nothing else. The scan job — which builds and scans the project, and so runs code from it — keeps exactly `contents: read`, `security-events: write` and `actions: read`, as without `--attest`; with two jobs these move from the workflow level to each job (`permissions: {}` at the top). Pull requests are not attested: a fork's pull request gets no OIDC token, and nobody verifies a pull request's reports later.

Artifact attestations need a public repository, or GitHub Enterprise Cloud for a private or internal one; anywhere else the `attest` job fails.

To verify a report, download the run's artifact and check it against the workflow that should have produced it:

```text
gh run download <run-id> --repo OWNER/REPO --name dev-guardian-reports
gh attestation verify dev-guardian-results.sarif --repo OWNER/REPO \
  --signer-workflow OWNER/REPO/.github/workflows/dev-guardian.yml \
  --source-ref refs/heads/main
gh attestation verify dev-guardian-report.json --repo OWNER/REPO \
  --signer-workflow OWNER/REPO/.github/workflows/dev-guardian.yml \
  --source-ref refs/heads/main
```

Use the branch you passed to `--branch` (`ci-init` prints the command with it). Keep `--source-ref`: `--signer-workflow` names the workflow **file**, and a copy of it on any other branch — edited to run on a push there — signs as the same path.

`--attest` is **command line only**, like `scan --start-command`: a `.guardian/ci.json` declaring `attest` makes `ci-init` refuse (exit 3), because a pull request could edit that file and hand a job the right to sign in the repository's name. GitLab and Bitbucket refuse `--attest` (exit 3): Bitbucket's OIDC tokens are no Sigstore identity, and on GitLab a cosign keyless signature of the reports would carry no provenance and have no store to be verified against — not the same guarantee, so the generator does not pretend it is.

## Scanning workflows

`scan_iac` also audits `.github/workflows/*.yml` when they exist: **zizmor** (template injection, unpinned `uses:`, excessive `permissions:`, persisted credentials) and **actionlint** (schema and expression errors). dev-guardian runs actionlint with `-shellcheck= -pyflakes=`, so its shellcheck and pyflakes checks of `run:` blocks are off. Either tool missing is a named gap in `missing_tools`, never silence.

## As dev-spec-driven's finish check

dev-spec-driven 1.29 or later can run this gate before a feature closes. In Claude Code, `/spec-setup init --guardian` (in a session, `spec_init { guardian: true }`) stores a project check named `guardian`; from a terminal it is `node "<dev-spec plugin root>/cli/dev-spec.js" init --guardian` — a plugin install puts no `dev-spec` on `PATH`, and dev-spec's own tool results print that line in full. `/spec-finish` — `finish --run` — then runs `scan --project <dir> --fail-on high --format json` through a launcher, `node .specs/guardian.cjs <args>`, that finds the newest dev-guardian installed and forwards every argument. Nothing needs installing in the plugin's `mcp/`: the CLI runs on the committed bundle `mcp/dist/engine.js` (`mcp/dist/cli.js` before 3.3.0). That takes dev-guardian 3.2.1 or later — 3.2.0's `scan` failed in every plugin install with `Cannot find package 'yaml'` (exit 3); the verdict names its version (`tool_version`) since 3.3.0, and dev-spec-driven warns below the one it needs.

It is the same gate as here: only a finding new to `.guardian/baseline.json`, at `high` or above, blocks the finish, and exit 2 is reported as an incomplete scan, never as a pass — `coverage_gap_details` tells dev-spec-driven which gap it is, so it only says "install" for a missing scanner. dev-spec-driven 1.30.2 also reads `accepted_gap_details` (with `accepted_gaps`: a pass that left files unanalysed says how many, and names the feature's own), `unused_timeout_acceptances` (a warning to remove the stale entries), `coverage_notes` (counted, never a gap) and a gating gap's `cause: "accepted_file_changed"` (dev-guardian's own remedy, never "list the file"); it does not read `coverage`. It runs the gate without a ref, so an `accept_timeouts` entry covers a file there only as it was at the last commit of `.guardian/scan.yml` ([above](#scan-settings-guardianscanyml)). **Record the baseline before you turn the check on**, on the base branch, and commit it: `node .specs/guardian.cjs baseline update --project .` (or `node "<dev-guardian plugin root>/cli/dev-guardian.mjs" baseline update --project .`). Without one every existing finding counts as new — the verdict says so (`baseline_status: "absent"`) — and the first finish is blocked by old debt.

To accept **one** finding you have reviewed, suppress it where its scanner reads suppressions, with a reason — an inline `nosemgrep: <rule> -- <reason>` or `# nosec`, a `.trivyignore` or `.gitleaksignore` entry — reviewed like code. Never run `baseline update` for that: it accepts every current finding, the feature's own included. Rebuilding the baseline is a human decision, made on the base commit, before the feature's code. A `suppress_finding` does not reach this gate, because `scan` works in a throwaway database. Never force the finish past it: the finding is still new to the next scan, and to CI.
