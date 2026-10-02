#!/usr/bin/env node
/**
 * dev-guardian CLI — universal entry point (no MCP connection required).
 *
 * Commands:
 *   mcp-config <host|all>   Bootstrap dev-guardian into any AI host (fills in
 *                           the absolute path to the MCP server for you).
 *   check                   Run the same dependency-free guardrail detectors
 *                           the hooks use, from a plain terminal / CI:
 *                             --file <path>   scan a file for secrets
 *                             --bash "<cmd>"  risk-assess a shell command
 *                             --powershell    read it as PowerShell quotes too
 *   scan                    Headless CI entry point: run the same scan
 *                           pipeline the MCP tools run, gate the result
 *                           against the committed baseline, and report
 *                           human / JSON / SARIF. Never writes the baseline.
 *                             --project <path>        default: cwd
 *                             --fail-on <severity>     default: high
 *                             --format human|json      default: human
 *                             --sarif <path>           also write SARIF here
 *                             --base-url <url>         include scan_dast
 *                             --authorized-target      confirm DAST target
 *                             --start-command <cmd> …  CLI ARGV ONLY, see below
 *                             --accept-partial-parse <path>  repeatable, CLI ARGV
 *                                                      ONLY: accept that Semgrep
 *                                                      only partly parsed <path>
 *                             --baseline-ref <ref>     read .guardian/baseline.json
 *                                                      from that commit, never the tree
 *                             --rules-ref <ref>        read the project's Semgrep rules
 *                                                      and ignore files from that commit
 *                             --reset-exclusions-from <ref>  CI only (CI=true), clean checkout:
 *                                                      put .semgrepignore, .gitleaksignore
 *                                                      and .gitleaks.toml back to that commit's
 *                             Exit codes: 0 pass, 1 gate failed, 2 incomplete
 *                             scan (a scanner did not run), 3 usage error.
 *   baseline update         Regenerate .guardian/baseline.json from the
 *                           current scan. The ONLY command that writes the
 *                           baseline — `scan` never does, on purpose.
 *                             Same pipeline flags as `scan` except --fail-on,
 *                             --format and --sarif (baseline update does not
 *                             gate or render a report — it writes a file).
 *   ci-init <host>          Generate a CI pipeline for the PROJECT being
 *                           scanned (github, gitlab or bitbucket) — never
 *                           for this repo, which ships none of its own.
 *                           Actions pinned by full commit SHA; scanner
 *                           binaries pinned by version and a sha256
 *                           verified against the tool's own GitHub release.
 *                             --project <path>   default: cwd
 *                             --branch <name>     GitHub push trigger branch, default main
 *                             --write             write the file (default: preview to stdout)
 *                             --force             overwrite an existing pipeline file (with --write);
 *                                                 never one that is a symlink out of the project
 *                                                 or a broken one
 *                             --attest            github only, CLI ARGV ONLY: attest the JSON report
 *                                                 and the SARIF (actions/attest-build-provenance)
 *                                                 in a job of their own
 *                             Needs network + git: resolves the release tag to its
 *                             commit SHA and pins that, not just the tag.
 *                             Exit codes: 0 done, 1 missing/unknown target or
 *                             refused overwrite, 3 usage error
 *   status                  One-screen terminal summary of the latest scan
 *                           for this project (read-only — no scan runs).
 *                           Reports; does not gate: exits 0 even on a
 *                           project full of findings, or one never scanned.
 *                             --project <path>        default: cwd
 *   dashboard               Writes a self-contained HTML report and prints
 *                           its path. Opens it in a browser only when
 *                           stdout is a TTY and --no-open was not given.
 *                             --project <path>        default: cwd
 *                             --out <path>             default: <project>/.guardian/dashboard.html
 *                             --no-open                never launch a browser
 *   db adopt                Show what the project's .guardian/guardian.db
 *                           holds (projects, scans, dates, suppressions,
 *                           paths) and, with --yes, register it as this
 *                           user's database — the only way an existing one
 *                           (from before 3.1.0, a copy) comes to be trusted.
 *                           CLI only, never an MCP tool.
 *                             --project <path>        default: cwd
 *                             --yes                    register it
 *                             --rehome                 with --yes: move this
 *                                                      project's rows filed under
 *                                                      a path that leads to it
 *                                                      to its canonical path
 *
 *   node cli/dev-guardian.mjs mcp-config <host|all> [--write] [--scope …]
 *   node cli/dev-guardian.mjs check --file path/to/file
 *   node cli/dev-guardian.mjs check --bash "rm -rf /"
 *   node cli/dev-guardian.mjs scan --project . --fail-on high --sarif out.sarif
 *   node cli/dev-guardian.mjs baseline update --project .
 *   node cli/dev-guardian.mjs status --project .
 *   node cli/dev-guardian.mjs dashboard --project .
 *   node cli/dev-guardian.mjs db adopt --project . --yes
 *
 * `--start-command`, and why it may only come from argv:
 *   scan_dast's own MCP tool deliberately has no way to start the app it
 *   tests, because that parameter would be filled by a model whose context
 *   includes the repository under analysis — an injected comment in a
 *   README would have somewhere to point. That reasoning holds only because
 *   a *human* fills in a CLI flag. A repository config file does not have
 *   that property: a pull request from a fork could edit it and gain code
 *   execution on the CI runner the moment this tool read the key from
 *   there — the classic "pwn request". So `--start-command` is accepted on
 *   argv only; if `.guardian/ci.json` (or any other repository file) ever
 *   declares `start_command`, this CLI refuses outright, regardless of what
 *   argv says.
 *   Starting the process is done with argv as an array (`shell: false`,
 *   never a joined string) and the whole tree is killed on every exit path
 *   — normal completion, a thrown scan, or the health check itself timing
 *   out — see `mcp/src/ci/appRunner.ts`. `--start-command` requires
 *   `--base-url` alongside it: the URL polled for the health check and the
 *   `scan_dast` target are the same origin, so there is nothing else for
 *   `--base-url` to name once the app starts on its own.
 *
 * Requires a built server (`cd mcp && npm install && npm run build`).
 */

import {
  closeSync,
  existsSync,
  linkSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  realpathSync,
  renameSync,
  statSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import { randomBytes } from 'node:crypto';
import { homedir, tmpdir } from 'node:os';
import { dirname, isAbsolute, join, parse, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';

import { ALL_HOSTS } from '../mcp/dist/hostsetup/hostSpecs.js';
import { previewMcpConfig, setupHost } from '../mcp/dist/hostsetup/setup.js';
import { execGitSync } from '../mcp/dist/platform/gitSafety.js';
import { detectOs } from '../mcp/dist/platform/osDetect.js';
import { hardenCommandSearch } from '../mcp/dist/platform/binaryPath.js';
import { canonicalPath } from '../mcp/dist/platform/projectPath.js';
import { scanForSecrets } from '../mcp/dist/hooks/secretScan.js';
import { assessBashCommand } from '../mcp/dist/hooks/bashGuard.js';
import { decodeText } from '../mcp/dist/hooks/textEncoding.js';
import { untrustedText } from '../mcp/dist/platform/untrustedText.js';
import {
  describeReadRefusal,
  describeWriteRefusal,
  isWithinDir,
  PROJECT_LOCKFILE_MAX_BYTES,
  readProjectText,
  writeProjectFile,
} from '../mcp/dist/platform/projectFs.js';

// `storage/*` and `dashboard/*` are NOT statically imported here (contrast
// the five imports directly above, which are pure — no `node:sqlite`
// anywhere in their own transitive closure, confirmed by grepping the built
// `dist/` for it). `storage/db.ts` requires `node:sqlite` at MODULE LOAD
// TIME (`createRequire(import.meta.url)('node:sqlite')`, top-level, not
// inside a function) — still a gated/experimental Node builtin below the
// project's own floor (Global Constraint 12: Node >= 22.13, no
// `--experimental-sqlite` anywhere), so on an OLDER Node a static top-level
// `import` of `storage/index.js` would throw the moment THIS FILE loads,
// before `main()` runs and before argv is even inspected — every
// invocation, including `--help`, `check`, and `mcp-config` (none of which
// touch a database), would crash with a raw `ERR_UNKNOWN_BUILTIN_MODULE`
// stack trace instead of running. `status`/`dashboard` are the only two
// subcommands that ever need a database or a snapshot renderer; they load
// this cluster lazily via `loadDashboardModules()` (mirroring
// `loadCiModules()`'s identical reasoning for `scan`/`baseline update`,
// just below), so every OTHER subcommand's process never touches
// `node:sqlite` at all, on any Node version.

// `scan` runs in the project it scans: no spawn by bare name may find a binary
// there (mcp/src/platform/binaryPath.ts). Pure — node:fs and node:path only.
hardenCommandSearch();

const HERE = dirname(fileURLToPath(import.meta.url)); // <plugin>/cli
const ROOT = resolve(HERE, '..'); // <plugin>
const SERVER_JS = resolve(ROOT, 'mcp', 'dist', 'server.js');
// Item 6a: the absolute path this project's own CLI substitutes into every
// `{{DEV_GUARDIAN_CLI}}` placeholder in an installed rules file — see
// `installRulesOne` in `mcp/src/hostsetup/setup.ts`. Without this, a rules
// file installed into ANOTHER project told the agent to run
// `node cli/dev-guardian.mjs`, a path that exists only inside the
// dev-guardian repo itself.
const CLI_JS = resolve(HERE, 'dev-guardian.mjs');
const HOST_RULES_DIR = resolve(ROOT, 'host-rules');
const VALID_HOSTS = new Set([...ALL_HOSTS, 'all']);

// --- CI (scan / baseline) -------------------------------------------------
//
// The relative-path key a repository may declare *other* CI settings under
// one day. It must never carry `start_command` — see the module doc above
// and `findStartCommandInRepoConfig` below, which is the one thing this
// section exists to check for. JSON, not YAML: this file is plain ESM
// JavaScript with no root-level `node_modules` to resolve a YAML parser
// from (mcp/'s own `yaml` dependency lives under mcp/node_modules, not
// reachable from a bare specifier here), and JSON needs none — `JSON.parse`
// is a language builtin, and `.guardian/baseline.json` already establishes
// JSON as this project's own convention for repo-local `.guardian/` state.
const CI_CONFIG_RELATIVE_PATH = '.guardian/ci.json';

// Mirrors CI_EXIT.USAGE_ERROR in mcp/src/ci/types.ts (value 3). Kept as a
// literal, not imported, because it must be usable BEFORE ci/types.js can
// be loaded at all — including to report that ci/types.js is missing
// (see loadCiModules below).
const USAGE_ERROR_EXIT = 3;

// `scan`/`baseline update` pull in `Storage`/`GuardianDatabase` (via
// loadCiModules -> runScans.js), which back onto `node:sqlite` — still an
// experimental Node API, so Node prints
// "(node:PID) ExperimentalWarning: SQLite is an experimental feature..."
// to stderr THE FIRST TIME that module loads, on every single invocation.
// That is Node's own runtime warning, not this project's, and left alone it
// would land in every CI log this command ever runs in — exactly the stray
// noise "pristine output" (this task's own load-bearing requirement) exists
// to keep out.
//
// Node's default warning printer is itself registered as a normal listener
// on `process`'s 'warning' event, not a fallback that only runs when no
// listener exists — confirmed directly: adding a listener WITHOUT first
// removing the default one still printed the warning (both fired). So this
// has to be two steps: drop the default listener, then install a narrow
// replacement that re-prints anything else exactly as Node would have —
// only this one, specifically named, warning is silenced; a real
// deprecation/experimental warning about something actually going wrong
// still reaches stderr.
process.removeAllListeners('warning');
process.on('warning', (warning) => {
  if (warning.name === 'ExperimentalWarning' && /SQLite/i.test(warning.message)) return;
  process.stderr.write(`${warning.stack ?? `${warning.name}: ${warning.message}`}\n`);
});

function usage() {
  process.stdout.write(`dev-guardian — CLI (no MCP connection needed)

Usage:
  node cli/dev-guardian.mjs mcp-config <host|all> [options]
  node cli/dev-guardian.mjs check (--file <path> | --bash "<command>" [--powershell]) [--min high|medium] [--json]
  node cli/dev-guardian.mjs scan [options]
  node cli/dev-guardian.mjs baseline update [options]
  node cli/dev-guardian.mjs ci-init <github|gitlab|bitbucket> [options]
  node cli/dev-guardian.mjs status [--project <path>]
  node cli/dev-guardian.mjs dashboard [--project <path>] [--out <path>] [--no-open]
  node cli/dev-guardian.mjs db adopt [--project <path>] [--yes [--rehome]]
  node cli/dev-guardian.mjs import-sarif <file> [--project <path>] [--allow-outside-project] [--max-results <n>]

mcp-config — wire the MCP server into an AI host
  Hosts: ${[...ALL_HOSTS].join(', ')}, all
  --write              Write/merge into the project (+ drop the rules file)
  --scope project|global   MCP scope (default project)
  --global             Shorthand for --scope global. Also required to include a
                        global-only host (windsurf, claude-desktop) when writing
                        "all" — otherwise those two are skipped, never silently
                        written to your global config
  --project <path>     Target project directory (default: current directory)
  --update-mcp         Refresh a stale MCP entry / rules block that already exists
  --force              Deprecated alias of --update-mcp
  Rules files are managed as a delimited block inside the target file
  (<!-- dev-guardian:begin --> … <!-- dev-guardian:end -->) — your own content
  around it is never touched or replaced.
  Exit codes: 0 preview/write completed, 1 missing or unknown host,
              2 usage error (e.g. --project with no value)

check — run the guardrail detectors (same engine as the hooks)
  --file <path>        Scan a file for hard-coded secrets (UTF-8, or UTF-16
                        by byte-order mark or NUL-interleaving)
  --bash "<command>"   Risk-assess a shell command (ok / warn / block)
  --powershell         With --bash: also read it with PowerShell's quoting, as
                        the hook does for the PowerShell tool
  --min high|medium    With --file: minimum secret confidence (default: medium)
  --json               Machine-readable output
  One of --file and --bash, never both.
  Exit code: 0 = clean/ok, 1 = secret found / command is risky or catastrophic,
             2 = usage error (neither or both of --file/--bash, an unknown
             argument, a bad --min) or the --file path does not exist /
             could not be read

scan — headless CI: run the scan pipeline, gate against the baseline, report
  --project <path>      Target project directory (default: current directory)
  --fail-on <severity>  info|low|medium|high|critical (default: high)
  --format human|json   Report format on stdout (default: human)
  --sarif <path>        Also write a SARIF 2.1.0 report to this path
  --base-url <url>      Include scan_dast against this target. Also the
                         health-check URL when --start-command is given —
                         they are the same origin, so one flag names both.
  --authorized-target   Confirm you are authorized to DAST-test that target
  --local-only          Keeps Semgrep local: only rules on disk — the
                         project's .semgrep.yml and registered custom rules,
                         plus the plugin's own packs (the LLM-application
                         pack still runs) — with --metrics=off and no
                         registry download. Fewer rules than the default
                         registry ruleset. It is NOT "nothing leaves the
                         machine": Trivy still fetches its vulnerability
                         database and a .NET project is still restored from
                         its NuGet feeds (SECURITY.md, network egress).
                         Semgrep's own version check is off on every run.
  --start-command <cmd> [args…]
                         Start <cmd> (argv, never a shell) for the DAST pass
                         and stop it — whole process tree — when the scan
                         ends, however it ends. Requires --base-url. CLI
                         ARGV ONLY — never honoured from a repository file:
                         a fork's pull request could otherwise edit
                         .guardian/ci.json and run arbitrary code on the
                         runner the moment this CLI read the key from there.
  --accept-partial-parse <path>
                         Repeatable. Semgrep could parse <path> (relative to
                         --project) only in part — e.g. PHP's legal
                         \`const NAMESPACE\` — and you accept that: when EVERY
                         file a Semgrep step only partly parsed is accepted,
                         its gap prints as "accepted" and does not force exit
                         2. Coverage still reads partial (JSON, SARIF). Matched
                         exactly: no globs, no directories. Parse errors only
                         (PartialParsing, Syntax error, Lexical error): a
                         per-file Timeout, a skipped, failed or scanned-nothing
                         Semgrep, or any file not named, still exits 2. With
                         --base-url, DAST never probed routes in those spans.
                         CLI ARGV ONLY, like --start-command: a repository
                         file declaring it is refused.
  --baseline-ref <ref>  Read .guardian/baseline.json from the commit <ref> names
                         (git, never the working tree). For a pull request: its
                         base (the ci-init pipelines pass it), so the pull request
                         cannot add its own findings to the baseline it is gated
                         against. None at <ref> is no baseline; a <ref> that names
                         no commit (not fetched) is exit 3.
  --rules-ref <ref>     Read the project's Semgrep rules (.semgrep.yml/.yaml and
                         those .dev-guardian/configs.json records), .guardianignore,
                         .trivyignore and .bandit from <ref> instead of the tree:
                         a pull request cannot delete the rule that catches it.
                         .semgrepignore, .gitleaks.toml, .gitleaksignore, actionlint
                         and zizmor configuration and the .NET build's files are
                         still read from the tree — each one the tree changes
                         against <ref> is named in the report. See docs/ci.md.
  --reset-exclusions-from <ref>
                         In CI only (CI=true, or GITHUB_ACTIONS / GITLAB_CI /
                         BITBUCKET_BUILD_NUMBER; exit 3 elsewhere — it would
                         revert your own files): before scanning, put
                         every .semgrepignore the scan reads, .gitleaksignore and
                         .gitleaks.toml back to <ref>'s, deleting those <ref>
                         lacks — no scanner flag reads them from elsewhere. Refused
                         (exit 3) in a checkout with changes, for one of those
                         files git does not track, or through a link. The report
                         names what it reset.
  Never writes .guardian/baseline.json — see \`baseline update\`.
  Leaves .guardian/reports/ in the scanned project either way (security_scan_full
  and map_attack_surface write there, same as interactively) — add the two lines
  \`**/.guardian/*\` and \`!**/.guardian/baseline.json\` to .gitignore by hand
  (never a bare \`.guardian/\`: git cannot re-include a file below an ignored
  directory, so the baseline CI needs could never be committed; \`**/\` covers
  a sub-project's .guardian/ too). The MCP server writes
  them every time it starts against a project; this CLI never starts that server.
  --sarif records coverage as a single pass/fail bit (SARIF's own
  invocation.executionSuccessful) — enough to tell an incomplete run from a clean
  one without cross-referencing anything else, but not WHICH scanner was missing
  or why. That detail lives only in this command's own exit code and its
  human/JSON output — check them before trusting a SARIF upload that shows
  nothing.
  Exit codes: 0 pass, 1 gate failed (new finding >= --fail-on),
              2 incomplete scan (an expected scanner did not run),
              3 usage or configuration error.

baseline update — regenerate .guardian/baseline.json from the current scan
  Same pipeline flags as scan: --project, --base-url, --authorized-target,
  --local-only, --start-command (same argv-only rule, --base-url requirement, and
  teardown). No --fail-on/--format/--sarif — this command does not gate or
  render a report, it writes a file.
  The ONLY dev-guardian command that writes the baseline; scan never does.
  Exit codes: 0 written with full coverage, 2 written but an expected
              scanner did not run (baseline may under-represent findings),
              3 usage or configuration error.

ci-init <github|gitlab|bitbucket> — generate a CI pipeline for the project being scanned
  --project <path>     Target project directory (default: current directory)
  --branch <name>       Branch the GitHub template triggers on push for (default: main);
                        no effect on gitlab/bitbucket, which trigger on the repo's own
                        default branch without naming one
  --write               Write the pipeline file (default: preview to stdout)
  --force               With --write, overwrite an existing pipeline file
                        (without it, an existing file is left untouched).
                        Still refused (exit 3) when that file is a symlink
                        that resolves outside the project, or a broken one;
                        replaced in one step (temp file + rename), never
                        written through a link
  --attest              GitHub only (refused for gitlab/bitbucket, exit 3). The
                        pipeline also writes the JSON report and, on a push,
                        signs a SLSA build-provenance attestation of it and of
                        the SARIF (actions/attest-build-provenance, pinned by
                        SHA) in a separate job that alone holds id-token: write
                        and attestations: write. Needs a public repository, or
                        GitHub Enterprise Cloud for a private one. CLI ARGV ONLY,
                        like scan's --start-command: a .guardian/ci.json
                        declaring "attest" is refused.
                        It attests even when the gate failed (an attestation
                        proves origin, not a pass), after refusing an empty or
                        unreadable report. On a public repository the full JSON
                        report is printed to the public job log and the reports
                        artifact is downloadable by any signed-in GitHub user.
                        Verify a report: download the run's dev-guardian-reports
                        artifact, then
                          gh attestation verify dev-guardian-results.sarif \\
                            --repo OWNER/REPO \\
                            --signer-workflow OWNER/REPO/.github/workflows/dev-guardian.yml \\
                            --source-ref refs/heads/<branch>
                        (--signer-workflow names the file; a copy of it on
                        another branch signs as the same path.)
  Writes: github -> .github/workflows/dev-guardian.yml
          gitlab -> .gitlab-ci.yml
          bitbucket -> bitbucket-pipelines.yml
  Needs a \`git\` binary: resolves dev-guardian's release tag to its exact
  commit SHA (from this checkout's own tags when present — no network
  needed then — else over the network via \`git ls-remote\`) and bakes that
  SHA into the pipeline, which verifies it again with \`git rev-parse HEAD\`
  after cloning — a moving tag is a supply-chain risk (see the module's own
  doc comment); the resolved commit cannot move.
  The generated pipeline clones dev-guardian itself (outside the checkout
  being scanned — never into it, which would make the scan audit
  dev-guardian's own source as part of the target project) at that pinned
  commit, installs the scanner binaries \`dev-guardian scan\` drives (Trivy,
  gitleaks, actionlint pinned by version + sha256 + archive layout; bandit
  and semgrep/zizmor pinned by exact version via pipx), then runs
  \`dev-guardian scan\` gated against the COMMITTED baseline — run
  \`dev-guardian baseline update\` once locally and commit
  .guardian/baseline.json before relying on the generated gate. A .NET
  project needs the .NET SDK too: installed via actions/setup-dotnet on the
  github target; gitlab/bitbucket document the requirement instead of
  installing it (see each template's own header comment).
  NEVER generates a pipeline for dev-guardian's own repository — only for
  the project passed via --project (default: current directory), and
  never through a symlink that escapes it either way (read or write).
  Exit codes: 0 preview/write completed, 1 missing/unknown target or an
              existing pipeline file refused without --force, 3 usage or
              configuration error, or a --force refused on a symlink (same
              convention as scan/baseline update).

status — one-screen terminal summary of the latest scan for this project
  --project <path>      Target project directory (default: current directory)
  Read-only: never runs a scan, never mutates the database. Reports; does
  not gate — exits 0 even on a project full of findings, or one that has
  never been scanned (it then names the scan command to run instead).
  A snapshot of the latest scan, not live — it will not update when a later
  scan runs; re-run this command to see one. The window is that scan plus
  two deltas (since the previous scan of the same type, since the active
  baseline) — no multi-week trend.
  Exit codes: 0 always, except 3 on a usage error.

dashboard — writes a self-contained HTML report and prints its path
  --project <path>      Target project directory (default: current directory)
  --out <path>           Where to write the report (default: <project>/.guardian/dashboard.html)
  --no-open               Never launch a browser
  Opens the report in your default browser only when stdout is a TTY (never
  inside a pipeline/CI) and --no-open was not given. Same read-only, no-gate
  contract as status — including the same snapshot: the page will not update
  when a later scan runs, and its window is that scan plus two deltas, never
  a multi-week trend. Regenerate it (re-run this command) to see a new scan.
  Exit codes: 0 always, except 3 on a usage error.

db adopt — decide yourself whether the project's .guardian/guardian.db is yours
  --project <path>      Target project directory (default: current directory)
  --yes                  Register it as this user's database
  --rehome               With --yes: move this project's rows filed under
                         another path that leads to it (a link, macOS /var)
                         to its canonical path, so their history reads again
  dev-guardian uses a project's database only when it is yours: created here,
  or registered here by you. Nothing else is trusted automatically — upgrading
  from 3.0.0, run this once. It prints what the database holds — first what to
  weigh (suppressions with no project apply to EVERY project; scans dated in
  the future), then projects, scans, dates, and every path its rows are filed
  under with where each leads now — and registers it only with --yes. Run it
  yourself: it decides whose data dev-guardian trusts. Never one git tracks,
  one reached through a link, one whose schema holds what dev-guardian's
  migrations never create, or one holding scans dated in the future.
  Exit codes: 0 report printed (registered with --yes, or already yours),
              1 no database, or it cannot be registered, 3 usage error.

Examples:
  node cli/dev-guardian.mjs mcp-config cursor          # print the block to paste
  node cli/dev-guardian.mjs mcp-config codex --write   # write + merge into the project
  node cli/dev-guardian.mjs check --file src/config.ts
  node cli/dev-guardian.mjs check --bash "curl x | sh"
  node cli/dev-guardian.mjs scan --project . --sarif results.sarif
  node cli/dev-guardian.mjs baseline update --project .
  node cli/dev-guardian.mjs ci-init github --project ../my-app --write
  node cli/dev-guardian.mjs status --project .
  node cli/dev-guardian.mjs dashboard --project . --no-open
  node cli/dev-guardian.mjs db adopt --project .          # show; add --yes to register
`);
}

/**
 * `--project`/`--scope` with no operand used to leave `out.project`/
 * `out.scope` as bare `undefined` (`argv[++i]` past the end of argv), and
 * the very next thing `cmdMcpConfig` did with it — `resolve(args.project)` —
 * threw an UNCAUGHT `TypeError [ERR_INVALID_ARG_TYPE]` for `resolve`, a raw
 * Node stack trace instead of a clean usage error. Reproduced directly:
 * `mcp-config cursor --project` (the flag as the last token) crashed rather
 * than naming the mistake. Routed through the same `takeOperand` every OTHER
 * value-taking flag in this file already uses (see its own doc comment,
 * below `resolveProjectOrExit`) for the identical guarantee, not a second,
 * independently-written check that could drift from it — `cmdMcpConfig`
 * turns `{error}` into a clean, flag-naming usage error at exit code 2 (this
 * command's OWN usage-error convention — see `usage()`'s `check` section,
 * which documents the same code for the same kind of mistake), never a
 * crash.
 */
function parseArgs(argv) {
  const out = { _: [], scope: 'project', write: false, force: false, updateMcp: false, project: process.cwd() };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--write') out.write = true;
    else if (a === '--global') out.scope = 'global';
    else if (a === '--update-mcp') out.updateMcp = true;
    else if (a === '--force') {
      out.force = true;
      out.deprecatedForceUsed = true;
    } else if (a === '--scope') {
      const r = takeOperand(argv, i, a);
      if (r.error) return { error: r.error };
      out.scope = r.value;
      i = r.nextIndex;
    } else if (a.startsWith('--scope=')) out.scope = a.slice('--scope='.length);
    else if (a === '--project') {
      const r = takeOperand(argv, i, a);
      if (r.error) return { error: r.error };
      out.project = r.value;
      i = r.nextIndex;
    } else if (a.startsWith('--project=')) out.project = a.slice('--project='.length);
    else out._.push(a);
  }
  if (out.scope !== 'project' && out.scope !== 'global') out.scope = 'project';
  // `--force` is a deprecated alias of `--update-mcp` (item 6b): both drive
  // the exact same underlying `force` behaviour downstream (a stale MCP
  // entry / rules block gets updated in place), so they collapse to one
  // flag here rather than `setupHost` having to know about two names for
  // the same thing.
  out.force = out.force || out.updateMcp;
  return { value: out };
}

function indent(s) {
  return s
    .split('\n')
    .map((l) => `    ${l}`)
    .join('\n');
}

function cmdMcpConfig(argv) {
  const parsed = parseArgs(argv);
  if (parsed.error) {
    // This command's own usage-error convention (see `usage()`'s `check`
    // section, which documents the same code for the same kind of mistake) —
    // exit 2, never the uncaught TypeError this replaces.
    process.stderr.write(`error: ${parsed.error}\n\n`);
    usage();
    process.exit(2);
  }
  const args = parsed.value;
  if (args.deprecatedForceUsed) {
    process.stderr.write('warning: --force is deprecated; use --update-mcp instead.\n');
  }
  const hostArg = args._[0];
  if (!hostArg || !VALID_HOSTS.has(hostArg)) {
    process.stderr.write(`Missing or unknown host: ${hostArg ?? '(none)'}\n\n`);
    usage();
    process.exit(1);
  }
  if (!existsSync(SERVER_JS)) {
    process.stderr.write(
      `MCP server not built: ${SERVER_JS}\nRun once:  cd mcp && npm install && npm run build\n`,
    );
    process.exit(1);
  }

  const projectPath = resolve(args.project);
  const env = { os: detectOs(), home: homedir(), appData: process.env.APPDATA, projectPath };
  const hosts = hostArg === 'all' ? [...ALL_HOSTS] : [hostArg];

  if (args.write) {
    const results = setupHost({
      hosts: [hostArg],
      projectPath,
      hostsDir: HOST_RULES_DIR,
      serverJsPath: SERVER_JS,
      cliPath: CLI_JS,
      env,
      scope: args.scope,
      registerMcp: true,
      installRules: true,
      apply: true,
      force: args.force,
    });
    for (const r of results) {
      process.stdout.write(`\n## ${r.host} (${r.scope})\n`);
      process.stdout.write(
        `  mcp:   ${r.mcp.status}${r.mcp.config_path ? `  -> ${r.mcp.config_path}` : ''}` +
          `${r.mcp.reason ? `  (${r.mcp.reason})` : ''}\n`,
      );
      process.stdout.write(
        `  rules: ${r.status}${r.target_path ? `  -> ${r.target_path}` : ''}` +
          `${r.reason ? `  (${r.reason})` : ''}\n`,
      );
      if (r.mcp.snippet) process.stdout.write(`  snippet:\n${indent(r.mcp.snippet)}\n`);
    }
    process.stdout.write('\nRestart the host so it re-reads its MCP config + rules.\n');
  } else {
    for (const host of hosts) {
      const p = previewMcpConfig(host, args.scope, SERVER_JS, env);
      const where = p.config_path
        ? `  ->  ${p.config_path}`
        : p.manual
          ? '  (manual — paste into the host MCP settings)'
          : '';
      process.stdout.write(`\n# ${host}${where}\n`);
      if (p.rules_target) {
        process.stdout.write(`# rules file: copy host-rules/ template to ${p.rules_target}\n`);
      }
      process.stdout.write(`${p.block}\n`);
    }
    process.stdout.write('\n# Paste each block at the path shown, or re-run with --write to apply.\n');
  }
}

/**
 * `check`'s arguments, or `{ error }` — a usage error, exit 2 (review of
 * 3.0.0, M3). Every argument is accounted for: `--file` together with
 * `--bash` used to print the command's verdict and ignore the file (`check
 * --file short.js --bash ls` read "OK", exit 0), `--min bogus` quietly became
 * `medium`, and an unknown flag (`--jsn`) or a stray word was accepted.
 */
function parseCheckArgs(argv) {
  const out = { file: undefined, bash: undefined, min: undefined, json: false, powershell: false };
  const valued = { '--file': 'file', '--bash': 'bash', '--min': 'min' };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const eq = a.indexOf('=');
    const flag = a.startsWith('--') && eq > 0 ? a.slice(0, eq) : a;
    const key = valued[flag];
    if (key !== undefined) {
      let value;
      if (flag !== a) value = a.slice(eq + 1);
      else {
        value = argv[i + 1];
        i += 1;
      }
      if (value === undefined) return { error: `${flag} needs a value` };
      if (out[key] !== undefined) return { error: `${flag} was given twice` };
      out[key] = value;
    } else if (a === '--json') out.json = true;
    else if (a === '--powershell') out.powershell = true;
    else return { error: `unknown argument: ${a}` };
  }
  if (out.file !== undefined && out.bash !== undefined) {
    return { error: '--file and --bash cannot be combined — run check once for each' };
  }
  if (out.min !== undefined && out.min !== 'high' && out.min !== 'medium') {
    return { error: `--min must be high or medium (got '${out.min}')` };
  }
  if (out.min !== undefined && out.bash !== undefined) return { error: '--min applies to --file only' };
  if (out.powershell && out.file !== undefined) return { error: '--powershell applies to --bash only' };
  return { value: { ...out, min: out.min ?? 'medium' } };
}

/** The largest `.guardian/*.json` configuration the CLI reads; a real one is a few KB. */
const MAX_REPO_CONFIG_BYTES = 1024 * 1024;

/**
 * A JSON file inside the repository, parsed — or `null` when it is absent,
 * not JSON, or refused. Read through `platform/projectFs.ts`: bounded,
 * regular files only, never through a link out of the repository. Every
 * caller is lenient by design (a missing or broken file is "no config"), and
 * a checkout a pull request controls can put a FIFO or a `/dev/zero` link at
 * any of these names — `readFileSync` blocked on the first and read the
 * second without end, until the CI job's own timeout.
 */
function readRepoJson(projectPath, relPath) {
  const r = readProjectText(projectPath, relPath, MAX_REPO_CONFIG_BYTES);
  if (r.status !== 'ok') return null;
  try {
    return JSON.parse(r.text);
  } catch {
    return null;
  }
}

function loadAllowlist(projectDir) {
  const data = readRepoJson(projectDir, join('.guardian', 'hooks-allowlist.json'));
  if (Array.isArray(data)) return data.filter((x) => typeof x === 'string');
  if (data && Array.isArray(data.secrets)) return data.secrets.filter((x) => typeof x === 'string');
  return [];
}

function cmdCheck(argv) {
  const parsed = parseCheckArgs(argv);
  if (parsed.error !== undefined) {
    process.stderr.write(`check: ${parsed.error}\n\n`);
    usage();
    process.exit(2);
  }
  const opts = parsed.value;

  if (opts.bash != null) {
    const a = assessBashCommand(opts.bash, { shell: opts.powershell ? 'powershell' : 'bash' });
    if (opts.json) {
      process.stdout.write(JSON.stringify(a) + '\n');
    } else {
      const icon = a.level === 'block' ? '⛔' : a.level === 'warn' ? '⚠️ ' : '✅';
      process.stdout.write(`${icon} ${a.level.toUpperCase()}\n`);
      for (const r of a.reasons) process.stdout.write(`  • ${untrustedText(r)}\n`);
    }
    process.exit(a.level === 'ok' ? 0 : 1);
  }

  if (opts.file != null) {
    const filePath = resolve(opts.file);
    if (!existsSync(filePath)) {
      process.stderr.write(`No such file: ${filePath}\n`);
      process.exit(2);
    }
    let text = '';
    try {
      // UTF-16 by byte-order mark or NUL-interleaving (PowerShell 5.1's `>`
      // and `Out-File` default), else UTF-8: read as UTF-8, a UTF-16 file
      // put a NUL between every character and hid every key (review M3).
      text = decodeText(readFileSync(filePath));
    } catch (e) {
      process.stderr.write(`Cannot read ${filePath}: ${e instanceof Error ? e.message : String(e)}\n`);
      process.exit(2);
    }
    const allowlist = loadAllowlist(process.cwd());
    const hits = scanForSecrets(text, { minConfidence: opts.min, allowlist });
    if (opts.json) {
      process.stdout.write(JSON.stringify({ file: filePath, hits }) + '\n');
    } else if (hits.length === 0) {
      process.stdout.write(`✅ No secrets detected in ${untrustedText(opts.file, { multiline: false })}\n`);
    } else {
      // The file's name and what matched in it are the repository's text:
      // control, bidi and zero-width characters are written as visible
      // `\u{XXXX}` before they reach the terminal (`platform/untrustedText.ts`).
      process.stdout.write(`⚠️  ${hits.length} possible secret(s) in ${untrustedText(opts.file, { multiline: false })}:\n`);
      for (const h of hits) {
        process.stdout.write(
          `  • ${untrustedText(h.title)} (${h.confidence}) — line ${h.line}: ${untrustedText(h.preview, { multiline: false })}\n`,
        );
      }
    }
    process.exit(hits.length > 0 ? 1 : 0);
  }

  process.stderr.write('check: provide --file <path> or --bash "<command>"\n\n');
  usage();
  process.exit(2);
}

// --- scan / baseline update (headless CI) ---------------------------------

/**
 * Print a one-line error to stderr and exit 3 (USAGE_ERROR_EXIT). Every
 * usage/configuration problem `cmdScan`/`cmdBaseline` can detect — an
 * unrecognised flag, a bad flag value, a missing project directory,
 * `--start-command` without `--base-url`, the pwn-request guard, a failure
 * anywhere in the pipeline (including starting the application) — goes
 * through this one function, so there is exactly one place that decides the
 * wording ("error: " prefix) and the exit code for all of them.
 */
function usageError(message) {
  process.stderr.write(`error: ${message}\n`);
  process.exit(USAGE_ERROR_EXIT);
}

/**
 * `mcp/dist/ci/*.js` (and the pre-existing `mcp/dist/types.js`) are loaded
 * lazily with dynamic `import()`, never a static top-of-file `import` like
 * this file's other dependencies. A static import that fails aborts the
 * whole process before a single line of this file's own code runs — INCLUDING
 * a friendly `existsSync` check placed after it in the source — so a repo
 * that has never run `cd mcp && npm run build` would otherwise see a raw
 * Node `ERR_MODULE_NOT_FOUND` stack trace on `dev-guardian scan` instead of
 * a message that says what to do. Awaited only from inside `cmdScan` /
 * `cmdBaseline`, so `mcp-config` and `check` are completely unaffected.
 */
async function loadCiModules() {
  const marker = resolve(ROOT, 'mcp', 'dist', 'ci', 'types.js');
  if (!existsSync(marker)) {
    process.stderr.write(
      `dev-guardian: MCP server not built (missing ${marker}).\n` +
        'Run once:  cd mcp && npm install && npm run build\n',
    );
    process.exit(USAGE_ERROR_EXIT);
  }
  const [ciTypes, baseline, gate, report, runScansMod, appRunner, types, refConfig] = await Promise.all([
    import('../mcp/dist/ci/types.js'),
    import('../mcp/dist/ci/baseline.js'),
    import('../mcp/dist/ci/gate.js'),
    import('../mcp/dist/ci/report.js'),
    import('../mcp/dist/ci/runScans.js'),
    import('../mcp/dist/ci/appRunner.js'),
    import('../mcp/dist/types.js'),
    import('../mcp/dist/ci/refConfig.js'),
  ]);
  return {
    CI_EXIT: ciTypes.CI_EXIT,
    BASELINE_RELATIVE_PATH: baseline.BASELINE_RELATIVE_PATH,
    parseBaseline: baseline.parseBaseline,
    buildBaseline: baseline.buildBaseline,
    serialiseBaseline: baseline.serialiseBaseline,
    evaluateGate: gate.evaluateGate,
    exitCodeForCoverage: gate.exitCodeForCoverage,
    renderHuman: report.renderHuman,
    renderJson: report.renderJson,
    renderSarif: report.renderSarif,
    runScans: runScansMod.runScans,
    startApp: appRunner.startApp,
    SEVERITIES: types.SEVERITIES,
    resolveCiRef: refConfig.resolveCiRef,
    readBaselineAtRef: refConfig.readBaselineAtRef,
    resetExclusionsFromRef: refConfig.resetExclusionsFromRef,
  };
}

/**
 * Default budget for `--start-command` to become healthy — generous for a
 * typical `npm start`/build-then-serve boot (which can genuinely take tens
 * of seconds under a cold cache) while still bounded: the design of record and the
 * app-runner module both exist because "a hang is the worst failure mode in
 * CI" (a job that never finishes burns its whole budget and the log says
 * nothing). Not exposed as a flag — the brief scopes `--start-command` to
 * argv + `--base-url` only, and a fixed, documented default is simpler than
 * a knob nobody asked for; revisit if a real pipeline needs a slower boot.
 */
const APP_START_TIMEOUT_MS = 60_000;

/**
 * `.guardian/baseline.json`'s text, `null` when there is none — or a usage
 * error when one is there and was refused (a link out of the repository, a
 * FIFO, a device, or larger than a lockfile may be). Refused is NOT read as
 * "no baseline": the committed baseline is what the gate subtracts, and a
 * pull request must not be able to swap in a file from outside the checkout,
 * nor make the job wait on a FIFO.
 */
function readBaselineOrExit(projectPath, relPath) {
  const r = readProjectText(projectPath, relPath, PROJECT_LOCKFILE_MAX_BYTES);
  if (r.status === 'ok') return r.text;
  if (r.status === 'absent') return null;
  return usageError(`${relPath} was not read: ${describeReadRefusal(r.reason)}`);
}

/**
 * The pwn-request guard (the design of record). `--start-command` may be supplied
 * only on argv — never honoured from a file inside the scanned repository,
 * because that file can arrive via a pull request from a fork, and a CLI
 * that read a command to run from it would hand that fork arbitrary code
 * execution on the CI runner. Returns the resolved config path when it
 * declares `start_command` (the caller refuses and names it), else `null`.
 *
 * Deliberately lenient on anything OTHER than a clearly-declared
 * `start_command`: a missing file, unreadable file, or malformed JSON is
 * treated the same as "no config" (matches this file's own existing
 * `loadAllowlist` precedent for optional `.guardian/` JSON) rather than
 * itself becoming a hard failure — the security property this function
 * exists for is "never silently RUN a repo-declared command", not "every
 * repository must carry a well-formed ci.json".
 */
function findStartCommandInRepoConfig(projectPath) {
  const configPath = resolve(projectPath, CI_CONFIG_RELATIVE_PATH);
  const data = readRepoJson(projectPath, CI_CONFIG_RELATIVE_PATH);
  if (data && typeof data === 'object' && !Array.isArray(data) && data.start_command) {
    return configPath;
  }
  return null;
}

function startCommandRefusalMessage(configPath) {
  return (
    `refusing to run: '${CI_CONFIG_RELATIVE_PATH}' declares "start_command" (found at ${configPath}). ` +
    '--start-command may only be supplied on the command line, never from a file inside the ' +
    'repository — a pull request from a fork could otherwise edit this file and run arbitrary ' +
    `code on the CI runner. Remove start_command from ${CI_CONFIG_RELATIVE_PATH} and pass ` +
    '--start-command as a command-line argument instead.'
  );
}

/**
 * `--accept-partial-parse` is argv-only too, by the same rule as
 * `--start-command`: it widens what the gate lets through, and a repository
 * file a fork's pull request can edit must never do that. A
 * `.guardian/ci.json` declaring `accept_partial_parse` is refused outright —
 * loudly, rather than read or silently ignored. Returns the config path when
 * it declares the key, else `null`; lenient on everything else, like
 * `findStartCommandInRepoConfig`.
 */
function findAcceptPartialParseInRepoConfig(projectPath) {
  const configPath = resolve(projectPath, CI_CONFIG_RELATIVE_PATH);
  const data = readRepoJson(projectPath, CI_CONFIG_RELATIVE_PATH);
  if (data && typeof data === 'object' && !Array.isArray(data) && data.accept_partial_parse !== undefined) {
    return configPath;
  }
  return null;
}

function acceptPartialParseRefusalMessage(configPath) {
  return (
    `refusing to run: '${CI_CONFIG_RELATIVE_PATH}' declares "accept_partial_parse" (found at ${configPath}). ` +
    '--accept-partial-parse may only be supplied on the command line, never from a file inside the ' +
    'repository — a pull request could otherwise edit this file and turn a scan gap into a pass. ' +
    `Remove accept_partial_parse from ${CI_CONFIG_RELATIVE_PATH} and pass --accept-partial-parse <path> ` +
    'in the pipeline definition instead.'
  );
}

/**
 * Why a `--accept-partial-parse` value cannot name a project file, or null.
 * The gate matches it exactly against project-relative paths, so an absolute
 * path or one climbing out with `..` could never match anything — refused as
 * a usage error rather than accepted and silently useless. Backslashes and a
 * leading `./` are fine (the gate normalises both); globs are not expanded,
 * so `*.php` is the literal file name `*.php`.
 */
function checkAcceptedPartialParse(value) {
  const posix = value.replace(/\\/g, '/');
  if (isAbsolute(value) || posix.startsWith('/') || /^[A-Za-z]:/.test(value)) {
    return `--accept-partial-parse takes a path relative to --project, not an absolute one (got '${value}')`;
  }
  if (posix.split('/').includes('..')) {
    return `--accept-partial-parse takes a path inside --project; '..' cannot name a scanned file (got '${value}')`;
  }
  return null;
}

/** Shared by `parseScanArgs`/`parseBaselineUpdateArgs`: `--start-command`
 *  consumes the REST of argv as the command's own argv (never a shell
 *  string), so it must be the last flag handled and must stop the loop —
 *  otherwise a plausible token after it (say, another `--flag`-looking
 *  argument meant for the started app) would be mis-parsed as one of THIS
 *  CLI's own flags instead of being passed straight through. */
function consumeStartCommand(argv, i) {
  return argv.slice(i + 1);
}

/**
 * Whether `value` counts as "no operand at all" for a flag that requires
 * one. Always true for `undefined` (the flag was the last token — see
 * `takeOperand` below). Also true for the empty string, but ONLY when the
 * caller opts in via `requireNonEmpty` — empty is not automatically
 * "missing" for every flag: `--base-url ""` / `--base-url=` is a real,
 * meaningful value (`scan_dast` reads it, refuses with `unsupported_target:
 * \`\` is not a valid URL`, and that refusal becomes a genuine, correctly
 * exit-2 coverage gap — confirmed by running it), and turning that into a
 * blanket usage error here would silently change a working, tested exit
 * code. `--sarif`, by contrast, has no such reading: there is no such thing
 * as writing a SARIF report to an empty path on purpose, so an empty value
 * is exactly as much "not given" as an absent one. Shared by BOTH of
 * `--sarif`'s spellings — the two-token form (`--sarif ""`, via
 * `takeOperand`) and the same-token form (`--sarif=`, checked inline where
 * that branch slices the value out) — because an unset CI variable collapses
 * `--sarif $SARIF_PATH` and `--sarif=$SARIF_PATH` to these two shapes
 * respectively, and a user must get the same refusal regardless of which one
 * their pipeline happened to write.
 */
function isMissingOperand(value, requireNonEmpty) {
  return value === undefined || (requireNonEmpty === true && value === '');
}

/**
 * The one operand-taking helper `parseScanArgs`/`parseBaselineUpdateArgs`
 * both call for EVERY value-taking flag (`--project`, `--fail-on`,
 * `--format`, `--sarif`, `--base-url`) — not two independent copies of the
 * same check, one per parser, which is exactly how this bug happened in the
 * first place: `--sarif` and `--base-url` each had their own bare
 * `argv[++i]`, with nothing guarding the case where there is no next token.
 *
 * `argv[i]` is the flag itself (already matched by the caller as `a`);
 * `argv[i + 1]` is where its value must live for the two-token form (`--x
 * value`, as opposed to the same-token `--x=value` form, which can never hit
 * the UNDEFINED case this guards — its value is embedded in `a` itself, so
 * there is nothing to look ahead for; it can still be EMPTY, handled by its
 * own branch calling `isMissingOperand` directly — see `--sarif=` in
 * `parseScanArgs`). When `--x` is the LAST token on the command line — or,
 * for `baseUrl` specifically, an unset/mistyped CI env var expanded to
 * nothing (`--base-url $STAGING_URL` with `STAGING_URL` empty in the
 * shell's own eyes, so the shell drops the token entirely rather than
 * passing an empty string) — `argv[i + 1]` is `undefined`. Every call site
 * used to assign that `undefined` straight into `out`, indistinguishable
 * downstream from "this flag was never passed at all": `if (opts.sarif)` is
 * falsy either way, and `runScans.ts#buildSequence`'s
 * `opts.baseUrl !== undefined` check drops `scan_dast` either way — both
 * SILENT, both still `coverage: full`, exit 0. `--fail-on`/`--format`
 * happened to escape only because something ELSE, downstream, separately
 * rejects `undefined` too (`SEVERITIES.includes`, the `human`/`json`
 * check) — an accident of validation order, not a guarantee, and
 * `--project` escaped only via the ugly path of `resolve(undefined)`
 * throwing and landing in the generic `fatal()` catch-all. Refusing right
 * here, once, makes it a guarantee for every flag instead of a coincidence
 * for some of them, and gives `--project` the same clean, flag-naming usage
 * error as the rest.
 *
 * `requireNonEmpty` (default false): passed through to `isMissingOperand`
 * so a caller can additionally refuse an EXPLICIT empty value (`--sarif
 * ""`), not just an absent one — see that function's own doc for which
 * flags this is (and, just as deliberately, is not) appropriate for.
 *
 * Returns `{ error }` — a complete message, ready for `usageError` with no
 * second prefix needed — or `{ value, nextIndex }`, where `nextIndex` is the
 * loop index to resume from (the consumed value token), matching the
 * pre-increment `argv[++i]` this replaces.
 */
function takeOperand(argv, i, flagName, requireNonEmpty = false) {
  const nextIndex = i + 1;
  const value = argv[nextIndex];
  if (isMissingOperand(value, requireNonEmpty)) {
    return { error: `${flagName} requires a value` };
  }
  return { value, nextIndex };
}

function parseScanArgs(argv) {
  const out = {
    project: process.cwd(),
    failOn: 'high',
    format: 'human',
    sarif: undefined,
    baseUrl: undefined,
    authorizedTarget: false,
    localOnly: false,
    startCommand: undefined,
    acceptPartialParse: [],
    baselineRef: undefined,
    rulesRef: undefined,
    resetExclusionsFrom: undefined,
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const ref = refFlag(a);
    if (ref !== null) {
      // requireNonEmpty: an unset CI variable (`--baseline-ref "$BASE"`) must
      // not silently fall back to the tree's own baseline — exit 3 instead.
      let value;
      if (a === ref.flag) {
        const r = takeOperand(argv, i, a, true);
        if (r.error) return r;
        value = r.value;
        i = r.nextIndex;
      } else {
        value = a.slice(ref.flag.length + 1);
        if (isMissingOperand(value, true)) return { error: `${ref.flag} requires a value` };
      }
      out[ref.key] = value;
    } else if (a === '--project') {
      const r = takeOperand(argv, i, a);
      if (r.error) return r;
      out.project = r.value;
      i = r.nextIndex;
    } else if (a.startsWith('--project=')) out.project = a.slice('--project='.length);
    else if (a === '--accept-partial-parse' || a.startsWith('--accept-partial-parse=')) {
      // Repeatable; each value a project-relative file (see
      // `checkAcceptedPartialParse`). requireNonEmpty: an unset CI variable
      // must not silently accept nothing and read as if it had.
      let value;
      if (a === '--accept-partial-parse') {
        const r = takeOperand(argv, i, a, true);
        if (r.error) return r;
        value = r.value;
        i = r.nextIndex;
      } else {
        value = a.slice('--accept-partial-parse='.length);
        if (isMissingOperand(value, true)) return { error: '--accept-partial-parse requires a value' };
      }
      const problem = checkAcceptedPartialParse(value);
      if (problem) return { error: problem };
      out.acceptPartialParse.push(value);
    } else if (a === '--fail-on') {
      const r = takeOperand(argv, i, a);
      if (r.error) return r;
      out.failOn = r.value;
      i = r.nextIndex;
    } else if (a.startsWith('--fail-on=')) out.failOn = a.slice('--fail-on='.length);
    else if (a === '--format') {
      const r = takeOperand(argv, i, a);
      if (r.error) return r;
      out.format = r.value;
      i = r.nextIndex;
    } else if (a.startsWith('--format=')) out.format = a.slice('--format='.length);
    else if (a === '--sarif') {
      // requireNonEmpty: true — an empty path is never a real destination
      // (unlike --base-url's empty string, which scan_dast reads and
      // meaningfully refuses), so --sarif "" is refused exactly like a
      // missing --sarif, not silently accepted as "write to ''".
      const r = takeOperand(argv, i, a, true);
      if (r.error) return r;
      out.sarif = r.value;
      i = r.nextIndex;
    } else if (a.startsWith('--sarif=')) {
      const value = a.slice('--sarif='.length);
      if (isMissingOperand(value, true)) return { error: '--sarif requires a value' };
      out.sarif = value;
    } else if (a === '--base-url') {
      const r = takeOperand(argv, i, a);
      if (r.error) return r;
      out.baseUrl = r.value;
      i = r.nextIndex;
    } else if (a.startsWith('--base-url=')) out.baseUrl = a.slice('--base-url='.length);
    else if (a === '--authorized-target') out.authorizedTarget = true;
    else if (a === '--local-only') out.localOnly = true;
    else if (a === '--start-command') {
      out.startCommand = consumeStartCommand(argv, i);
      break;
    } else return { error: `Unknown flag: ${a}` };
  }
  return { value: out };
}

/**
 * `--baseline-ref` / `--rules-ref` in either spelling (`--x v`, `--x=v`), or
 * null. Both take a git ref and are read against the scanned project's
 * repository (`mcp/src/ci/refConfig.ts`).
 */
function refFlag(a) {
  for (const [flag, key] of [
    ['--baseline-ref', 'baselineRef'],
    ['--rules-ref', 'rulesRef'],
    ['--reset-exclusions-from', 'resetExclusionsFrom'],
  ]) {
    if (a === flag || a.startsWith(`${flag}=`)) return { flag, key };
  }
  return null;
}

function parseBaselineUpdateArgs(argv) {
  const out = {
    project: process.cwd(),
    baseUrl: undefined,
    authorizedTarget: false,
    localOnly: false,
    startCommand: undefined,
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--project') {
      const r = takeOperand(argv, i, a);
      if (r.error) return r;
      out.project = r.value;
      i = r.nextIndex;
    } else if (a.startsWith('--project=')) out.project = a.slice('--project='.length);
    else if (a === '--base-url') {
      const r = takeOperand(argv, i, a);
      if (r.error) return r;
      out.baseUrl = r.value;
      i = r.nextIndex;
    } else if (a.startsWith('--base-url=')) out.baseUrl = a.slice('--base-url='.length);
    else if (a === '--authorized-target') out.authorizedTarget = true;
    else if (a === '--local-only') out.localOnly = true;
    else if (a === '--start-command') {
      out.startCommand = consumeStartCommand(argv, i);
      break;
    } else return { error: `Unknown flag: ${a}` };
  }
  return { value: out };
}

/**
 * Mirrors `mcp/src/platform/projectPath.ts`'s own `isRootOrHome` exactly
 * (coordinator review, Minor): every MCP tool resolves its `project_path`
 * through `resolveProjectPath`, which refuses a filesystem root or the
 * user's home directory outright — mass scans starting there are almost
 * always a mistake and can take hours. This CLI's own `resolveProjectOrExit`
 * (below) checked existence/directory-ness only, so `--project /` (or
 * `--project ~`) proceeded here where the identical input refuses through an
 * MCP host. Deliberately NOT the same function as `resolveProjectPath` (that
 * one throws `InvalidProjectPathError` for a caller that turns it into a
 * tool response; this CLI turns every usage problem into `usageError`/exit
 * 3) — but the RULE itself must be identical, so it is ported rather than
 * re-invented.
 */
function isRootOrHome(p) {
  // Filesystem root (e.g. "C:\\" or "/").
  if (parse(p).root === p) return true;
  // User home root (e.g. "/home/foo" or "C:\\Users\\foo").
  const home = resolve(homedir());
  return p === home;
}

/**
 * Steps shared by `cmdScan` and `cmdBaseline` before either one runs the
 * pipeline: resolve+validate `--project`, then the pwn-request guard, then
 * `--start-command`'s own usage rules. Order matters — the repo-config guard
 * runs unconditionally (regardless of what argv says) and BEFORE anything
 * argv-specific, so a malicious repository file can never be shadowed by
 * "well argv didn't ask for it anyway".
 */
function resolveProjectOrExit(rawProject) {
  const projectPath = resolve(rawProject);
  if (!existsSync(projectPath) || !statSync(projectPath).isDirectory()) {
    return usageError(`--project does not exist or is not a directory: ${projectPath}`);
  }
  if (isRootOrHome(projectPath)) {
    return usageError(
      `--project must not be a filesystem root or the user's home directory: ${projectPath}`,
    );
  }
  return projectPath;
}

function enforceStartCommandRules(projectPath, opts) {
  const offendingConfig = findStartCommandInRepoConfig(projectPath);
  if (offendingConfig) return usageError(startCommandRefusalMessage(offendingConfig));

  if (opts.startCommand !== undefined) {
    if (opts.startCommand.length === 0) {
      return usageError('--start-command requires a command (e.g. --start-command node server.js)');
    }
    if (!opts.baseUrl) {
      // The health URL `startApp` polls and the `scan_dast` target are the
      // same origin (resolution recorded in the task report) — there is
      // nothing else for --base-url to name once the app is started for
      // you, so this is a real usage mistake, not a missing capability.
      return usageError(
        '--start-command requires --base-url: it is used both as the health-check URL that ' +
          'confirms the app came up and as the scan_dast target once it has. Pass --base-url ' +
          'pointing at the origin --start-command will make the app listen on.',
      );
    }
  }
}

/**
 * Registers SIGINT/SIGTERM handlers for the lifetime of an app-lifecycle
 * block (coordinator review, Finding 3): interrupting the CLI — a cancelled
 * CI job (SIGTERM) or a developer's Ctrl-C (SIGINT) — must not orphan the
 * application `--start-command` started. Neither `appRunner.ts`'s own
 * safety nets reach this on POSIX: execa's `cleanup` option is inert once
 * `detached: true` is set (confirmed by reading execa's source — see the
 * task report), and `detached` puts the child outside the terminal's own
 * foreground process group, so it does not even receive the terminal's own
 * Ctrl-C. Nothing but an explicit handler here closes that gap. Verified
 * directly in a Linux container: without this, SIGINT/SIGTERM to the CLI
 * left the started application running; with it, gone.
 *
 * `signal` is threaded into `startApp` so an interrupt arriving WHILE the
 * app is still starting (before `getApp()` has anything to return yet)
 * cancels that wait too, instead of leaving the just-spawned process to be
 * found only once `startApp`'s own timeout eventually elapses. That case
 * needs its OWN handling, not just `getApp()`: `getStartingApp()` exposes
 * the in-flight `startApp()` promise itself, and the handler AWAITS it
 * (swallowing its now-expected rejection) rather than calling
 * `process.exit()` right after requesting the abort. This is not a
 * refinement — it was a real, caught bug: `controller.abort()` only
 * *requests* that `startApp` clean up after itself; the clean-up
 * (`waitForHealthy` noticing the abort, then `stop()`ing whatever it
 * spawned, INSIDE `startApp`'s own catch block, all before its promise
 * settles) still takes a moment to actually run. Calling `process.exit()`
 * immediately after the abort — this module's own first version — tore
 * the whole CLI process down before that in-flight cleanup got to finish,
 * leaving the just-started application running. Caught in a Linux
 * container, not by inspection: `SIGTERM: started app is GONE ... FAIL —
 * pid N still alive`, sent while the app was still mid-health-check.
 * Awaiting the SAME promise `cmdScan`/`cmdBaseline`'s own try block is
 * already awaiting guarantees this handler cannot outrun it.
 *
 * The returned `isInterrupted()` exists because this handler calls
 * `process.exit()` itself, with the conventional 128+signum shell code —
 * the caller's own normal exit-code logic (a gate verdict, a usage error)
 * must not ALSO run afterwards for a scan the user explicitly cancelled;
 * checking this flag after the try/finally block is how the caller yields
 * to whichever exit path actually applies.
 */
function armInterruptTeardown(getApp, getStartingApp) {
  const controller = new AbortController();
  let interrupted = false;
  const onSignal = (exitCode) => () => {
    interrupted = true;
    void (async () => {
      controller.abort();
      const app = getApp();
      if (app) {
        // Already running: this handler owns the only handle to it, so it
        // stops it directly rather than waiting on anything else.
        try {
          await app.stop();
        } catch {
          /* the process is exiting regardless; best-effort */
        }
      } else {
        // Not yet running: `controller.abort()` above is what makes the
        // IN-FLIGHT `startApp()` call clean up after itself — awaiting
        // that same call (not a fresh `app.stop()`, there is no `app` yet)
        // is how this handler waits for that real cleanup instead of
        // outrunning it. Its rejection here is the expected, ordinary
        // shape of a cancelled start, not a new failure to report.
        const pending = getStartingApp();
        if (pending) {
          try {
            await pending;
          } catch {
            /* expected: this is what an aborted startApp() looks like */
          }
        }
      }
      process.exit(exitCode);
    })();
  };
  const onSigint = onSignal(130); // 128 + SIGINT(2) — the conventional shell code
  const onSigterm = onSignal(143); // 128 + SIGTERM(15)
  process.on('SIGINT', onSigint);
  process.on('SIGTERM', onSigterm);
  return {
    signal: controller.signal,
    isInterrupted: () => interrupted,
    dispose: () => {
      process.off('SIGINT', onSigint);
      process.off('SIGTERM', onSigterm);
    },
  };
}

async function cmdScan(argv) {
  const parsed = parseScanArgs(argv);
  // parseScanArgs's own `error` is already a complete, flag-naming message
  // (an unknown flag, or a value-taking flag with no operand) — no second
  // prefix needed here.
  if (parsed.error) return usageError(parsed.error);
  const opts = parsed.value;

  const ci = await loadCiModules();
  const {
    parseBaseline,
    evaluateGate,
    renderHuman,
    renderJson,
    renderSarif,
    runScans,
    startApp,
    BASELINE_RELATIVE_PATH,
    SEVERITIES,
    resolveCiRef,
    readBaselineAtRef,
    resetExclusionsFromRef,
  } = ci;

  if (!SEVERITIES.includes(opts.failOn)) {
    return usageError(`--fail-on must be one of ${SEVERITIES.join('|')} (got '${opts.failOn}')`);
  }
  if (opts.format !== 'human' && opts.format !== 'json') {
    return usageError(`--format must be 'human' or 'json' (got '${opts.format}')`);
  }

  const projectPath = resolveProjectOrExit(opts.project);
  enforceStartCommandRules(projectPath, opts);
  // The same argv-only rule for --accept-partial-parse, checked whatever argv
  // says (see `findAcceptPartialParseInRepoConfig`).
  const acceptConfig = findAcceptPartialParseInRepoConfig(projectPath);
  if (acceptConfig) return usageError(acceptPartialParseRefusalMessage(acceptConfig));

  // --baseline-ref / --rules-ref (docs/ci.md): resolved, and the baseline
  // read, before anything starts or scans — a ref that names no commit, or a
  // baseline at it too large to read, is a usage error (exit 3), never "no
  // baseline" and never the tree's own copy.
  let baselineRef = null;
  let rulesRef = null;
  let baselineAtRef = null;
  let exclusionsReset = null;
  try {
    if (opts.baselineRef !== undefined) {
      baselineRef = await resolveCiRef(projectPath, opts.baselineRef, '--baseline-ref');
      baselineAtRef = await readBaselineAtRef(projectPath, baselineRef);
    }
    if (opts.rulesRef !== undefined) rulesRef = await resolveCiRef(projectPath, opts.rulesRef, '--rules-ref');
    // Last: it rewrites the checkout, so only once every other flag resolved.
    if (opts.resetExclusionsFrom !== undefined) {
      const resetRef = await resolveCiRef(projectPath, opts.resetExclusionsFrom, '--reset-exclusions-from');
      exclusionsReset = await resetExclusionsFromRef(projectPath, resetRef);
    }
  } catch (e) {
    return usageError(e instanceof Error ? e.message : String(e));
  }

  // `app` (when --start-command was given) must be stopped as soon as
  // runScans() is done with it, success or failure — runScans() (via
  // scan_dast inside it) is the ONLY consumer of the running application, so
  // nothing after this point needs it alive, and scoping teardown this
  // tightly keeps it correct with no wider changes needed. This has to be a
  // stash-then-check-after pattern, NOT `catch (e) { return usageError(...) }`
  // inside the same try: `usageError` calls `process.exit()`, which — verified
  // directly, see the task report — skips every `finally` still owed further
  // up the call stack. Putting the exit-inducing call inside a nested catch
  // would skip `app.stop()` below on exactly the path this exists to cover
  // ("a scan that throws must not leave the user's application running").
  let app = null;
  let startingApp = null;
  const interrupt = armInterruptTeardown(() => app, () => startingApp);
  let pipelineError = null;
  let result;
  try {
    if (opts.startCommand !== undefined) {
      startingApp = startApp({
        command: opts.startCommand,
        cwd: projectPath,
        healthUrl: opts.baseUrl,
        timeoutMs: APP_START_TIMEOUT_MS,
        signal: interrupt.signal,
      });
      app = await startingApp;
    }
    result = await runScans({
      projectPath,
      baseUrl: opts.baseUrl,
      authorizedTarget: opts.authorizedTarget ? true : undefined,
      localOnly: opts.localOnly ? true : undefined,
      ...(rulesRef !== null ? { rulesRef } : {}),
    });
  } catch (e) {
    pipelineError = e;
  } finally {
    interrupt.dispose();
    if (app) await app.stop();
  }
  if (interrupt.isInterrupted()) {
    // The SIGINT/SIGTERM handler is already tearing down and will call
    // process.exit() itself with the conventional 128+signum code — don't
    // also report a usage error for the cancellation-shaped rejection its
    // own abort caused.
    return;
  }
  if (pipelineError) {
    return usageError(`scan failed to run: ${pipelineError instanceof Error ? pipelineError.message : String(pipelineError)}`);
  }

  let baselineText;
  let baselineSource;
  if (baselineRef !== null && baselineAtRef !== null) {
    baselineText = baselineAtRef.text;
    baselineSource = {
      from: 'ref',
      path: BASELINE_RELATIVE_PATH,
      ref: baselineRef.ref,
      commit: baselineRef.commit,
      present: baselineAtRef.text !== null,
      tree_differs: baselineAtRef.treeDiffers,
    };
  } else {
    baselineText = readBaselineOrExit(projectPath, BASELINE_RELATIVE_PATH);
    baselineSource = { from: 'tree', path: BASELINE_RELATIVE_PATH };
  }
  const parsedBaseline = parseBaseline(baselineText);

  const verdict = evaluateGate({
    findings: result.findings,
    baseline: parsedBaseline ? parsedBaseline.file : null,
    failOn: opts.failOn,
    steps: result.steps,
    droppedBaselineEntries: parsedBaseline ? parsedBaseline.dropped : 0,
    // argv only — see `findAcceptPartialParseInRepoConfig`.
    acceptedPartialParses: opts.acceptPartialParse,
    baselineSource,
    rulesSource: result.rulesSource,
    exclusionsReset,
  });

  // --sarif is independent of --format: a pipeline commonly wants a human
  // headline in its own log AND a SARIF file for code-scanning upload in
  // the same run, so this always fires when the flag is given, regardless
  // of --format.
  if (opts.sarif) {
    const sarifPath = resolve(opts.sarif);
    mkdirSync(dirname(sarifPath), { recursive: true });
    writeFileSync(sarifPath, renderSarif(verdict, projectPath));
  }

  const text = opts.format === 'json' ? renderJson(verdict) : renderHuman(verdict);
  process.stdout.write(text.endsWith('\n') ? text : `${text}\n`);

  // Faithfully returned, never re-derived: evaluateGate already decided
  // whether this is a pass, a gate failure, or an incomplete scan.
  //
  // `process.exitCode = ...; return;`, NEVER `process.exit(...)`, here.
  // `process.stdout`/`.stderr` to a PIPE are synchronous on Windows but
  // ASYNCHRONOUS on POSIX (Node's own documented platform difference);
  // `process.exit()` tears the process down without waiting for pending
  // async I/O to flush, so a large write — and `renderHuman`/`renderJson`
  // are UNBOUNDED, scaling with finding count, worst case on exactly the
  // "first scan of an existing codebase, baseline absent, everything new"
  // case the design of record names — can be truncated mid-write on a real Linux CI
  // runner (invisible in this project's own tests, all of which run on
  // Windows, where stdout-to-pipe is synchronous). Setting `exitCode` and
  // returning lets Node exit on its own once the event loop drains AND the
  // write flushes; nothing here holds the loop open past that; `runScans`
  // has already closed its ephemeral database and removed its temp
  // directory in its own `finally` blocks by this point.
  process.exitCode = verdict.exitCode;
  return;
}

async function cmdBaseline(argv) {
  const sub = argv[0];
  if (sub !== 'update') {
    return usageError(`Unknown baseline subcommand: '${sub ?? '(none)'}' (only 'update' is supported)`);
  }

  const parsed = parseBaselineUpdateArgs(argv.slice(1));
  // Same reasoning as cmdScan's own — see the comment there.
  if (parsed.error) return usageError(parsed.error);
  const opts = parsed.value;

  const ci = await loadCiModules();
  const {
    parseBaseline,
    buildBaseline,
    serialiseBaseline,
    evaluateGate,
    exitCodeForCoverage,
    runScans,
    startApp,
    BASELINE_RELATIVE_PATH,
  } = ci;

  const projectPath = resolveProjectOrExit(opts.project);
  enforceStartCommandRules(projectPath, opts);

  // Same reasoning, and the same required shape, as cmdScan's own — see the
  // comments there (including `armInterruptTeardown`). `baseline update`
  // accepts --start-command/--base-url for the identical reason: scan_dast
  // is part of the same pipeline this command runs, so an app it started
  // must be stopped — including on SIGINT/SIGTERM — before this function
  // can exit, on every path, and `usageError` below must never be reached
  // from inside a catch nested in this try.
  let app = null;
  let startingApp = null;
  const interrupt = armInterruptTeardown(() => app, () => startingApp);
  let pipelineError = null;
  let result;
  try {
    if (opts.startCommand !== undefined) {
      startingApp = startApp({
        command: opts.startCommand,
        cwd: projectPath,
        healthUrl: opts.baseUrl,
        timeoutMs: APP_START_TIMEOUT_MS,
        signal: interrupt.signal,
      });
      app = await startingApp;
    }
    result = await runScans({
      projectPath,
      baseUrl: opts.baseUrl,
      authorizedTarget: opts.authorizedTarget ? true : undefined,
      localOnly: opts.localOnly ? true : undefined,
    });
  } catch (e) {
    pipelineError = e;
  } finally {
    interrupt.dispose();
    if (app) await app.stop();
  }
  if (interrupt.isInterrupted()) {
    return;
  }
  if (pipelineError) {
    return usageError(`scan failed to run: ${pipelineError instanceof Error ? pipelineError.message : String(pipelineError)}`);
  }

  const baselineText = readBaselineOrExit(projectPath, BASELINE_RELATIVE_PATH);
  const parsedBaseline = parseBaseline(baselineText);
  const previousFile = parsedBaseline ? parsedBaseline.file : null;

  const updated = buildBaseline(result.findings, previousFile, new Date().toISOString());

  // The only command that writes .guardian/baseline.json — `scan` never
  // does (see the module doc). NOT "the only write path in this whole CLI"
  // (this comment's own stale claim, per review): `scan --sarif <path>`
  // also writes, to a caller-chosen path that may well sit inside the
  // repository too. What is actually true of this write, and not of
  // --sarif's, is that it is IMPLICIT — always `.guardian/baseline.json`,
  // never a path the caller names — where --sarif's is explicit and opt-in.
  // Through `platform/projectFs.ts`: a temp file renamed into place, never
  // written through a link (a dangling one created its target outside the
  // project) or a `.guardian` directory that links out.
  const baselinePath = resolve(projectPath, BASELINE_RELATIVE_PATH);
  const written = writeProjectFile(projectPath, BASELINE_RELATIVE_PATH, serialiseBaseline(updated), {
    mode: 'replace',
  });
  if (!written.ok) {
    return usageError(
      `baseline not written to ${BASELINE_RELATIVE_PATH}: ${describeWriteRefusal(written.reason, written.detail)}`,
    );
  }

  // evaluateGate is reused here ONLY for its `coverage`/`coverageGaps`
  // computation (never re-derived — see scanCoverage.ts's own contract) so
  // this command can tell the caller whether the baseline it just wrote
  // reflects every scanner running, or was generated with a gap. `failOn`
  // is supplied but unused for that purpose: baseline update has no
  // pass/fail gate of its own, so `.blocking`/`.exitCode` from this verdict
  // are deliberately never read below.
  const verdict = evaluateGate({
    findings: result.findings,
    baseline: previousFile,
    failOn: 'critical',
    steps: result.steps,
    droppedBaselineEntries: parsedBaseline ? parsedBaseline.dropped : 0,
  });

  // The write always happens first and is always reported as a completed
  // fact ("updated", past tense) — a user without Semgrep installed must
  // still be able to adopt a baseline at all, so this can never read as a
  // refusal. The coverage-gap warning that can follow is a SEPARATE
  // sentence about trustworthiness, not a qualifier on whether the write
  // happened (coordinator review, resolution #4): a reader must come away
  // knowing BOTH "the file now exists" AND, distinctly, "do not trust it
  // completely yet" — collapsing those into one ambiguous sentence would
  // risk exactly the misreading ("this failed, nothing was written") the
  // review specifically asked this report to rule out.
  const entryWord = updated.entries.length === 1 ? 'entry' : 'entries';
  process.stdout.write(
    `baseline updated: ${updated.entries.length} ${entryWord} -> ${baselinePath}\n` +
      `coverage: ${verdict.coverage}\n`,
  );
  if (verdict.coverageGaps.length > 0) {
    process.stdout.write(
      '\nWARNING: the baseline above was written from an INCOMPLETE scan. It may be missing ' +
        'findings a full scan would have found — a later, complete run may report those as new, ' +
        "and whoever's change triggers that run will look responsible for debt this baseline " +
        'never actually captured. Gaps:\n',
    );
    for (const gap of verdict.coverageGaps) process.stdout.write(`  - ${untrustedText(gap)}\n`);
  }

  // Never CI_EXIT.GATE_FAILED: this command has no gate. Full coverage is a
  // clean write (0); anything less is written anyway (the user explicitly
  // asked for this), but reported as incomplete (2) rather than a silent
  // 0 — the same reasoning `scan` applies, aimed at the write instead of a
  // gate verdict.
  //
  // `exitCodeForCoverage` (mcp/src/ci/gate.ts, coordinator review): this
  // command has no `blocking`-findings concept of its own, so it cannot
  // reuse `evaluateGate`'s full exit-code decision the way `scan` does —
  // but the coverage-only half of that decision is exactly what it needs,
  // and re-encoding it here as a second, CLI-local ternary would have been
  // a duplicate, untested definition of "what does an incomplete scan mean
  // for an exit code" that could silently drift from gate.ts's own. Reused,
  // not re-derived — same rule this file already follows for `coverage`/
  // `coverageGaps` themselves.
  //
  // `process.exitCode = ...; return;`, not `process.exit(...)` — see the
  // matching comment at the end of `cmdScan` for why: stdout to a pipe is
  // asynchronous on POSIX, and this function's own writes above (the
  // baseline-updated line, and the WARNING paragraph, which can list one
  // line per coverage gap) are not bounded to a size guaranteed to fit
  // inside a single synchronous flush.
  process.exitCode = exitCodeForCoverage(verdict.coverage);
  return;
}

// --- ci-init (CI config generator, Task 21) -------------------------------
//
// `dev-guardian ci-init <github|gitlab|bitbucket>` writes a CI pipeline for
// the project being scanned — NEVER for this repo, which has none of its
// own (Global Constraint 7). Kept free of `node:sqlite`: it renders a
// static template with values read from two JSON files
// (.claude-plugin/plugin.json, configs/ci/pinned.json) and writes a file —
// no scan runs, so there is nothing here that needs `loadCiModules()`/
// `loadDashboardModules()`'s lazy-import dance at all, and `ci-init` works
// on any supported Node version, not just >= 22.13. It DOES need a `git`
// binary now (fix round 1, "pin the one component that runs everything"):
// it resolves the release tag to its exact commit SHA at generation time —
// from THIS checkout's own tags when it has the tag (no network at all,
// the common case), else over the network via `git ls-remote` — and bakes
// that SHA into the template, which then verifies it with `git rev-parse
// HEAD` in the pipeline itself, after cloning by tag — the tag is a moving
// pointer an attacker who compromised the release process (or force-pushed
// over it) could repoint after this file was generated; the resolved commit cannot
// move without changing its own hash. Same reasoning Trivy's own
// GHSA-69fq-xp46-6x23 lesson already lives in this codebase for
// (`installCatalog.ts`'s `TRIVY_INSTALL_TAG` comment).

const CONFIGS_CI_DIR = resolve(ROOT, 'configs', 'ci');
const PINNED_PATH = resolve(CONFIGS_CI_DIR, 'pinned.json');
const PLUGIN_JSON_PATH = resolve(ROOT, '.claude-plugin', 'plugin.json');
const DEFAULT_CI_BRANCH = 'main';

/**
 * One entry per `ci-init` target: which template under `configs/ci/` to
 * render, and where the rendered pipeline lives in the TARGET project —
 * each path is GitHub's/GitLab's/Bitbucket's own fixed convention, not a
 * choice this tool makes.
 */
const CI_TARGETS = {
  github: { templateFile: 'github.yml', outputPath: join('.github', 'workflows', 'dev-guardian.yml') },
  gitlab: { templateFile: 'gitlab.yml', outputPath: '.gitlab-ci.yml' },
  bitbucket: { templateFile: 'bitbucket.yml', outputPath: 'bitbucket-pipelines.yml' },
};

function parseCiInitArgs(argv) {
  const out = { _: [], project: process.cwd(), write: false, force: false, attest: false, branch: DEFAULT_CI_BRANCH };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--write') out.write = true;
    else if (a === '--force') out.force = true;
    else if (a === '--attest') out.attest = true;
    else if (a === '--project') {
      const r = takeOperand(argv, i, a);
      if (r.error) return { error: r.error };
      out.project = r.value;
      i = r.nextIndex;
    } else if (a.startsWith('--project=')) out.project = a.slice('--project='.length);
    else if (a === '--branch') {
      const r = takeOperand(argv, i, a, true); // requireNonEmpty — an empty branch name is never meaningful
      if (r.error) return { error: r.error };
      out.branch = r.value;
      i = r.nextIndex;
    } else if (a.startsWith('--branch=')) {
      const value = a.slice('--branch='.length);
      if (value.length === 0) return { error: '--branch requires a value' };
      out.branch = value;
    } else if (a.startsWith('--')) return { error: `Unknown flag: ${a}` };
    else out._.push(a);
  }
  return { value: out };
}

/**
 * Substitutes every `{{KEY}}` token in `text` with `vars[KEY]`, then
 * refuses (throws) if anything shaped LIKE a placeholder survives — a
 * safety net against a template referencing a variable this function was
 * never given, which would otherwise leak a literal `{{TYPO}}` into a
 * generated CI pipeline silently. The leftover check uses the EXACT SAME
 * token shape as the substitution itself (`{{[A-Z0-9_]+}}`), not a generic
 * `{{...}}`: a generic one also matches GitHub Actions' own live expression
 * syntax, `${{ github.event_name }}` — its INNER `{{ github.event_name }}`
 * fits a naive `\{\{[^}]*\}\}` even though the leading `$` makes it a
 * completely different, legitimate thing this function never touches (the
 * substitution regex already requires `[A-Z0-9_]+` with no spaces or dots,
 * so it never matches a real expression either — only the leftover check
 * had the wider, wrong pattern).
 */
const PLACEHOLDER_TOKEN = /\{\{([A-Z0-9_]+)\}\}/g;

/**
 * A section marker: a line holding only `# {{#NAME}}` (keep what follows
 * when NAME is on), `# {{^NAME}}` (keep it when NAME is off) or
 * `# {{/NAME}}` (end), indented freely. A YAML comment, so the template stays
 * readable as YAML around it; the marker lines themselves never reach the
 * output.
 */
const SECTION_LINE = /^\s*# \{\{([#^/])([A-Z0-9_]+)\}\}\s*$/;
/**
 * Anything that STARTS like a marker — `{{` then `#`, `^` or `/`, spaces
 * allowed — on a line that is not exactly one. A near-miss (`# {{#attest}}`,
 * `# {{ #ATTEST }}`, `#{{#ATTEST}}`) would otherwise pass as a plain YAML
 * comment and keep its block whatever the flag said. No GitHub Actions
 * expression starts that way (`${{ !cancelled() }}`, `${{ github.ref }}`).
 */
const SECTION_TOKEN = /\{\{\s*[#^/]/;

/**
 * Keeps or drops each marked block of `text` by `sections[NAME]` (see
 * `SECTION_LINE`). Refuses — throws — a section the caller did not declare
 * (so a typo is never silently kept or dropped), an unclosed, unopened or
 * nested one, and any malformed marker, including one sharing its line with
 * anything else.
 */
function applyCiSections(text, sections) {
  const out = [];
  let open = null;
  for (const line of text.split('\n')) {
    const m = SECTION_LINE.exec(line);
    if (m === null) {
      if (SECTION_TOKEN.test(line)) {
        throw new Error(
          `ci-init: malformed section marker (a marker is a line holding only "# {{#NAME}}", "# {{^NAME}}" or "# {{/NAME}}", NAME in A-Z0-9_): ${line.trim()}`,
        );
      }
      if (open === null || open.keep) out.push(line);
      continue;
    }
    const [, kind, name] = m;
    if (kind === '/') {
      if (open === null || open.name !== name) throw new Error(`ci-init: section end {{/${name}}} without an opening`);
      open = null;
      continue;
    }
    if (open !== null) throw new Error(`ci-init: nested section ${name} inside ${open.name}`);
    if (!Object.hasOwn(sections, name)) throw new Error(`ci-init: template references unknown section ${name}`);
    const on = sections[name] === true;
    open = { name, keep: kind === '#' ? on : !on };
  }
  if (open !== null) throw new Error(`ci-init: unclosed section ${open.name}`);
  return out.join('\n');
}

export function renderCiTemplate(text, vars, sections = {}) {
  const rendered = applyCiSections(text, sections).replace(PLACEHOLDER_TOKEN, (whole, key) => {
    if (!Object.hasOwn(vars, key)) throw new Error(`ci-init: template references unknown placeholder {{${key}}}`);
    return String(vars[key]);
  });
  const leftover = new RegExp(PLACEHOLDER_TOKEN.source).exec(rendered);
  if (leftover) throw new Error(`ci-init: unresolved placeholder in rendered template: ${leftover[0]}`);
  return rendered;
}

function readJsonOrExit(path, label) {
  let text;
  try {
    text = readFileSync(path, 'utf8');
  } catch (e) {
    return usageError(`ci-init: could not read ${label} (${path}): ${e instanceof Error ? e.message : String(e)}`);
  }
  try {
    return JSON.parse(text);
  } catch (e) {
    return usageError(`ci-init: ${label} (${path}) is not valid JSON: ${e instanceof Error ? e.message : String(e)}`);
  }
}

/** `https://…` — the shape `git clone` needs; refuses anything else (a bare `owner/repo` slug, a `git@` SSH form, or garbage). */
const REPO_URL_SHAPE = /^https:\/\/\S+$/;
/** `vX.Y.Z` — a plain, unambiguous release tag. Refuses a pre-release/build suffix too: `git clone --branch` needs an exact ref, never a range. */
const RELEASE_TAG_SHAPE = /^v\d+\.\d+\.\d+$/;

/**
 * `pinned.<section>[<key>]` -> `<KEY>_<SUFFIX>` placeholder entries, driven
 * by `fieldSuffix` (which JSON field becomes which placeholder suffix) —
 * one small map instead of hand-enumerating every `PACK_FIELD: pinned.pack.field`
 * line per scanner/action, so adding an entry to `pinned.json` cannot drift
 * from what this function derives: it either shows up under its own
 * `<KEY>_<SUFFIX>` name automatically, or (a field `fieldSuffix` does not
 * name, e.g. a future scanner-specific extra) is silently not turned into a
 * placeholder at all — never silently WRONG, only silently absent, and a
 * template referencing it would fail loudly via `renderCiTemplate`'s own
 * unknown-placeholder check. Keys starting with `_` (`_readme`, `_note`, …)
 * are documentation, not data, and are skipped.
 */
function placeholdersFromSection(pinned, sectionName, fieldSuffix) {
  const section = pinned[sectionName];
  if (typeof section !== 'object' || section === null || Array.isArray(section)) {
    throw new Error(`ci-init: ${PINNED_PATH} "${sectionName}" is missing or not an object`);
  }
  const out = {};
  for (const [key, entry] of Object.entries(section)) {
    if (key.startsWith('_')) continue;
    if (typeof entry !== 'object' || entry === null || Array.isArray(entry)) {
      throw new Error(`ci-init: ${PINNED_PATH} "${sectionName}.${key}" is not an object`);
    }
    const prefix = key.toUpperCase();
    for (const [field, suffix] of Object.entries(fieldSuffix)) {
      const value = entry[field];
      if (value === undefined) continue; // e.g. semgrep/zizmor have no url/sha256
      out[`${prefix}_${suffix}`] = value;
    }
  }
  return out;
}

/** A plain git ref/branch name: no whitespace, none of the characters YAML flow syntax or a shell would read specially. */
const BRANCH_NAME_SHAPE = /^[A-Za-z0-9._/-]+$/;
/** A full, lower-hex, 40-character commit SHA. */
const COMMIT_SHA_SHAPE = /^[0-9a-f]{40}$/;

/**
 * Resolves `tag` on `repoUrl` to the commit it actually names — tried
 * locally first (`resolveTagLocally`, no network at all, the common case),
 * falling back to the network only when the local checkout cannot answer
 * (`resolveTagRemotely`). Returns null when NEITHER can — no `git` at all,
 * offline with no local tag either, or an unknown tag — never throws.
 */
/**
 * Test seam (fix round 2): `GUARDIAN_CI_INIT_PIN_SHA`, honoured ONLY when
 * set, skips both the local-tag lookup and the network fallback entirely.
 * Real, undoctored need for it: this repo bumps `.claude-plugin/
 * plugin.json`'s `version` and tags the release SEPARATELY — the version
 * is committed first, the tag comes later — so between those two steps
 * (which is most of the time a release branch exists at all) neither
 * `resolveTagLocally` nor `resolveTagRemotely` has an answer, and every
 * `ci-init` call in the test suite would exit 3 for a reason that has
 * nothing to do with what the suite is testing. Production `ci-init` never
 * sets this itself; only a test's own `env` does.
 */
function resolveDevGuardianCommitSha(repoUrl, tag) {
  const pinned = process.env['GUARDIAN_CI_INIT_PIN_SHA'];
  if (pinned !== undefined) {
    return COMMIT_SHA_SHAPE.test(pinned) ? pinned : null;
  }
  return resolveTagLocally(tag) ?? resolveTagRemotely(repoUrl, tag);
}

/**
 * `tag` resolved from THIS CLI's own checkout (`ROOT`) — no network at all.
 * `ci-init` normally runs from inside a clone of dev-guardian itself, and
 * that clone's own refs already carry the answer whenever it is a full,
 * unmodified clone/fetch — confirmed directly against this repo's own
 * checkout. `^{commit}` peels either tag shape (lightweight or annotated)
 * down to the commit in one call, so there is no separate-line parsing to
 * get wrong the way a raw `ls-remote` listing needs (see
 * `resolveTagRemotely`). Null when `ROOT` is not a git repo, or does not
 * have this tag (a shallow or tag-less install) — `resolveDevGuardianCommitSha`
 * falls back to the network in either case, never assumes offline means
 * "unknown".
 */
function resolveTagLocally(tag) {
  // Hardened like every git dev-guardian starts (`platform/gitSafety.ts`),
  // though ROOT is dev-guardian's own checkout.
  const r = execGitSync(ROOT, ['rev-parse', '--verify', `refs/tags/${tag}^{commit}`], { timeoutMs: 10_000 });
  if (r.failure !== null || r.status !== 0) return null;
  const sha = r.stdout.trim();
  return COMMIT_SHA_SHAPE.test(sha) ? sha : null;
}

/**
 * `tag` on `repoUrl`, resolved over the network via `git ls-remote --tags`
 * — the fallback when `resolveTagLocally` cannot answer. Deliberately NOT
 * `git ls-remote --tags <url> <tag>` (a single-ref query): dev-guardian's
 * own release tags are ANNOTATED — confirmed directly (`git ls-remote
 * --tags` against the real repo lists TWO lines per tag) — and a
 * single-ref query returns only the tag OBJECT's own SHA, not the commit
 * it points at and `git checkout`/`git clone --branch` actually resolves
 * to; verified they differ for this project's own v2.0.0 tag. The full
 * listing includes a second, `^{}`-suffixed line for an annotated tag's
 * dereferenced commit; this prefers that line when present and falls back
 * to the plain one only for a lightweight tag (no such line at all).
 * Returns null on any failure — no network, no `git`, unknown tag, or an
 * answer not shaped like a commit SHA — never throws.
 */
function resolveTagRemotely(repoUrl, tag) {
  // From the temp directory, not the working directory: `ci-init` runs in the
  // user's project, whose own git configuration (`url.<x>.insteadOf`, a
  // credential helper, core.sshCommand) would otherwise apply to this URL.
  // Hardened as well (`platform/gitSafety.ts`).
  const r = execGitSync(tmpdir(), ['ls-remote', '--tags', repoUrl], { timeoutMs: 20_000 });
  if (r.failure !== null || r.status !== 0) return null;
  const out = r.stdout;
  let plain;
  let peeled;
  for (const line of out.split('\n')) {
    const tab = line.indexOf('\t');
    if (tab < 0) continue;
    const sha = line.slice(0, tab).trim();
    const ref = line.slice(tab + 1).trim();
    if (ref === `refs/tags/${tag}`) plain = sha;
    else if (ref === `refs/tags/${tag}^{}`) peeled = sha;
  }
  const sha = peeled ?? plain;
  return sha !== undefined && COMMIT_SHA_SHAPE.test(sha) ? sha : null;
}

/** Builds the placeholder table every `configs/ci/*.yml` template draws from — see `renderCiTemplate`. */
function ciTemplateVars(plugin, pinned, branch) {
  if (typeof plugin !== 'object' || plugin === null || Array.isArray(plugin)) {
    return usageError(`ci-init: ${PLUGIN_JSON_PATH} does not contain a JSON object`);
  }
  if (typeof pinned !== 'object' || pinned === null || Array.isArray(pinned)) {
    return usageError(`ci-init: ${PINNED_PATH} does not contain a JSON object`);
  }
  const repo = plugin.repository;
  if (typeof repo !== 'string' || !REPO_URL_SHAPE.test(repo)) {
    return usageError(
      `ci-init: ${PLUGIN_JSON_PATH}'s "repository" (${JSON.stringify(repo)}) is not an https:// URL`,
    );
  }
  const tag = typeof plugin.version === 'string' ? `v${plugin.version}` : '';
  if (!RELEASE_TAG_SHAPE.test(tag)) {
    return usageError(
      `ci-init: ${PLUGIN_JSON_PATH}'s "version" (${JSON.stringify(plugin.version)}) is not a plain X.Y.Z ` +
        'release version — refusing to render a `git clone --branch` target this loosely shaped.',
    );
  }
  if (!BRANCH_NAME_SHAPE.test(branch)) {
    return usageError(`ci-init: --branch ${JSON.stringify(branch)} is not a plain branch name`);
  }
  const sha = resolveDevGuardianCommitSha(repo, tag);
  if (sha === null) {
    return usageError(
      `ci-init: could not resolve ${tag} to a commit SHA — neither this checkout's own tags nor ` +
        `\`git ls-remote --tags ${repo}\` had an answer. ci-init needs a \`git\` binary (found on PATH?) ` +
        'and, unless this checkout already has the tag, network access — it pins the exact commit the ' +
        'generated pipeline verifies against, not just the tag name (a moving tag is a supply-chain risk; ' +
        'see the module doc comment).',
    );
  }
  let actionVars;
  let scannerVars;
  try {
    actionVars = placeholdersFromSection(pinned, 'actions', { sha: 'SHA', version: 'VERSION' });
    scannerVars = placeholdersFromSection(pinned, 'scanners', {
      version: 'VERSION',
      linux_amd64_url: 'URL',
      linux_amd64_sha256: 'SHA256',
      archive_member: 'MEMBER',
    });
  } catch (e) {
    return usageError(e instanceof Error ? e.message : String(e));
  }
  return {
    DEV_GUARDIAN_REPO: repo,
    DEV_GUARDIAN_TAG: tag,
    DEV_GUARDIAN_SHA: sha,
    DEFAULT_BRANCH: branch,
    ...actionVars,
    ...scannerVars,
  };
}

/**
 * Whether `projectPath` is dev-guardian's OWN checkout, OR is INSIDE it —
 * the one place `ci-init` must never write to (Global Constraint 7: no
 * GitHub Actions in this repo; the brief's own words, "never for this
 * repo"). A CONTAINMENT check, not mere equality: `--project <this
 * repo>/mcp` is still inside the checkout, and `--write` there would create
 * `.github/workflows/dev-guardian.yml` (or the other targets' equivalents)
 * somewhere under this repo's own tree — exactly what the constraint
 * forbids, just one directory removed from the obvious case. Checked
 * lexically first, then again on the real paths (mirrors
 * `isRunAsEntryPoint`'s own reasoning below for the identical hazard, and
 * `scanContainers.ts#isInside` upstream in `mcp/src/`): a symlink INTO this
 * checkout must refuse exactly like a direct path into it, and a path
 * `realpathSync` cannot resolve must read as "not inside" rather than
 * crash a usage check.
 */
/** Whether `candidate` (an absolute, already-resolved path) IS `root` or is inside it. */
function isWithin(root, candidate) {
  const rel = relative(root, candidate);
  return rel === '' || (!rel.startsWith(`..${sep}`) && rel !== '..' && !isAbsolute(rel));
}

function isDevGuardianOwnRepo(projectPath) {
  if (isWithin(resolve(ROOT), resolve(projectPath))) return true;
  try {
    return isWithin(realpathSync(ROOT), realpathSync(projectPath));
  } catch {
    return false;
  }
}

function safeRealpath(p) {
  try {
    return realpathSync(p);
  } catch {
    return null;
  }
}

function safeLstat(p) {
  try {
    return lstatSync(p);
  } catch {
    return null;
  }
}

/**
 * The first ALREADY-EXISTING ancestor directory of `outPath`, between
 * `projectPath` and `outPath`'s own parent, that resolves outside
 * `projectPath` — or null when every existing one stays inside (an
 * ancestor that does not exist yet is not checked: `mkdirSync` creates it
 * fresh, with nothing to escape through). Github's nested output
 * (`.github/workflows/dev-guardian.yml`) is the case this matters for: a
 * `.github` that is already a symlink pointing outside the project would
 * otherwise have `mkdirSync(..., { recursive: true })` silently create
 * `workflows/` THROUGH it, and the write would land outside the project
 * entirely. gitlab/bitbucket's flat, root-level output paths have no
 * intermediate ancestor to check at all.
 *
 * Does NOT check `outPath` itself — a symlinked LEAF (the pipeline file's
 * own name already existing as a symlink) is a different hazard, handled at
 * the write: a plain `--write` publishes with `link()` (`createFile`), which
 * refuses ANY existing entry at that name, a dangling symlink included, and
 * never follows one; `--force` refuses a leaf link that escapes or dangles
 * (`refuseEscapingLeafSymlink`) and otherwise replaces the entry by rename
 * (`replaceFile`). Not `wx` alone: on Windows a `wx` open over a dangling
 * symlink follows it and creates the link's target, wherever that is.
 */
function firstEscapingAncestor(projectPath, outPath) {
  const rootReal = safeRealpath(projectPath) ?? resolve(projectPath);
  const segments = relative(projectPath, outPath).split(sep).filter((s) => s.length > 0);
  let current = projectPath;
  for (let i = 0; i < segments.length - 1; i++) {
    current = join(current, segments[i]);
    if (!existsSync(current)) continue;
    const real = safeRealpath(current);
    if (real === null) continue;
    if (!isWithin(rootReal, real)) return current;
  }
  return null;
}

/**
 * Guards `--force` specifically: an existing `outPath` that is a symlink
 * resolving OUTSIDE the project, or a broken one (pointing nowhere this
 * process can resolve), is refused — never "fixed" by guessing what the
 * link was for. The write itself (`replaceFile`) replaces a link rather
 * than following it, so this refusal is about intent, not mechanics: a
 * pipeline file that is a link out of the project is not this command's
 * to replace.
 *
 * Returns `{ ok: true }` when `outPath` is not a symlink, or is one that
 * resolves INSIDE the project (replaced by a plain file — what `--force`
 * means for every other existing path); `{ ok: false, reason }` otherwise.
 */
function refuseEscapingLeafSymlink(projectPath, outPath) {
  const st = safeLstat(outPath);
  if (st === null || !st.isSymbolicLink()) return { ok: true };
  const real = safeRealpath(outPath);
  const rootReal = safeRealpath(projectPath) ?? resolve(projectPath);
  if (real === null || !isWithin(rootReal, real)) {
    return {
      ok: false,
      reason: real === null ? 'it is a broken symlink' : 'it is a symlink that resolves outside the project',
    };
  }
  return { ok: true };
}

/** Remove `path`, ignoring a failure: it is a temp file this command made. */
function removeTemp(path) {
  try {
    unlinkSync(path);
  } catch {
    // Already gone, or held open by a scanner: the name is random and hidden.
  }
}

/**
 * A fresh temp file beside `outPath` holding `content`; its path. The name is
 * random (`crypto.randomBytes`) and the file is opened `wx`: an entry already
 * at that name — anyone's, a link included — fails the open with EEXIST and
 * is never written to or deleted. Once the open succeeded the file is this
 * call's, and a failed write removes it.
 */
function writeTempBeside(outPath, content) {
  const { dir, base } = parse(outPath);
  const tmp = join(dir, `.${base}.${randomBytes(8).toString('hex')}.tmp`);
  const fd = openSync(tmp, 'wx');
  let written = false;
  try {
    writeFileSync(fd, content, 'utf8');
    written = true;
  } finally {
    closeSync(fd);
    if (!written) removeTemp(tmp);
  }
  return tmp;
}

/**
 * `--force`'s write: a temp file beside `outPath`, renamed over it in one
 * step. A rename replaces the directory ENTRY — a symlink or a hard link at
 * `outPath` is replaced, never written through (a truncating `'w'` write goes
 * through the inode every name of the file shares) — and `outPath` is never
 * absent or half-written.
 */
function replaceFile(outPath, content) {
  const tmp = writeTempBeside(outPath, content);
  try {
    renameSync(tmp, outPath);
  } catch (e) {
    removeTemp(tmp);
    throw e;
  }
}

/**
 * A plain `--write`: creates `outPath` only when NOTHING is at that name.
 * Returns false, having written nothing there, when something is.
 *
 * The file is written to a temp file and published with `link()`, which
 * refuses any existing entry at `outPath` — a dangling symlink included —
 * with EEXIST, and never follows one. Not a `wx` open: on Windows a `wx`
 * (CREATE_NEW) open over a DANGLING symlink follows it and creates the
 * link's target, wherever it points (measured), which would put the pipeline
 * outside the project. The published file is complete from its first moment.
 *
 * Where hard links are not supported (FAT/exFAT, some network shares), this
 * falls back to an `lstat` check and a `wx` write. That leaves one race, on
 * Windows only: a dangling symlink created at `outPath` between the check and
 * the open would be followed. POSIX `O_EXCL` never follows a link.
 */
function createFile(outPath, content) {
  const tmp = writeTempBeside(outPath, content);
  try {
    linkSync(tmp, outPath);
    return true;
  } catch (e) {
    if (e instanceof Error && 'code' in e && e.code === 'EEXIST') return false;
    if (safeLstat(outPath) !== null) return false;
    try {
      writeFileSync(outPath, content, { encoding: 'utf8', flag: 'wx' });
      return true;
    } catch (e2) {
      if (e2 instanceof Error && 'code' in e2 && e2.code === 'EEXIST') return false;
      throw e2;
    }
  } finally {
    removeTemp(tmp);
  }
}

/**
 * `ci-init --attest` is argv-only, by the same rule as `--start-command`: it
 * adds a job that can mint an OIDC token and sign in this repository's name,
 * so a repository file — which a pull request can edit — must never be able
 * to turn it on. A `.guardian/ci.json` declaring `attest` is refused outright,
 * loudly, rather than read or silently ignored; lenient on everything else,
 * like `findStartCommandInRepoConfig`. The config path when it declares the
 * key, else null.
 */
function findAttestInRepoConfig(projectPath) {
  const configPath = resolve(projectPath, CI_CONFIG_RELATIVE_PATH);
  const data = readRepoJson(projectPath, CI_CONFIG_RELATIVE_PATH);
  if (data && typeof data === 'object' && !Array.isArray(data) && data.attest !== undefined) return configPath;
  return null;
}

/**
 * Why `--attest` is refused on GitLab and Bitbucket. GitHub's artifact
 * attestations bind a file's digest to the workflow, commit and run that
 * produced it, signed by Sigstore with the job's own OIDC identity and
 * stored where `gh attestation verify` finds them. Bitbucket Pipelines' OIDC
 * tokens are not a Sigstore (Fulcio) identity at all. GitLab's are on
 * gitlab.com, so `cosign sign-blob` could sign the reports there — but that
 * is a signature with no provenance and nothing that stores or looks it up,
 * and a self-managed instance needs its own Sigstore setup; emitting it as
 * if it were the same guarantee would overstate what the pipeline proves.
 */
const ATTEST_GITHUB_ONLY =
  '--attest is GitHub-only: it uses GitHub artifact attestations (actions/attest-build-provenance), ' +
  "signed with the workflow's own OIDC identity and verified with `gh attestation verify`. GitLab and " +
  'Bitbucket have no equivalent this generator can emit soundly — Bitbucket\'s OIDC is not a Sigstore ' +
  "identity, and on GitLab a cosign keyless signature of the reports would carry no provenance and no " +
  'store to verify it against. Generate the pipeline without --attest.';

/**
 * How to check a report `--attest` attested — the same words in --help, the
 * write message, the workflow's header and docs/ci.md. `--source-ref` pins
 * the branch the pipeline triggers on: `--signer-workflow` names the workflow
 * FILE, and a copy of it on any other branch — edited to run on a push there
 * — signs as the same path.
 */
function attestVerifyHint(branch) {
  return (
    'Verify a report the attest job signed: download the `dev-guardian-reports` artifact of that run ' +
    '(gh run download <run-id> --repo OWNER/REPO --name dev-guardian-reports), then\n' +
    '  gh attestation verify dev-guardian-results.sarif --repo OWNER/REPO \\\n' +
    '    --signer-workflow OWNER/REPO/.github/workflows/dev-guardian.yml \\\n' +
    `    --source-ref refs/heads/${branch}\n` +
    '  (and the same for dev-guardian-report.json). --source-ref matters: --signer-workflow names the ' +
    'workflow file, and a copy of it on another branch signs as the same path.'
  );
}

/** What `--attest` proves and exposes — said on every write. */
const ATTEST_SCOPE_NOTE =
  'The attest job runs even when the gate failed: an attestation proves where the reports came from, not that ' +
  'the gate passed. On a public repository the full JSON report is printed to the public job log, and the ' +
  'reports artifact can be downloaded by any signed-in GitHub user while it is retained.';

function cmdCiInit(argv) {
  const parsed = parseCiInitArgs(argv);
  if (parsed.error) return usageError(parsed.error);
  const args = parsed.value;

  const targetArg = args._[0];
  const target = targetArg !== undefined ? CI_TARGETS[targetArg] : undefined;
  if (!target) {
    process.stderr.write(
      `Missing or unknown ci-init target: ${targetArg ?? '(none)'}\n` +
        `Valid targets: ${Object.keys(CI_TARGETS).join(', ')}\n\n`,
    );
    usage();
    process.exit(1);
  }
  if (args.attest && targetArg !== 'github') return usageError(`ci-init ${targetArg}: ${ATTEST_GITHUB_ONLY}`);

  const projectPath = resolveProjectOrExit(args.project);
  if (isDevGuardianOwnRepo(projectPath)) {
    return usageError(
      "ci-init generates a pipeline for the PROJECT BEING SCANNED, never for dev-guardian's own " +
        'repository (it ships no GitHub Actions of its own). Pass --project pointing at the project ' +
        'you want a CI pipeline for.',
    );
  }
  // Checked whatever argv says: a repository file never turns --attest on,
  // and one that tries is refused rather than ignored.
  const attestConfig = findAttestInRepoConfig(projectPath);
  if (attestConfig) {
    return usageError(
      `ci-init: refusing to run: '${CI_CONFIG_RELATIVE_PATH}' declares "attest" (found at ${attestConfig}). ` +
        '--attest may only be given on the command line, never from a file inside the repository — a pull ' +
        'request could otherwise edit that file and give a pipeline job the right to sign in this ' +
        `repository's name. Remove attest from ${CI_CONFIG_RELATIVE_PATH} and pass --attest to ci-init instead.`,
    );
  }

  const plugin = readJsonOrExit(PLUGIN_JSON_PATH, 'dev-guardian plugin.json');
  const pinned = readJsonOrExit(PINNED_PATH, 'configs/ci/pinned.json');
  const vars = ciTemplateVars(plugin, pinned, args.branch);

  const templatePath = resolve(CONFIGS_CI_DIR, target.templateFile);
  if (!existsSync(templatePath)) {
    return usageError(`ci-init: template missing: ${templatePath}`);
  }
  const templateText = readFileSync(templatePath, 'utf8');
  // Only the GitHub template has an ATTEST section (--attest is refused for
  // the others above); declaring it for every target keeps a stray marker in
  // any template a loud error rather than an unknown section.
  const rendered = renderCiTemplate(templateText, vars, { ATTEST: args.attest });

  const outPath = resolve(projectPath, target.outputPath);

  if (!args.write) {
    process.stdout.write(`# ${targetArg} pipeline  ->  ${outPath}\n\n`);
    process.stdout.write(rendered);
    process.stdout.write(`\n# Paste this at the path shown, or re-run with --write to write it there.\n`);
    return;
  }

  // Never follow a symlinked ancestor (e.g. a `.github` that is itself a
  // symlink) out of the project — same containment rule `scanIac.ts`
  // applies on the READ side to a symlinked `.github/workflows`, applied
  // here on the WRITE side before anything is created.
  const escapee = firstEscapingAncestor(projectPath, outPath);
  if (escapee !== null) {
    return usageError(
      `ci-init: refusing to write through ${escapee} — it exists and resolves outside the project ` +
        `(${projectPath}). Remove or fix that path first.`,
    );
  }
  mkdirSync(dirname(outPath), { recursive: true });

  const refuseExisting = () => {
    process.stderr.write(
      `ci-init: refusing to overwrite existing pipeline file: ${outPath}\n` +
        `Re-run with --force to overwrite it, or remove it first.\n`,
    );
    process.exit(1);
  };

  if (args.force) {
    const leaf = refuseEscapingLeafSymlink(projectPath, outPath);
    if (!leaf.ok) {
      return usageError(
        `ci-init: refusing to overwrite ${outPath} with --force — ${leaf.reason}. Remove it first.`,
      );
    }
    replaceFile(outPath, rendered);
  } else if (!createFile(outPath, rendered)) {
    // Something is at the name — a dangling symlink included (see createFile).
    refuseExisting();
  }
  process.stdout.write(`Wrote ${targetArg} pipeline to ${outPath}\n`);
  if (targetArg === 'github') {
    process.stdout.write(
      'Enable "security-events: write" / code scanning for this repository so the SARIF upload step can run.\n',
    );
  }
  if (args.attest) {
    process.stdout.write(
      'The attest job needs artifact attestations: any public repository, or GitHub Enterprise Cloud for a ' +
        'private one — elsewhere it fails.\n' +
        `${ATTEST_SCOPE_NOTE}\n` +
        `${attestVerifyHint(args.branch)}\n`,
    );
  }
  process.stdout.write(
    'If .guardian/baseline.json does not exist yet in this project, run `dev-guardian baseline update` ' +
      "once locally and commit it before relying on this pipeline's gate.\n",
  );
}

// --- status / dashboard (local reporting) ---------------------------------
//
// The design of record: "Nothing here runs a scan, mutates the database, opens a
// socket, or reaches the network." Both commands are thin — resolve
// --project, open THIS project's own database, build one snapshot, render,
// print or write — and both REPORT rather than gate (the design of record):
// `status`/`dashboard` exit 0 whenever they render, including over a
// project full of critical findings or one that has never been scanned.
// `scan` is the gate, with its own exit codes; if either of these two ever
// returned non-zero for a dirty project, every pipeline that runs one for a
// summary would break. The ONLY non-zero either can produce is
// USAGE_ERROR_EXIT (3) — via `usageError` (a bad flag, a --project that
// does not exist) or `fatal` (anything else that goes wrong, e.g. --out
// pointing somewhere unwritable) — never a bespoke code of their own.

/**
 * `openDatabase({ projectPath })` + `runMigrations(db)` + `new Storage(db)`
 * + `buildSnapshot(...)`, with the database closed in a `finally` on EVERY
 * path — a throw inside `runMigrations`, `new Storage(db)` itself, OR
 * `buildSnapshot` all propagate straight through this `finally` (the
 * database still closes) to the caller, same as a normal return.
 *
 * Both `runMigrations(db)` AND `new Storage(db)` are inside the try, not
 * before it — a fix-round-1 correction (both were previously in front of
 * it). `runMigrations(db)` is normally a proven no-op here (`openDatabase`/
 * `openDatabaseAtPath` already run migrations internally; nothing pending,
 * nothing executed — see `migrations/runner.ts`), but a DATABASE FILE can be
 * in a state its own recorded schema version does not describe (hand-edited,
 * corrupted, partially migrated by a crashed prior process) — `runMigrations`
 * alone would not notice that (it trusts the recorded version and does
 * nothing), but `new Storage(db)`'s constructor WOULD: every repo class
 * prepares its statements immediately, and `db.prepare()` validates against
 * the actual current schema, so a genuinely missing table surfaces right
 * there, not inside `runMigrations`. That is precisely why `new Storage(db)`
 * itself has to be inside the guarded region, not just the calls that look
 * more dangerous.
 *
 * The `finally` closes the raw `db` handle directly — `storage.close()`
 * would not be reachable/safe here, because the one call this most needs to
 * guard is `new Storage(db)` throwing, at which point the `storage` local
 * was never assigned. `db`, in contrast, is guaranteed to exist for the
 * entire try (obtained from `resolveDbHandle` before the try even starts),
 * and `Storage.close()` is itself nothing more than `this.db.close()` —
 * closing `db` directly is equivalent on every path where `storage` DOES
 * exist, and is the only option on the one path where it does not.
 *
 * Closing here, before returning, is also deliberate for a second reason:
 * rendering (`renderStatus`/`renderDashboard`) and writing (`--out`) are
 * pure/filesystem operations over the already-built snapshot and touch
 * storage not at all, so the SQLite handle has no reason to stay open one
 * moment past the one query pass that needed it — and it means a LATER
 * failure (e.g. `--out` pointing at an unwritable path) always happens with
 * the database already closed, never the other way around.
 *
 * **Genuinely read-only (coordinator review, Important).** `openDatabase`
 * always calls `ensureDir` + `runMigrations` for a file-backed database —
 * correct for the MCP server, which persists scans, but wrong here: on a
 * directory that has no database yet ANYWHERE `openDatabase` would look, it
 * CREATES one (an empty, freshly-migrated 143 KB file), which contradicts
 * this command's own documented promise (the design of record: "Nothing here runs a
 * scan, mutates the database, opens a socket, or reaches the network") the
 * moment a user points `status`/`dashboard` at a project it has never
 * touched. Detected by `resolveDbHandle` (below) checking BOTH locations
 * `openDatabase` can produce — the documented primary path AND its
 * writability fallback (see `storage/db.ts`'s own module doc) — before
 * opening anything: only when NEITHER exists does this open an IN-MEMORY
 * database instead (`inMemory: true`, never touches disk) rather than the
 * real project path. `buildSnapshot` only ever queries `storage`; a
 * freshly-migrated empty in-memory database and a freshly-migrated empty
 * file-backed one are indistinguishable to every query it runs, so this
 * reuses the exact "never scanned" path already proven by the unit suite
 * (`dashboard/snapshot.test.ts`), rather than hand-rolling a second copy of
 * that empty state here. `projectPath` itself is passed through unchanged
 * either way, so `snapshot.project_path` — and everything rendered from it —
 * still names the real project, never `:memory:`.
 *
 * **Both locations, not just the primary one.** `openDatabase` has a
 * documented fallback (`storage/db.ts`): when `<project>/.guardian` is not
 * writable — read-only CI mounts, restrictive ACLs, read-only shares, all of
 * which `scan`/the MCP server explicitly support, with a warning, rather
 * than refusing — it persists to `os.tmpdir()/dev-guardian/<hash>/
 * guardian.db` instead, and every scan run against that same unwritable
 * project directory lands there. The ORIGINAL version of this function only
 * ever checked the primary path, so a project scanned entirely through that
 * fallback rendered as "never scanned" here even though a complete scan was
 * sitting in the fallback, fully queryable: a false negative about the one
 * thing this project cares most about not getting wrong — asserting
 * something that is not true. `resolveDbHandle` closes that gap by checking
 * the fallback location too (`resolveFallbackDbPath`, reused rather than
 * re-derived — the sha1 and directory layout live in exactly one place). When
 * only the fallback exists, it is opened DIRECTLY via `openDatabaseAtPath`,
 * not through another `openDatabase({ projectPath })` call — see that
 * function's own doc comment in `storage/db.ts` for why re-running the
 * writability probe at this point would risk creating a fresh, empty PRIMARY
 * database instead of reading the fallback that was just found.
 */
/**
 * True when `error` is the shape Node throws for a builtin module that does
 * not exist on the running Node version — `createRequire(...)('node:sqlite')`
 * in `storage/db.ts` throws exactly this when `node:sqlite` is not
 * registered (below the project's Node floor). Matched on BOTH the stable
 * error `code` and a message fallback (Node has changed the exact wording of
 * this error across versions; the `code` has not), so a genuine, unrelated
 * failure inside `storage`/`dashboard` (a real bug) is never misreported as
 * a Node-version problem — only this one, specific, well-known shape is.
 */
export function isNodeSqliteUnavailable(error) {
  if (error && typeof error === 'object' && 'code' in error && error.code === 'ERR_UNKNOWN_BUILTIN_MODULE') {
    return true;
  }
  const message = error instanceof Error ? error.message : String(error);
  return /node:sqlite/i.test(message);
}

/**
 * Lazily loads the `storage`/`dashboard` module cluster — see the module doc
 * comment above the (deliberately static) imports for why this is dynamic
 * rather than a top-level `import`. Mirrors `loadCiModules()` exactly: the
 * same "not built" friendly check (a marker file existence probe, so a repo
 * that never ran `npm run build` gets one clear line instead of
 * `ERR_MODULE_NOT_FOUND`), and — new here, because this cluster is the one
 * that can genuinely fail on a Node version this project no longer
 * supports — a SECOND friendly message specifically for that case, so
 * `status`/`dashboard` on Node < 22.13 fail with "this command requires
 * Node.js >= 22.13" rather than a raw `ERR_UNKNOWN_BUILTIN_MODULE` stack
 * trace. Only `status`/`dashboard` ever call this; every other subcommand
 * never touches `node:sqlite`, on any Node version — see the note above the
 * static imports.
 */
async function loadDashboardModules() {
  const marker = resolve(ROOT, 'mcp', 'dist', 'storage', 'index.js');
  if (!existsSync(marker)) {
    process.stderr.write(
      `dev-guardian: MCP server not built (missing ${marker}).\n` +
        'Run once:  cd mcp && npm install && npm run build\n',
    );
    process.exit(USAGE_ERROR_EXIT);
  }
  try {
    const [storage, migrations, snapshot, statusRenderer, dashboardRenderer] = await Promise.all([
      import('../mcp/dist/storage/index.js'),
      import('../mcp/dist/storage/migrations/runner.js'),
      import('../mcp/dist/dashboard/snapshot.js'),
      import('../mcp/dist/dashboard/renderStatus.js'),
      import('../mcp/dist/dashboard/renderHtml.js'),
    ]);
    return {
      openDatabase: storage.openDatabase,
      openDatabaseAtPath: storage.openDatabaseAtPath,
      resolveFallbackDbPath: storage.resolveFallbackDbPath,
      Storage: storage.Storage,
      runMigrations: migrations.runMigrations,
      buildSnapshot: snapshot.buildSnapshot,
      renderStatus: statusRenderer.renderStatus,
      renderDashboard: dashboardRenderer.renderDashboard,
    };
  } catch (e) {
    if (isNodeSqliteUnavailable(e)) {
      process.stderr.write(
        `dev-guardian: this command requires Node.js >= 22.13 (built-in node:sqlite support). ` +
          `Current: ${process.version}.\n`,
      );
      process.exit(USAGE_ERROR_EXIT);
    }
    throw e;
  }
}

/**
 * The storage layer's `existingOnly` open makes every decision the server
 * makes — a project database that is not this user's own (no id registered
 * for its path: one from before 3.1.0 until `db adopt --yes`), one git
 * tracks or one holding schema objects the migrations never create is
 * refused; the per-user fallback (no longer the shared temp directory) must
 * belong to this user — and never creates a database: an empty in-memory one
 * when neither location has one. The existence checks this function used to
 * make itself opened a predictable fallback path in the shared temp
 * directory whenever it existed.
 */
function resolveDbHandle(mods, projectPath) {
  const opened = mods.openDatabase({ projectPath, existingOnly: true });
  if (opened.unusable) {
    // The database this command exists to show cannot be read or completed.
    // The server runs on in memory; a report of an empty in-memory database
    // would read as "no scan yet", so this refuses with the storage layer's
    // own line (the file, and what to do) — exit 3, as before.
    opened.db.close();
    return usageError(opened.warning ?? `the database '${opened.unusable}' cannot be used`);
  }
  if (opened.warning) process.stderr.write(`dev-guardian: ${opened.warning}\n`);
  return opened.db;
}

function buildProjectSnapshot(mods, projectPath) {
  const db = resolveDbHandle(mods, projectPath);
  try {
    mods.runMigrations(db);
    const storage = new mods.Storage(db);
    // Rows are keyed by the canonical spelling every MCP tool stores
    // (resolveProjectPath); the database FILE is still located from
    // `projectPath` as given, as the server itself does.
    return mods.buildSnapshot(storage, canonicalPath(projectPath), Date.now());
  } finally {
    db.close();
  }
}

function parseStatusArgs(argv) {
  const out = { project: process.cwd() };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--project') {
      const r = takeOperand(argv, i, a);
      if (r.error) return r;
      out.project = r.value;
      i = r.nextIndex;
    } else if (a.startsWith('--project=')) out.project = a.slice('--project='.length);
    else return { error: `Unknown flag: ${a}` };
  }
  return { value: out };
}

function parseDashboardArgs(argv) {
  const out = { project: process.cwd(), out: undefined, noOpen: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--project') {
      const r = takeOperand(argv, i, a);
      if (r.error) return r;
      out.project = r.value;
      i = r.nextIndex;
    } else if (a.startsWith('--project=')) out.project = a.slice('--project='.length);
    else if (a === '--out') {
      // requireNonEmpty: true — fix-round-2 correction, mirroring --sarif's
      // OWN existing treatment in parseScanArgs exactly (both call sites,
      // not just this one). An empty --out is never a real destination
      // (unlike --base-url's empty string, which scan_dast reads and
      // meaningfully refuses): `resolve('')` is the cwd, and cmdDashboard
      // would then try to writeFileSync a DIRECTORY, throwing
      // "EISDIR: ... open '<cwd>'" — a real, non-silent exit 3, but one that
      // names an unrelated directory instead of the flag the user actually
      // got wrong. Refusing right here, the same way --sarif already does,
      // gives --out the same clean, flag-naming usage error instead.
      const r = takeOperand(argv, i, a, true);
      if (r.error) return r;
      out.out = r.value;
      i = r.nextIndex;
    } else if (a.startsWith('--out=')) {
      const value = a.slice('--out='.length);
      if (isMissingOperand(value, true)) return { error: '--out requires a value' };
      out.out = value;
    } else if (a === '--no-open') out.noOpen = true;
    else return { error: `Unknown flag: ${a}` };
  }
  return { value: out };
}

async function cmdStatus(argv) {
  const parsed = parseStatusArgs(argv);
  // parseStatusArgs's own `error` is already a complete, flag-naming message
  // (an unknown flag, or a value-taking flag with no operand) — no second
  // prefix needed here. Same convention as cmdScan/cmdBaseline.
  if (parsed.error) return usageError(parsed.error);
  const opts = parsed.value;

  const projectPath = resolveProjectOrExit(opts.project);
  const mods = await loadDashboardModules();
  const snapshot = buildProjectSnapshot(mods, projectPath);

  const color = process.stdout.isTTY === true && !process.env.NO_COLOR;
  const text = mods.renderStatus(snapshot, { color });
  process.stdout.write(text.endsWith('\n') ? text : `${text}\n`);

  // `process.exitCode = 0; return;`, never `process.exit(0)` — see the
  // matching comment at the end of cmdScan: stdout to a pipe is
  // asynchronous on POSIX, and the line above scales with finding count
  // (the design of record's findings cap is 2000), so it is not guaranteed to fit
  // inside one synchronous flush.
  process.exitCode = 0;
  return;
}

// ---------------------------------------------------------------------------
// import-sarif — the `import_sarif` tool without an assistant session
// ---------------------------------------------------------------------------

/**
 * Lazily loads the storage layer and the `import_sarif` tool module (loading
 * it registers it) — see loadDashboardModules for why this is dynamic and for
 * the two friendly failures (not built; Node without node:sqlite). The CLI
 * calls the tool's own handler, so it is the same import by construction.
 */
async function loadImportSarifModules() {
  const marker = resolve(ROOT, 'mcp', 'dist', 'tools', 'importSarif.js');
  if (!existsSync(marker)) {
    process.stderr.write(
      `dev-guardian: MCP server not built (missing ${marker}).\n` +
        'Run once:  cd mcp && npm install && npm run build\n',
    );
    process.exit(USAGE_ERROR_EXIT);
  }
  try {
    const [storage, tools] = await Promise.all([
      import('../mcp/dist/storage/index.js'),
      import('../mcp/dist/tools/index.js'),
      import('../mcp/dist/tools/importSarif.js'),
    ]);
    return { openDatabase: storage.openDatabase, Storage: storage.Storage, TOOLS: tools.TOOLS };
  } catch (e) {
    if (isNodeSqliteUnavailable(e)) {
      process.stderr.write(
        `dev-guardian: this command requires Node.js >= 22.13 (built-in node:sqlite support). ` +
          `Current: ${process.version}.\n`,
      );
      process.exit(USAGE_ERROR_EXIT);
    }
    throw e;
  }
}

function parseImportSarifArgs(argv) {
  const out = { file: undefined, project: process.cwd(), allowOutside: false, maxResults: undefined };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--project') {
      const r = takeOperand(argv, i, a, true);
      if (r.error) return r;
      out.project = r.value;
      i = r.nextIndex;
    } else if (a.startsWith('--project=')) {
      const value = a.slice('--project='.length);
      if (isMissingOperand(value, true)) return { error: '--project requires a value' };
      out.project = value;
    } else if (a === '--allow-outside-project') out.allowOutside = true;
    else if (a === '--max-results' || a.startsWith('--max-results=')) {
      let raw = a.slice('--max-results='.length);
      if (a === '--max-results') {
        const r = takeOperand(argv, i, a, true);
        if (r.error) return r;
        raw = r.value;
        i = r.nextIndex;
      }
      const n = Number(raw);
      if (!/^\d+$/.test(raw) || n < 1 || n > 200000) {
        return { error: '--max-results must be an integer from 1 to 200000' };
      }
      out.maxResults = n;
    } else if (a.startsWith('-')) return { error: `Unknown flag: ${a}` };
    else if (out.file === undefined) out.file = a;
    else return { error: `Unexpected argument: ${a}` };
  }
  if (out.file === undefined) return { error: 'import-sarif requires the SARIF file to import' };
  return { value: out };
}

/** Exit 1 for a log the tool refuses (invalid, outside the project, not a plain file, absent); 3 is a usage error. */
const IMPORT_SARIF_REFUSALS = new Set(['invalid_sarif', 'outside_project', 'refused_file', 'not_found']);

async function cmdImportSarif(argv) {
  const parsed = parseImportSarifArgs(argv);
  if (parsed.error) return usageError(parsed.error);
  const opts = parsed.value;

  const projectPath = resolveProjectOrExit(opts.project);
  const mods = await loadImportSarifModules();
  const tool = mods.TOOLS.find((t) => t.name === 'import_sarif');
  if (tool === undefined) return usageError('the import_sarif tool is not available in this build');

  const opened = mods.openDatabase({ projectPath });
  if (opened.unusable || opened.path === ':memory:') {
    // An import into a database that is thrown away at exit would report success and keep nothing.
    opened.db.close();
    return usageError(opened.warning ?? `the database '${opened.unusable ?? ':memory:'}' cannot be used`);
  }
  if (opened.warning) process.stderr.write(`dev-guardian: ${opened.warning}\n`);

  let result;
  try {
    const ctx = {
      storage: new mods.Storage(opened.db),
      shell: null,
      scriptsDir: '',
      progressNotifier: { send() {} },
      ...(opened.warning ? { storageWarning: opened.warning } : {}),
    };
    result = await tool.handler(
      {
        project_path: projectPath,
        // A path the user typed is relative to where they typed it, not to the project.
        sarif_path: resolve(opts.file),
        ...(opts.allowOutside ? { allow_outside_project: true } : {}),
        ...(opts.maxResults !== undefined ? { max_results: opts.maxResults } : {}),
      },
      ctx,
    );
  } finally {
    opened.db.close();
  }

  if (!result.ok) {
    process.stderr.write(`error: ${result.error.code}: ${result.error.message}\n`);
    process.exitCode = IMPORT_SARIF_REFUSALS.has(result.error.code) ? 1 : USAGE_ERROR_EXIT;
    return;
  }

  let partial = false;
  const lines = [];
  for (const run of result.runs) {
    const c = run.counts;
    if (c.skipped.length > 0 || c.truncated > 0) partial = true;
    lines.push(
      `scan ${run.scan_id}  ${run.scan_type}  coverage: ${run.coverage}`,
      `  results: ${c.results}  imported: ${c.imported}  without_location: ${c.without_location}  skipped: ${c.skipped.length}`,
      `  suppressed_at_source: ${c.suppressed_at_source}  not_findings: ${c.not_findings}  duplicates: ${c.duplicates}  truncated: ${c.truncated}`,
    );
    for (const w of run.warnings) lines.push(`  warning: ${w}`);
  }
  process.stdout.write(`${lines.join('\n')}\n`);
  // exitCode, not process.exit(): stdout to a pipe is asynchronous (see cmdStatus).
  process.exitCode = partial ? 2 : 0;
}

/**
 * Computes the `{ command, args }` this process spawns to open `target` in
 * the OS default browser — pure, no I/O, and exported so a test can assert
 * on the exact argv shape without ever launching anything.
 *
 * **win32 — fix-round-2 correction.** The fix-round-1 version spawned
 * `cmd.exe /c start "" <target>`, fixing the ENOENT from spawning the bare
 * `'start'` builtin directly (no `start.exe` on PATH) — but it traded that
 * bug for a second, subtler one this task exists to fix: `spawn(..., {shell:
 * false})` keeps `target` as its own untouched argv ELEMENT only up to
 * `CreateProcess` itself. `cmd.exe /c <rest>` does not treat `<rest>` as an
 * already-split argv — it re-parses the WHOLE remaining command line as
 * cmd's own script syntax, where `&` (and `|`, `&&`, `||`, `%VAR%`, …) are
 * live METACHARACTERS regardless of any quoting `spawn` applied when
 * building the underlying command line, because that quoting only has to
 * satisfy `CreateProcess`'s C-runtime argv split, not cmd's SEPARATE,
 * SECOND parse of its own `/c` argument. A dashboard path containing `&` —
 * plausible on Windows, where `&` is a legal filename character and this
 * project's own repo path contains a space for the same kind of reason —
 * would silently split into two commands under the OLD implementation;
 * `shell: false` never protected against this, because the danger was never
 * in how Node invoked `cmd.exe`, only in what `cmd.exe` itself does once
 * running.
 *
 * `explorer.exe <target>` sidesteps the whole problem: it is a real,
 * standalone executable (like `open`/`xdg-open` below), so `target` reaches
 * it as one argv element with no SECOND parse by anything that treats `&` as
 * syntax. (`explorer.exe` is also what Windows itself invokes for "open
 * with default application" on a file passed as a bare argument, so this is
 * not a repurposing of some other tool's argument grammar — it is that
 * grammar.) The `rundll32 url.dll,FileProtocolHandler <target>` alternative
 * named in the task brief was measured to behave identically for this one
 * argument shape and was not chosen only because `explorer.exe` needs no
 * DLL entry-point name to get right.
 *
 * **darwin/other — unchanged.** `open`/`xdg-open` ARE standalone
 * executables, spawned directly with `target` as their one argument — never
 * shared this class of bug, because neither re-parses its own argument for
 * shell metacharacters.
 */
export function resolveOpenerCommand(platform, target) {
  if (platform === 'win32') return { command: 'explorer.exe', args: [target] };
  if (platform === 'darwin') return { command: 'open', args: [target] };
  return { command: 'xdg-open', args: [target] };
}

/**
 * Best-effort only: opens `target` in the OS default browser and ignores
 * whatever happens. By the time this runs, `dashboard` has ALREADY written
 * its file and printed its path — a missing `xdg-open` in a headless
 * container, or any other spawn failure, must not turn an already-succeeded
 * command into a failure, and must not crash the process either.
 *
 * `spawn`'s failure to find the executable (ENOENT) surfaces asynchronously
 * as an `'error'` event, not a thrown exception — an EventEmitter `'error'`
 * with no listener attached throws on its own, so the listener below is not
 * decorative, it is what "ignored" actually requires. `shell: false` (see
 * `resolveOpenerCommand` for exactly what this still guarantees on win32)
 * matches this project's own house style for spawning anything with a
 * dynamic argument (see `--start-command` in the module doc comment above);
 * `detached: true` + `unref()` so this process exiting neither waits on, nor
 * attempts to tear down, the browser it started; `stdio: 'ignore'` keeps the
 * browser process from holding this CLI's own stdout/stderr pipes open.
 */
function openInBrowser(target) {
  const { command, args } = resolveOpenerCommand(process.platform, target);
  try {
    const child = spawn(command, args, { shell: false, detached: true, stdio: 'ignore' });
    child.on('error', () => {
      /* best-effort — see the doc comment above */
    });
    child.unref();
  } catch {
    /* best-effort — see the doc comment above */
  }
}

async function cmdDashboard(argv) {
  const parsed = parseDashboardArgs(argv);
  // Same convention as cmdScan/cmdBaseline — see cmdStatus's own comment.
  if (parsed.error) return usageError(parsed.error);
  const opts = parsed.value;

  const projectPath = resolveProjectOrExit(opts.project);
  const outPath = resolve(opts.out ?? join(projectPath, '.guardian', 'dashboard.html'));

  const mods = await loadDashboardModules();
  const snapshot = buildProjectSnapshot(mods, projectPath);
  const html = mods.renderDashboard(snapshot);

  // Both calls below can throw (an unwritable --out, a destination that is
  // itself a directory, a disk full) and are DELIBERATELY left to propagate
  // straight out of cmdDashboard to the top-level `.catch(fatal)` — nothing
  // has been written to stdout yet at this point, so a failure here must
  // report clearly and exit 3, never having already told the user it
  // succeeded. mkdirSync mirrors cmdScan's identical --sarif handling: the
  // destination directory may not exist yet (a custom --out is not required
  // to sit under the project's own .guardian/, which openDatabase already
  // created).
  //
  // A destination inside the project — the default `.guardian/dashboard.html`
  // among them — is the repository's path, which a checkout can make a link:
  // written through `platform/projectFs.ts` (a temp file renamed into place,
  // never through a link or a directory that links out). An `--out` outside
  // the project is the operator's own choice and written as given.
  if (isWithinDir(projectPath, outPath)) {
    const written = writeProjectFile(projectPath, outPath, html, { mode: 'replace' });
    if (!written.ok) {
      return usageError(`dashboard not written to ${outPath}: ${describeWriteRefusal(written.reason, written.detail)}`);
    }
  } else {
    mkdirSync(dirname(outPath), { recursive: true });
    writeFileSync(outPath, html);
  }

  process.stdout.write(`${outPath}\n`);

  // Opens a browser ONLY when stdout is a TTY (never inside a pipeline/CI —
  // spawnSync-driven tests give the child a pipe, so this is exercised by
  // construction) and --no-open was not passed. This check runs AFTER the
  // path has already been printed: opening the browser is a pure add-on to
  // an already-complete, already-reported success, never a precondition
  // for it.
  if (process.stdout.isTTY && !opts.noOpen) {
    openInBrowser(outPath);
  }

  // Same exit discipline as cmdStatus — see its own comment.
  process.exitCode = 0;
  return;
}

/**
 * Last-resort safety net for `cmdScan`/`cmdBaseline`/`cmdStatus`/
 * `cmdDashboard`/`cmdDb`: each already wraps (or, for status/dashboard,
 * delegates to `buildProjectSnapshot`'s own try/finally for) its own
 * storage/pipeline work and converts every usage problem to `usageError`
 * (exit 3), so nothing inside them SHOULD reject. This exists so that if one
 * somehow does anyway — a database the storage layer refuses (printed as
 * its own message, see `fatalOutcome`), an --out write failure, anything not
 * already caught closer to its source — Node reports one clean line and
 * exits 3, instead of an "unhandled promise rejection" warning on stderr —
 * exactly the kind of stray noise the pristine-output requirement (the
 * design of record, and this task's e2e) exists to keep out of a CI log.
 */
function fatal(e) {
  const out = fatalOutcome(e);
  process.stderr.write(out.text);
  process.exit(out.exitCode);
}

/**
 * What `fatal` prints for `e`, and its exit code — pure, for the tests.
 *
 * A `GuardianDbError` (`mcp/src/storage/dbError.ts`) is not an unexpected
 * error: it is a database dev-guardian cannot use, and its message already
 * names the file and what to do. Printed after "unexpected error:" it read as
 * a crash in dev-guardian, so it is printed alone — with exit 3, what
 * `status`/`dashboard` exit with when they refuse an unusable database
 * themselves. Recognised by name: the storage layer is loaded lazily from
 * `mcp/dist`, so this file holds no class to test `instanceof` against.
 * Anything else is still unexpected, exit 3.
 */
export function fatalOutcome(e) {
  if (e instanceof Error && e.name === 'GuardianDbError') {
    return { text: `dev-guardian: ${e.message}\n`, exitCode: USAGE_ERROR_EXIT };
  }
  return {
    text: `dev-guardian: unexpected error: ${e instanceof Error ? e.message : String(e)}\n`,
    exitCode: USAGE_ERROR_EXIT,
  };
}

// --- db adopt ---------------------------------------------------------------
//
// A project's `.guardian/guardian.db` is used only when it is this user's own
// (mcp/src/storage/dbProvenance.ts): created here, or registered here by the
// user. Nothing else is trusted automatically — not a database from before
// 3.1.0, not a copy of a registered one — because nothing in a file tells its
// owner from whoever wrote it (round 6 of the 3.0 review defeated every rule
// that tried). `db adopt` lets the PERSON decide: it prints what the database
// holds — what to weigh first (suppressions with no project, which apply to
// every project; scans dated in the future), then its projects, scan counts,
// dates, and every project path its rows are filed under with where each
// leads now — and registers it only with --yes. --rehome also moves the rows
// filed under another path that leads to this project (a link, macOS /var)
// to the project's canonical path, so its history reads again. A CLI command
// and never an MCP tool: a model whose context includes the repository must
// not be the one that vouches for the repository's database.

/** Lazily loads the storage layer (node:sqlite) — see loadDashboardModules. */
async function loadDbModules() {
  const marker = resolve(ROOT, 'mcp', 'dist', 'storage', 'db.js');
  if (!existsSync(marker)) {
    process.stderr.write(
      `dev-guardian: MCP server not built (missing ${marker}).\n` +
        'Run once:  cd mcp && npm install && npm run build\n',
    );
    process.exit(USAGE_ERROR_EXIT);
  }
  try {
    return await import('../mcp/dist/storage/db.js');
  } catch (e) {
    if (isNodeSqliteUnavailable(e)) {
      process.stderr.write(
        `dev-guardian: this command requires Node.js >= 22.13 (built-in node:sqlite support). ` +
          `Current: ${process.version}.\n`,
      );
      process.exit(USAGE_ERROR_EXIT);
    }
    throw e;
  }
}

function parseDbAdoptArgs(argv) {
  const out = { project: process.cwd(), yes: false, rehome: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--project') {
      const r = takeOperand(argv, i, a, true);
      if (r.error) return r;
      out.project = r.value;
      i = r.nextIndex;
    } else if (a.startsWith('--project=')) {
      const value = a.slice('--project='.length);
      if (isMissingOperand(value, true)) return { error: '--project requires a value' };
      out.project = value;
    } else if (a === '--yes') out.yes = true;
    else if (a === '--rehome') out.rehome = true;
    else return { error: `Unknown flag: ${a}` };
  }
  return { value: out };
}

const PATH_TARGET = {
  canonical: "this project's canonical path",
  'this-project': 'leads to this project: --rehome moves these rows to its canonical path',
  elsewhere: 'another directory: never touched',
  missing: 'does not exist: never touched',
  unresolved: 'not looked at (a network, device or process-relative path): never touched',
};

/** The human-readable report `db adopt` prints (stdout). */
function renderDbReport(report) {
  const lines = [];
  for (const w of report.warnings) lines.push(`!! ${w}`);
  if (report.warnings.length > 0) lines.push('');
  lines.push(`Database      ${report.db_path}`);
  const status = {
    trusted: "this user's database (registered for this location)",
    foreign: `not used: ${report.why ?? ''}`,
    none: 'empty: nothing to adopt',
  }[report.status];
  lines.push(`Status        ${status}`);
  const c = report.contents;
  if (c !== null) {
    const range = c.first_started !== null ? `, from ${c.first_started} to ${c.last_finished ?? '(unfinished)'}` : '';
    lines.push(`Scans         ${c.scans} (${c.completed} completed)${range}`);
    lines.push(`Projects      ${c.projects.length + c.more_projects}`);
    for (const p of c.projects) {
      lines.push(`  ${p.project_path}`);
      lines.push(
        `    ${p.scans} scan(s), ${p.completed} completed` +
          (p.first_started !== null ? `, ${p.first_started} .. ${p.last_finished ?? '(unfinished)'}` : ''),
      );
    }
    if (c.more_projects > 0) lines.push(`  … and ${c.more_projects} more`);
    lines.push(
      `Suppressions  ${c.suppressions}` +
        (c.null_scoped_suppressions > 0
          ? `, of which ${c.null_scoped_suppressions} have no project and apply to EVERY project`
          : ''),
    );
    lines.push(`Baselines     ${c.baselines}`);
  }
  if (report.paths.length > 0) {
    lines.push(`Paths         rows are filed under ${report.paths.length} project path(s); this project is ${report.canonical_project}`);
    for (const p of report.paths) {
      lines.push(`  ${p.project_path}`);
      lines.push(`    ${p.rows} row(s): ${PATH_TARGET[p.target] ?? p.target}`);
    }
    lines.push(
      report.rehome.rows > 0
        ? `--rehome would move ${report.rehome.rows} row(s) under ${report.rehome.paths} path(s) to ${report.canonical_project}, and nothing else.`
        : '--rehome would change nothing: no row is filed under another path that leads to this project.',
    );
  }
  if (report.blockers.length > 0) {
    lines.push('', 'It cannot be registered:');
    for (const b of report.blockers) lines.push(`  - ${b}`);
  }
  return `${lines.join('\n')}\n`;
}

async function cmdDb(argv) {
  const [sub, ...rest] = argv;
  if (sub !== 'adopt') {
    return usageError(`Unknown db subcommand: '${sub ?? '(none)'}' (only 'adopt' is supported)`);
  }
  const parsed = parseDbAdoptArgs(rest);
  if (parsed.error) return usageError(parsed.error);
  const opts = parsed.value;
  const projectPath = resolve(opts.project);
  if (!existsSync(projectPath) || !statSync(projectPath).isDirectory()) {
    return usageError(`--project does not exist or is not a directory: ${projectPath}`);
  }
  const mods = await loadDbModules();

  let report;
  try {
    report = mods.inspectProjectDatabase(projectPath);
  } catch (e) {
    process.stderr.write(`dev-guardian: ${e instanceof Error ? e.message : String(e)}\n`);
    process.exitCode = 1;
    return;
  }
  if (!report.exists) {
    process.stderr.write(`dev-guardian: there is no database at '${report.db_path}': nothing to adopt.\n`);
    process.exitCode = 1;
    return;
  }
  process.stdout.write(renderDbReport(report));
  if (report.blockers.length > 0) {
    process.exitCode = 1;
    return;
  }
  const trusted = report.status === 'trusted';
  if (!opts.yes) {
    process.stdout.write(
      trusted
        ? `\nAlready registered.${opts.rehome && report.rehome.rows > 0 ? ' Nothing changed: add --yes to --rehome.' : ''}\n`
        : '\nNot registered. If this is your database, run the same command with --yes yourself: dev-guardian ' +
            'then uses it and trusts what it holds' +
            ((report.contents?.null_scoped_suppressions ?? 0) > 0
              ? ` — the ${report.contents?.null_scoped_suppressions} suppression(s) that apply to every project included`
              : '') +
            '.\n',
    );
    process.exitCode = 0;
    return;
  }
  if (trusted && !opts.rehome) {
    process.stdout.write('\nAlready registered: nothing to do.\n');
    process.exitCode = 0;
    return;
  }
  try {
    const done = mods.registerProjectDatabase(projectPath, { rehome: opts.rehome });
    const lines = [];
    if (!done.already) {
      lines.push(`Registered '${done.db_path}' as this user's database (id ${done.db_id}). The server uses it from its next start.`);
    }
    if (done.rehomed !== undefined) {
      lines.push(
        `Rehomed ${done.rehomed.moved} row(s) from ${done.rehomed.paths} path(s) to ${report.canonical_project}` +
          (done.rehomed.kept > 0 ? `; ${done.rehomed.kept} row(s) left where they were (the same key exists there already)` : '') +
          '.',
      );
    }
    process.stdout.write(`\n${lines.join('\n')}\n`);
    process.exitCode = 0;
  } catch (e) {
    process.stderr.write(`dev-guardian: ${e instanceof Error ? e.message : String(e)}\n`);
    process.exitCode = 1;
  }
}

const HELP_FLAGS = new Set(['-h', '--help', 'help']);

/**
 * True when the user asked for help *of this CLI* somewhere after the command.
 *
 * Stops at `--start-command`, because everything after that belongs to the
 * user's application: `scan --start-command npm start --help` is asking npm
 * for help, not us, and swallowing it would silently skip the scan.
 */
function asksForHelp(rest) {
  for (let i = 0; i < rest.length; i++) {
    const a = rest[i];
    if (a === '--start-command') return false;
    // A value-taking flag's operand is its value, never a help request:
    // `scan --baseline-ref --help` used to print the usage and exit 0 without
    // scanning. The command's own parser then reads it (and a missing or
    // bad value is exit 3, as for any flag).
    if (VALUE_FLAGS.has(a)) {
      i += 1;
      continue;
    }
    if (HELP_FLAGS.has(a)) return true;
  }
  return false;
}

/** Every flag, of every subcommand, that takes its value as the next argument. */
const VALUE_FLAGS = new Set([
  '--project',
  '--fail-on',
  '--format',
  '--sarif',
  '--base-url',
  '--accept-partial-parse',
  '--baseline-ref',
  '--rules-ref',
  '--reset-exclusions-from',
  '--scope',
  '--file',
  '--bash',
  '--min',
  '--branch',
  '--out',
  '--max-results',
]);

function main() {
  const argv = process.argv.slice(2);
  const cmd = argv[0];
  if (!cmd || HELP_FLAGS.has(cmd)) {
    usage();
    process.exit(cmd ? 0 : 1);
  }
  // `scan --help` is the first thing anyone types. Answer it rather than
  // rejecting it as an unknown flag.
  if (asksForHelp(argv.slice(1))) {
    usage();
    process.exit(0);
  }
  if (cmd === 'mcp-config') return cmdMcpConfig(argv.slice(1));
  if (cmd === 'check') return cmdCheck(argv.slice(1));
  if (cmd === 'scan') return void cmdScan(argv.slice(1)).catch(fatal);
  if (cmd === 'baseline') return void cmdBaseline(argv.slice(1)).catch(fatal);
  if (cmd === 'ci-init') {
    // cmdCiInit is synchronous (no scan runs — see its own module doc), so
    // this is the sync equivalent of the `.catch(fatal)` every async
    // subcommand below uses: a write failure this function did not already
    // turn into a clean usageError (ENOTDIR, a read-only filesystem, …)
    // must not crash with a raw Node stack trace either.
    try {
      return cmdCiInit(argv.slice(1));
    } catch (e) {
      return fatal(e);
    }
  }
  if (cmd === 'status') return void cmdStatus(argv.slice(1)).catch(fatal);
  if (cmd === 'dashboard') return void cmdDashboard(argv.slice(1)).catch(fatal);
  if (cmd === 'db') return void cmdDb(argv.slice(1)).catch(fatal);
  if (cmd === 'import-sarif') return void cmdImportSarif(argv.slice(1)).catch(fatal);

  process.stderr.write(`Unknown command: ${cmd}\n\n`);
  usage();
  process.exit(1);
}

/**
 * Entry-point guard (fix-round-1 addition, fix-round-2 correction below):
 * `main()` runs when this file is executed directly (`node
 * cli/dev-guardian.mjs ...` — every real user invocation, and every existing
 * e2e test, which spawns exactly that as a subprocess) but NOT when it is
 * `import`ed, e.g. by `test/unit/cli/browserOpener.test.ts` to reach
 * `resolveOpenerCommand` as a plain function. Without this, that import alone
 * would run the full CLI against the TEST RUNNER's own argv/exit lifecycle —
 * `main()` calls `process.exit()` on more than one path — which would tear
 * down the whole vitest worker rather than merely fail one test.
 *
 * **Compares REALPATHS, not raw paths (fix-round-2 correction).** The
 * fix-round-1 version compared `import.meta.url` against
 * `pathToFileURL(process.argv[1]).href` directly — right for the
 * file-URL-vs-Windows-drive-letter mismatch it was written for, but it
 * assumed `process.argv[1]` and the module Node actually loaded name the
 * SAME path, which is false through a symlink or (Windows) junction: Node's
 * ESM loader resolves `import.meta.url` to the link's REAL target, while
 * `process.argv[1]` still holds the path the user typed — the link itself.
 * Two different strings naming the same file compared unequal, `isEntryPoint`
 * came back `false`, and `main()` silently never ran: reproduced directly —
 * `check --bash 'rm -rf /'` through a symlink to this file printed nothing
 * and exited 0, the same as a clean/ok command, on a catastrophic one.
 * `realpathSync` resolves symlinks/junctions on both sides before comparing,
 * so a link and its target compare equal regardless of which one was
 * invoked. Wrapped in try/catch: `process.argv[1]` can in principle name a
 * path `realpathSync` cannot resolve (already deleted, a dangling link) —
 * that must read as "not the entry point" (`main()` does not run) rather
 * than crash the module-load itself before a single line of user-facing
 * output is produced.
 */
function isRunAsEntryPoint() {
  if (process.argv[1] === undefined) return false;
  try {
    const thisFile = realpathSync(fileURLToPath(import.meta.url));
    const invoked = realpathSync(process.argv[1]);
    return thisFile === invoked;
  } catch {
    return false;
  }
}
const isEntryPoint = isRunAsEntryPoint();
if (isEntryPoint) {
  main();
}
