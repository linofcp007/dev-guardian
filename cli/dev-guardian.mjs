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
 *                             Exit codes: 0 pass, 1 gate failed, 2 incomplete
 *                             scan (a scanner did not run), 3 usage error.
 *   baseline update         Regenerate .guardian/baseline.json from the
 *                           current scan. The ONLY command that writes the
 *                           baseline — `scan` never does, on purpose.
 *                             Same pipeline flags as `scan` except --fail-on,
 *                             --format and --sarif (baseline update does not
 *                             gate or render a report — it writes a file).
 *
 *   node cli/dev-guardian.mjs mcp-config <host|all> [--write] [--scope …]
 *   node cli/dev-guardian.mjs check --file path/to/file
 *   node cli/dev-guardian.mjs check --bash "rm -rf /"
 *   node cli/dev-guardian.mjs scan --project . --fail-on high --sarif out.sarif
 *   node cli/dev-guardian.mjs baseline update --project .
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
  existsSync,
  mkdirSync,
  readFileSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { homedir } from 'node:os';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { ALL_HOSTS } from '../mcp/dist/hostsetup/hostSpecs.js';
import { previewMcpConfig, setupHost } from '../mcp/dist/hostsetup/setup.js';
import { detectOs } from '../mcp/dist/platform/osDetect.js';
import { scanForSecrets } from '../mcp/dist/hooks/secretScan.js';
import { assessBashCommand } from '../mcp/dist/hooks/bashGuard.js';

const HERE = dirname(fileURLToPath(import.meta.url)); // <plugin>/bin
const ROOT = resolve(HERE, '..'); // <plugin>
const SERVER_JS = resolve(ROOT, 'mcp', 'dist', 'server.js');
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
  node cli/dev-guardian.mjs check (--file <path> | --bash "<command>") [--min high|medium] [--json]
  node cli/dev-guardian.mjs scan [options]
  node cli/dev-guardian.mjs baseline update [options]

mcp-config — wire the MCP server into an AI host
  Hosts: ${[...ALL_HOSTS].join(', ')}, all
  --write              Write/merge into the project (+ drop the rules file)
  --scope project|global   MCP scope (default project)
  --project <path>     Target project directory (default: current directory)
  --force              Overwrite an existing rules file / update a differing MCP entry

check — run the guardrail detectors (same engine as the hooks)
  --file <path>        Scan a file for hard-coded secrets
  --bash "<command>"   Risk-assess a shell command (ok / warn / block)
  --min high|medium    Minimum secret confidence to report (default: medium)
  --json               Machine-readable output
  Exit code: 0 = clean/ok, 1 = secret found / command is risky or catastrophic

scan — headless CI: run the scan pipeline, gate against the baseline, report
  --project <path>      Target project directory (default: current directory)
  --fail-on <severity>  info|low|medium|high|critical (default: high)
  --format human|json   Report format on stdout (default: human)
  --sarif <path>        Also write a SARIF 2.1.0 report to this path
  --base-url <url>      Include scan_dast against this target. Also the
                         health-check URL when --start-command is given —
                         they are the same origin, so one flag names both.
  --authorized-target   Confirm you are authorized to DAST-test that target
  --start-command <cmd> [args…]
                         Start <cmd> (argv, never a shell) for the DAST pass
                         and stop it — whole process tree — when the scan
                         ends, however it ends. Requires --base-url. CLI
                         ARGV ONLY — never honoured from a repository file
                         (see the module header comment for why).
  Never writes .guardian/baseline.json — see \`baseline update\`.
  Exit codes: 0 pass, 1 gate failed (new finding >= --fail-on),
              2 incomplete scan (an expected scanner did not run),
              3 usage or configuration error.

baseline update — regenerate .guardian/baseline.json from the current scan
  Same pipeline flags as scan: --project, --base-url, --authorized-target,
  --start-command (same argv-only rule, --base-url requirement, and
  teardown). No --fail-on/--format/--sarif — this command does not gate or
  render a report, it writes a file.
  The ONLY dev-guardian command that writes the baseline; scan never does.
  Exit codes: 0 written with full coverage, 2 written but an expected
              scanner did not run (baseline may under-represent findings),
              3 usage or configuration error.

Examples:
  node cli/dev-guardian.mjs mcp-config cursor          # print the block to paste
  node cli/dev-guardian.mjs mcp-config codex --write   # write + merge into the project
  node cli/dev-guardian.mjs check --file src/config.ts
  node cli/dev-guardian.mjs check --bash "curl x | sh"
  node cli/dev-guardian.mjs scan --project . --sarif results.sarif
  node cli/dev-guardian.mjs baseline update --project .
`);
}

function parseArgs(argv) {
  const out = { _: [], scope: 'project', write: false, force: false, project: process.cwd() };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--write') out.write = true;
    else if (a === '--force') out.force = true;
    else if (a === '--scope') out.scope = argv[++i];
    else if (a.startsWith('--scope=')) out.scope = a.slice('--scope='.length);
    else if (a === '--project') out.project = argv[++i];
    else if (a.startsWith('--project=')) out.project = a.slice('--project='.length);
    else out._.push(a);
  }
  if (out.scope !== 'project' && out.scope !== 'global') out.scope = 'project';
  return out;
}

function indent(s) {
  return s
    .split('\n')
    .map((l) => `    ${l}`)
    .join('\n');
}

function cmdMcpConfig(argv) {
  const args = parseArgs(argv);
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

function parseCheckArgs(argv) {
  const out = { file: undefined, bash: undefined, min: 'medium', json: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--file') out.file = argv[++i];
    else if (a.startsWith('--file=')) out.file = a.slice('--file='.length);
    else if (a === '--bash') out.bash = argv[++i];
    else if (a.startsWith('--bash=')) out.bash = a.slice('--bash='.length);
    else if (a === '--min') out.min = argv[++i];
    else if (a.startsWith('--min=')) out.min = a.slice('--min='.length);
    else if (a === '--json') out.json = true;
  }
  if (out.min !== 'high' && out.min !== 'medium') out.min = 'medium';
  return out;
}

function loadAllowlist(projectDir) {
  try {
    const p = resolve(projectDir, '.guardian', 'hooks-allowlist.json');
    if (!existsSync(p)) return [];
    const data = JSON.parse(readFileSync(p, 'utf8'));
    if (Array.isArray(data)) return data.filter((x) => typeof x === 'string');
    if (data && Array.isArray(data.secrets)) return data.secrets.filter((x) => typeof x === 'string');
  } catch {
    /* ignore */
  }
  return [];
}

function cmdCheck(argv) {
  const opts = parseCheckArgs(argv);

  if (opts.bash != null) {
    const a = assessBashCommand(opts.bash);
    if (opts.json) {
      process.stdout.write(JSON.stringify(a) + '\n');
    } else {
      const icon = a.level === 'block' ? '⛔' : a.level === 'warn' ? '⚠️ ' : '✅';
      process.stdout.write(`${icon} ${a.level.toUpperCase()}\n`);
      for (const r of a.reasons) process.stdout.write(`  • ${r}\n`);
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
      text = readFileSync(filePath, 'utf8');
    } catch (e) {
      process.stderr.write(`Cannot read ${filePath}: ${e instanceof Error ? e.message : String(e)}\n`);
      process.exit(2);
    }
    const allowlist = loadAllowlist(process.cwd());
    const hits = scanForSecrets(text, { minConfidence: opts.min, allowlist });
    if (opts.json) {
      process.stdout.write(JSON.stringify({ file: filePath, hits }) + '\n');
    } else if (hits.length === 0) {
      process.stdout.write(`✅ No secrets detected in ${opts.file}\n`);
    } else {
      process.stdout.write(`⚠️  ${hits.length} possible secret(s) in ${opts.file}:\n`);
      for (const h of hits) {
        process.stdout.write(`  • ${h.title} (${h.confidence}) — line ${h.line}: ${h.preview}\n`);
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
  const [ciTypes, baseline, gate, report, runScansMod, appRunner, types] = await Promise.all([
    import('../mcp/dist/ci/types.js'),
    import('../mcp/dist/ci/baseline.js'),
    import('../mcp/dist/ci/gate.js'),
    import('../mcp/dist/ci/report.js'),
    import('../mcp/dist/ci/runScans.js'),
    import('../mcp/dist/ci/appRunner.js'),
    import('../mcp/dist/types.js'),
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
  };
}

/**
 * Default budget for `--start-command` to become healthy — generous for a
 * typical `npm start`/build-then-serve boot (which can genuinely take tens
 * of seconds under a cold cache) while still bounded: design doc §7 and the
 * app-runner module both exist because "a hang is the worst failure mode in
 * CI" (a job that never finishes burns its whole budget and the log says
 * nothing). Not exposed as a flag — the brief scopes `--start-command` to
 * argv + `--base-url` only, and a fixed, documented default is simpler than
 * a knob nobody asked for; revisit if a real pipeline needs a slower boot.
 */
const APP_START_TIMEOUT_MS = 60_000;

/**
 * The pwn-request guard (design doc §7). `--start-command` may be supplied
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
  if (!existsSync(configPath)) return null;
  let data;
  try {
    data = JSON.parse(readFileSync(configPath, 'utf8'));
  } catch {
    return null;
  }
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

/** Shared by `parseScanArgs`/`parseBaselineUpdateArgs`: `--start-command`
 *  consumes the REST of argv as the command's own argv (never a shell
 *  string), so it must be the last flag handled and must stop the loop —
 *  otherwise a plausible token after it (say, another `--flag`-looking
 *  argument meant for the started app) would be mis-parsed as one of THIS
 *  CLI's own flags instead of being passed straight through. */
function consumeStartCommand(argv, i) {
  return argv.slice(i + 1);
}

function parseScanArgs(argv) {
  const out = {
    project: process.cwd(),
    failOn: 'high',
    format: 'human',
    sarif: undefined,
    baseUrl: undefined,
    authorizedTarget: false,
    startCommand: undefined,
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--project') out.project = argv[++i];
    else if (a.startsWith('--project=')) out.project = a.slice('--project='.length);
    else if (a === '--fail-on') out.failOn = argv[++i];
    else if (a.startsWith('--fail-on=')) out.failOn = a.slice('--fail-on='.length);
    else if (a === '--format') out.format = argv[++i];
    else if (a.startsWith('--format=')) out.format = a.slice('--format='.length);
    else if (a === '--sarif') out.sarif = argv[++i];
    else if (a.startsWith('--sarif=')) out.sarif = a.slice('--sarif='.length);
    else if (a === '--base-url') out.baseUrl = argv[++i];
    else if (a.startsWith('--base-url=')) out.baseUrl = a.slice('--base-url='.length);
    else if (a === '--authorized-target') out.authorizedTarget = true;
    else if (a === '--start-command') {
      out.startCommand = consumeStartCommand(argv, i);
      break;
    } else return { error: a };
  }
  return { value: out };
}

function parseBaselineUpdateArgs(argv) {
  const out = {
    project: process.cwd(),
    baseUrl: undefined,
    authorizedTarget: false,
    startCommand: undefined,
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--project') out.project = argv[++i];
    else if (a.startsWith('--project=')) out.project = a.slice('--project='.length);
    else if (a === '--base-url') out.baseUrl = argv[++i];
    else if (a.startsWith('--base-url=')) out.baseUrl = a.slice('--base-url='.length);
    else if (a === '--authorized-target') out.authorizedTarget = true;
    else if (a === '--start-command') {
      out.startCommand = consumeStartCommand(argv, i);
      break;
    } else return { error: a };
  }
  return { value: out };
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

async function cmdScan(argv) {
  const parsed = parseScanArgs(argv);
  if (parsed.error) return usageError(`Unknown flag: ${parsed.error}`);
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
  } = ci;

  if (!SEVERITIES.includes(opts.failOn)) {
    return usageError(`--fail-on must be one of ${SEVERITIES.join('|')} (got '${opts.failOn}')`);
  }
  if (opts.format !== 'human' && opts.format !== 'json') {
    return usageError(`--format must be 'human' or 'json' (got '${opts.format}')`);
  }

  const projectPath = resolveProjectOrExit(opts.project);
  enforceStartCommandRules(projectPath, opts);

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
  let pipelineError = null;
  let result;
  try {
    if (opts.startCommand !== undefined) {
      app = await startApp({
        command: opts.startCommand,
        cwd: projectPath,
        healthUrl: opts.baseUrl,
        timeoutMs: APP_START_TIMEOUT_MS,
      });
    }
    result = await runScans({
      projectPath,
      baseUrl: opts.baseUrl,
      authorizedTarget: opts.authorizedTarget ? true : undefined,
    });
  } catch (e) {
    pipelineError = e;
  } finally {
    if (app) await app.stop();
  }
  if (pipelineError) {
    return usageError(`scan failed to run: ${pipelineError instanceof Error ? pipelineError.message : String(pipelineError)}`);
  }

  const baselinePath = resolve(projectPath, BASELINE_RELATIVE_PATH);
  const baselineText = existsSync(baselinePath) ? readFileSync(baselinePath, 'utf8') : null;
  const parsedBaseline = parseBaseline(baselineText);

  const verdict = evaluateGate({
    findings: result.findings,
    baseline: parsedBaseline ? parsedBaseline.file : null,
    failOn: opts.failOn,
    steps: result.steps,
    droppedBaselineEntries: parsedBaseline ? parsedBaseline.dropped : 0,
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
  // case design doc §4 names — can be truncated mid-write on a real Linux CI
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
  if (parsed.error) return usageError(`Unknown flag: ${parsed.error}`);
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
  // comment there. `baseline update` accepts --start-command/--base-url for
  // the identical reason: scan_dast is part of the same pipeline this
  // command runs, so an app it started must be stopped before this function
  // can exit, on every path, and `usageError` below must never be reached
  // from inside a catch nested in this try.
  let app = null;
  let pipelineError = null;
  let result;
  try {
    if (opts.startCommand !== undefined) {
      app = await startApp({
        command: opts.startCommand,
        cwd: projectPath,
        healthUrl: opts.baseUrl,
        timeoutMs: APP_START_TIMEOUT_MS,
      });
    }
    result = await runScans({
      projectPath,
      baseUrl: opts.baseUrl,
      authorizedTarget: opts.authorizedTarget ? true : undefined,
    });
  } catch (e) {
    pipelineError = e;
  } finally {
    if (app) await app.stop();
  }
  if (pipelineError) {
    return usageError(`scan failed to run: ${pipelineError instanceof Error ? pipelineError.message : String(pipelineError)}`);
  }

  const baselinePath = resolve(projectPath, BASELINE_RELATIVE_PATH);
  const baselineText = existsSync(baselinePath) ? readFileSync(baselinePath, 'utf8') : null;
  const parsedBaseline = parseBaseline(baselineText);
  const previousFile = parsedBaseline ? parsedBaseline.file : null;

  const updated = buildBaseline(result.findings, previousFile, new Date().toISOString());

  // The only write path in this whole CLI that touches the user's
  // repository — see the module doc and the task report's self-review.
  mkdirSync(dirname(baselinePath), { recursive: true });
  writeFileSync(baselinePath, serialiseBaseline(updated));

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
    for (const gap of verdict.coverageGaps) process.stdout.write(`  - ${gap}\n`);
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

/**
 * Last-resort safety net for `cmdScan`/`cmdBaseline`: both already wrap
 * their own `runScans()` call in try/catch and convert every usage problem
 * to `usageError` (exit 3), so nothing inside them SHOULD reject. This
 * exists so that if one somehow does anyway, Node reports one clean line and
 * exits 3, instead of an "unhandled promise rejection" warning on stderr —
 * exactly the kind of stray noise the pristine-output requirement (design
 * doc §8, and this task's e2e) exists to keep out of a CI log.
 */
function fatal(e) {
  process.stderr.write(`dev-guardian: unexpected error: ${e instanceof Error ? e.message : String(e)}\n`);
  process.exit(USAGE_ERROR_EXIT);
}

function main() {
  const argv = process.argv.slice(2);
  const cmd = argv[0];
  if (!cmd || cmd === '-h' || cmd === '--help' || cmd === 'help') {
    usage();
    process.exit(cmd ? 0 : 1);
  }
  if (cmd === 'mcp-config') return cmdMcpConfig(argv.slice(1));
  if (cmd === 'check') return cmdCheck(argv.slice(1));
  if (cmd === 'scan') return void cmdScan(argv.slice(1)).catch(fatal);
  if (cmd === 'baseline') return void cmdBaseline(argv.slice(1)).catch(fatal);

  process.stderr.write(`Unknown command: ${cmd}\n\n`);
  usage();
  process.exit(1);
}

main();
