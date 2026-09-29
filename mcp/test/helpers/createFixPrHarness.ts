/**
 * The shared harness of the create_fix_pr integration files —
 * `createFixPr.test.ts` (selection, refusals, the breakdown, the PR body),
 * `createFixPrDryRun.test.ts` (what a dry run must leave untouched),
 * `createFixPrOpenPr.test.ts` (a real PR, then a repeat run) and
 * `createFixPrLocalRules.test.ts` (a semgrep fix verified with the project's
 * own rules).
 *
 * They were one file that took 365-385 s — the longest file in the suite, and
 * so the floor under the whole run's wall clock — because vitest runs the
 * tests of one file one after another (review 3.0, R7). Split by concern,
 * the files run in parallel. Every test body moved unchanged.
 *
 * Call {@link useFixPrRepo} once at the top level of a test file: it registers
 * the `beforeEach` / `afterEach` that make the throwaway repository and the
 * stub `gh`. `repo`, `binDir`, `ghLog` and `originDir` are live
 * bindings: read them inside a test, never at import time.
 *
 * `create_fix_pr` driven end to end against a real git repo, a real npm
 * registry and the real scanners. Nothing here is mocked except `gh` (see
 * the stub in `beforeEach`), and that is the point: the tool's whole job is
 * to apply a fix and then PROVE it worked, and a proof against a fake
 * scanner proves nothing.
 *
 * ---- Where the runtime goes, and why the timeouts look the way they do ---
 *
 * The original file took ~2 minutes on an idle machine, ~3.5 under a loaded one,
 * and that is not accidental overhead — it is network round-trips the tests
 * genuinely make. Measured by instrumenting `runProcess` (2026-08-20,
 * Windows, idle, 132s total for the file):
 *
 *   semgrep --config auto --json     x3   24.8s   (the verification re-scan)
 *   semgrep --config auto --autofix  x3   23.8s   (the fix itself)
 *   npm audit --json                x11   19.9s   (deps_audit, before+after)
 *   npm install --package-lock-only  x6   11.4s   (the deps fix itself)
 *   npm install --silent (setup)     x6  ~16s     (setupLodashRepo)
 *   trivy fs                        x11    4.1s
 *   git + gh                          -   ~6s
 *
 * So ~95 of those ~132 seconds are round-trips to the Semgrep rule registry
 * and to the npm registry. `--config auto` refetches its rules on EVERY
 * invocation — measured 7.4s warm, standalone, on a two-file project — and
 * this file invokes it six times.
 *
 * The per-test timeouts were 30s and 45s against tests measuring 8–18s
 * idle, i.e. a margin of 2–3x. That is not a margin at all once other
 * vitest files are competing for the same CPU and the same network: one
 * case was reported at 29.4s against its 30s bound. `REGISTRY_BACKED_
 * TIMEOUT_MS` below is sized against the MEASURED worst case (18.1s) with a
 * margin load cannot close, and it bounds a genuine hang, nothing else — no
 * test in this file asserts anything by reaching it.
 */
import { afterEach, beforeEach } from 'vitest';
import { execFileSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { mkdtempSync, writeFileSync, chmodSync, existsSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { openDatabase } from '../../src/storage/db.js';
import { Storage } from '../../src/storage/index.js';
import { TOOLS } from '../../src/tools/index.js';
import type { Finding } from '../../src/types.js';
import '../../src/registerAll.js';
import { rmDirOrDefer } from './tempDir.js';
import { isInstalled } from './toolchain.js';

// execFileSync (unlike execa/runProcess, which shell out through
// cross-spawn) does not resolve npm's Windows .cmd shim on its own — same
// reason this file already spells out 'gh.cmd' below rather than just 'gh'.
const NPM_BIN = process.platform === 'win32' ? 'npm.cmd' : 'npm';

/** See the module comment for the measurements this number comes from. */
export const REGISTRY_BACKED_TIMEOUT_MS = 120_000;

/* ------------------------------------------------------------------ */
/* Toolchain availability — same technique as rulePackFixture.test.ts  */
/* ------------------------------------------------------------------ */

/**
 * Resolved once, at collection time, so `it.skipIf` can report a skip as a
 * skip — this repo's established discipline everywhere else (see
 * `rulePackFixture.test.ts`'s header) and, until now, the one place it was
 * missing.
 *
 * Three tests (two in createFixPrOpenPr, the risk_score one in
 * createFixPrDryRun) need a real, TRIVY-sourced CVE record and not merely a
 * finding that happens to mention lodash. Without trivy on PATH they FAILED
 * rather than skipped, which is why a Linux container run of this file reads
 * as behavioural failures when it is really an unmet environment dependency.
 * Measured directly with trivy removed from PATH: the `risk_score` test
 * fails on `expect(active_cves).toBeGreaterThan(0)`, because `active_cves`
 * is read from the `cves` table (`storage.cves.listActive`) and only trivy's
 * parser ever writes a row there — `npm audit` findings do not land in it.
 * The other two need the scan differential to genuinely PASS against the
 * scanner that reported the target, which is what makes `outcome:
 * 'pr_created'` reachable at all.
 *
 * `gh` is deliberately NOT gated: `beforeEach` puts a stub `gh` on PATH that
 * shadows any real one, so every `gh`-touching test here passes with the
 * real `gh` uninstalled — confirmed by running this file with `gh`, `trivy`
 * and `semgrep` all removed from PATH, where only the trivy-dependent test
 * above failed.
 */
export const TRIVY_INSTALLED = await isInstalled('trivy');
export const REQUIRE_SEMGREP = process.env['GUARDIAN_REQUIRE_SEMGREP'] === '1';
export const SEMGREP_INSTALLED = await isInstalled('semgrep');
export const DOTNET_INSTALLED = await isInstalled('dotnet');

export let repo: string;
export let binDir: string;
export let ghLog: string;
export let originDir: string | null;

/** Registers the per-test repository and stub `gh` (see the module comment). */
export function useFixPrRepo(): void {
  let pathBefore: string | undefined;
  beforeEach(() => {
    repo = mkdtempSync(join(tmpdir(), 'fixpr-tool-'));
    execFileSync('git', ['init', '-q', '-b', 'main', repo]);
    execFileSync('git', ['-C', repo, 'config', 'user.email', 't@example.com']);
    execFileSync('git', ['-C', repo, 'config', 'user.name', 'T']);
    writeFileSync(join(repo, 'package.json'), JSON.stringify({ name: 'x', version: '1.0.0' }));
    execFileSync('git', ['-C', repo, 'add', '.']);
    execFileSync('git', ['-C', repo, 'commit', '-q', '-m', 'first']);
    originDir = null;

    // A stub `gh` that records every invocation and fails loudly if asked to push.
    binDir = mkdtempSync(join(tmpdir(), 'fixpr-bin-'));
    ghLog = join(binDir, 'gh.log');
    const script = process.platform === 'win32'
      ? `@echo off\r\n>>"${ghLog}" echo %*\r\nexit /b 0\r\n`
      : `#!/bin/sh\necho "$@" >> "${ghLog}"\nexit 0\n`;
    const ghPath = join(binDir, process.platform === 'win32' ? 'gh.cmd' : 'gh');
    writeFileSync(ghPath, script);
    if (process.platform !== 'win32') chmodSync(ghPath, 0o755);
    pathBefore = process.env['PATH'];
    process.env['PATH'] = `${binDir}${process.platform === 'win32' ? ';' : ':'}${process.env['PATH'] ?? ''}`;
  });

  afterEach(() => {
    // Restored, not left to grow one dead directory per test for the rest of
    // the worker's life.
    if (pathBefore !== undefined) process.env['PATH'] = pathBefore;
    rmDirOrDefer(repo);
    rmDirOrDefer(binDir);
    if (originDir) rmDirOrDefer(originDir);
  });
}

/**
 * Adds a real BARE repo as `origin` so `git push` inside `openPr` can
 * genuinely succeed — none of the tests above needed this (they stop at
 * verification, or at a push that is EXPECTED to fail for lack of a remote),
 * but proving C1 means inspecting an actual committed diff, which means
 * actually reaching `created`.
 */
export function addOriginRemote(): void {
  originDir = mkdtempSync(join(tmpdir(), 'fixpr-origin-'));
  execFileSync('git', ['init', '-q', '--bare', '-b', 'main', originDir]);
  execFileSync('git', ['-C', repo, 'remote', 'add', 'origin', originDir]);
}

/**
 * A REAL, network-backed 'deps' fix scenario, used instead of a semgrep
 * fixture: no `--config auto` rule with a reliable autofix was found in this
 * session (several candidates probed — eval/md5/csurf/f-string/yaml.load —
 * none carried a `fix`), while lodash@4.17.20 carries several genuine, real
 * CVEs (CVE-2021-23337 among them) that `npm outdated`/`trivy fs` both
 * confirm reachable and fast (~1-3s each) from this environment. Verified
 * lodash@4.18.1 (the version `npm outdated` resolves "latest" to) is itself
 * trivy-clean (no CVE, only the expected MIT license notice) before relying
 * on it here, so the fix is expected to genuinely resolve every target with
 * nothing new appearing.
 *
 * A FULL `npm install`, not `--package-lock-only`: `deps_update_plan`'s own
 * npm-outdated parsing reads npm's `current` field (installed version),
 * which npm only reports for a package actually present in `node_modules` —
 * with nothing installed, `npm outdated --json` omits `current` entirely
 * and `deps_update_plan` (correctly) treats that as nothing to compare,
 * reporting no outdated packages at all. Confirmed directly: this cost the
 * first version of this fixture an empty `plan` and hence zero groups.
 * `node_modules` itself is not committed (`.gitignore`d) — only
 * `package.json`/`package-lock.json` are, which is all `applyGroup`'s own
 * `--package-lock-only` fix needs inside the worktree.
 */
export function setupLodashRepo(): void {
  writeFileSync(join(repo, 'package.json'), JSON.stringify({
    name: 'x', version: '1.0.0', dependencies: { lodash: '4.17.20' },
  }));
  // shell: true — Windows's npm.cmd is not directly spawnable (EINVAL)
  // without going through a shell; this file's own runtime code never does
  // this (runProcess is shell:false end to end via execa, which handles the
  // .cmd resolution itself), this is test-setup-only.
  execFileSync(NPM_BIN, ['install', '--silent'], { cwd: repo, shell: true });
  writeFileSync(join(repo, '.gitignore'), 'node_modules/\n');
  execFileSync('git', ['-C', repo, 'add', 'package.json', 'package-lock.json', '.gitignore']);
  execFileSync('git', ['-C', repo, 'commit', '-q', '-m', 'add lodash']);
}

/**
 * Runs the REAL `deps_audit` tool (real Trivy) against `repo` as test setup,
 * so create_fix_pr's own reads (`listOpenForProject`, `getLatestForProject`)
 * see a genuine "before" scan — the actual CVE-2021-23337 finding and the
 * actual MIT license finding trivy reports for lodash@4.17.20 — rather than
 * a hand-constructed approximation that could silently drift from what the
 * real parser actually produces (exactly the mismatch that made the first
 * version of this fixture fail: a hand-seeded "before" state that omitted
 * the license finding read the SAME license finding as "new" once the real
 * post-fix re-scan reported it).
 */
export async function seedRealDepsBefore(c: ReturnType<typeof ctx>): Promise<void> {
  const depsAudit = TOOLS.find((t) => t.name === 'deps_audit');
  const res = await depsAudit?.handler({ project_path: repo }, c as never);
  if (!res || !res.ok) {
    throw new Error(`setup: deps_audit against the real repo failed: ${JSON.stringify(res)}`);
  }
}

export function ctx() {
  // openDatabase({ inMemory: true }) returns { db, path }, not a raw DB, and
  // already runs migrations internally — the brief's own ctx() snippet calls
  // runMigrations(openDatabase(...)) and new Storage(openDatabase(...)),
  // passing the wrapper where a raw DB is expected on both counts. Fixed here
  // by unwrapping .db and dropping the now-redundant runMigrations call.
  // `projectPath` is genuinely ignored when `inMemory: true` (see the doc
  // comment on `OpenOptions`), but the type still requires it — pass a
  // placeholder that is never read rather than relax the src/ type.
  const { db } = openDatabase({ inMemory: true, projectPath: tmpdir() });
  return { storage: new Storage(db) };
}

/**
 * Seeds one Finding as the sole content of a completed scan for `projectPath`,
 * so `findings.listOpenForProject` — what the tool reads — returns it. Mirrors
 * the seeding pattern already used by `ciRunScans.test.ts` / `metaTools.test.ts`.
 */
export function seedFinding(c: ReturnType<typeof ctx>, projectPath: string, finding: Finding): void {
  seedFindings(c, projectPath, [finding]);
}

/**
 * The plural form — and it is not a convenience. `listOpenForProject` reads
 * the LATEST completed scan only, so seeding N findings by calling
 * `seedFinding` N times creates N scans and the tool sees exactly one
 * finding: the last. Any test about counts across several findings has to
 * put them in one scan, which is also what a real scan does.
 */
export function seedFindings(c: ReturnType<typeof ctx>, projectPath: string, findings: Finding[]): void {
  const scanId = randomUUID();
  c.storage.scans.insert({
    scan_id: scanId,
    scan_type: 'sast',
    project_path: projectPath,
    tree_hash: 'deadbeef',
  });
  c.storage.findings.bulkInsert(findings.map((f) => ({ ...f, scan_id: scanId })));
  c.storage.scans.finalize({ scan_id: scanId, status: 'completed', tools_run: [], missing_tools: [] });
}

export function semgrepFinding(over: Partial<Finding> = {}): Finding {
  return {
    fingerprint: 'fp-semgrep-1',
    tool: 'semgrep',
    rule_id: 'javascript.express.security.some-rule',
    severity: 'high',
    category: 'security',
    title: 'Hardcoded secret',
    message: 'do not hardcode secrets',
    file_path: 'src/index.js',
    line_start: 1,
    fix_available: true,
    ...over,
  };
}

export function ghLogContents(): string {
  return existsSync(ghLog) ? readFileSync(ghLog, 'utf8') : '';
}

export function worktreeCount(): number {
  return execFileSync('git', ['-C', repo, 'worktree', 'list'], { encoding: 'utf8' })
    .trim()
    .split('\n').length;
}

/**
 * Overwrites the stub `gh` this file's own `beforeEach` already put on
 * PATH — same path, new behaviour. Used only by the I1 test below. The
 * `beforeEach` stub is stateless: every invocation, of any subcommand,
 * unconditionally logs and returns success with EMPTY stdout — enough for
 * every other test in this file, which only cares whether `pr create` /
 * `push` were reached at all, but not enough to simulate "a PR now exists
 * for this branch", which is what a repeat run past this point needs `gh pr
 * list` to actually report. `pr create` fails loudly here rather than
 * quietly "succeeding": if a wrong implementation still reaches `openPr`
 * after this point, the test sees that failure instead of a second
 * indistinguishable `pr_created`.
 *
 * Node-backed, not raw batch/shell `if %1==...` parsing: confirmed directly
 * that on Windows, `%1` arrives as the literal 4-character text `"pr"` —
 * quotes included, because cross-spawn (which `runProcess` goes through for
 * a `.cmd` target, same as this file's own top comment already notes for
 * `npm.cmd`) quotes each argv token when it builds the command line, and raw
 * batch `%1` substitution does not strip that the way real argv parsing
 * does — so a bare `"%1"=="pr"` comparison (adding a SECOND pair of quotes)
 * never matches. Node's own `process.argv` has no such quirk, so the actual
 * branch logic lives in a tiny Node script; the platform-specific `.cmd`/
 * shell file only forwards argv to it.
 */
export function installGhStubThatReportsAnExistingPr(): void {
  const ghPath = join(binDir, process.platform === 'win32' ? 'gh.cmd' : 'gh');
  const stubScriptPath = join(binDir, 'gh-stub.mjs');
  writeFileSync(stubScriptPath, [
    "import { appendFileSync } from 'node:fs';",
    'const args = process.argv.slice(2);',
    `appendFileSync(${JSON.stringify(ghLog)}, args.map((a) => '"' + a + '"').join(' ') + '\\n');`,
    "if (args[0] === 'pr' && args[1] === 'list') {",
    "  process.stdout.write('[{\"number\":1}]');",
    '  process.exit(0);',
    '}',
    "if (args[0] === 'pr' && args[1] === 'create') {",
    "  process.stderr.write('already exists — this stub should never be asked to create a second PR');",
    '  process.exit(1);',
    '}',
    'process.exit(0);',
    '',
  ].join('\n'));

  const script = process.platform === 'win32'
    ? `@echo off\r\n"${process.execPath}" "${stubScriptPath}" %*\r\n`
    : `#!/bin/sh\nexec "${process.execPath}" "${stubScriptPath}" "$@"\n`;
  writeFileSync(ghPath, script);
  if (process.platform !== 'win32') chmodSync(ghPath, 0o755);
}
