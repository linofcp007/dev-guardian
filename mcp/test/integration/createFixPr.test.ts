/**
 * `create_fix_pr` driven end to end against a real git repo, a real npm
 * registry and the real scanners. Nothing here is mocked except `gh` (see
 * the stub in `beforeEach`), and that is the point: the tool's whole job is
 * to apply a fix and then PROVE it worked, and a proof against a fake
 * scanner proves nothing.
 *
 * ---- Where the runtime goes, and why the timeouts look the way they do ---
 *
 * This file takes ~2 minutes on an idle machine, ~3.5 under a loaded one,
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
import { describe, expect, it, beforeEach, afterEach } from 'vitest';
import { execFileSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { mkdtempSync, writeFileSync, chmodSync, existsSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { openDatabase } from '../../src/storage/db.js';
import { Storage } from '../../src/storage/index.js';
import { buildPrBody } from '../../src/tools/createFixPr.js';
import { TOOLS } from '../../src/tools/index.js';
import type { FixGroup } from '../../src/fixpr/types.js';
import type { Finding } from '../../src/types.js';
import '../../src/registerAll.js';
import { okResult } from '../helpers/toolResult.js';
import { rmDir } from '../helpers/tempDir.js';
import { isInstalled } from '../helpers/toolchain.js';

// execFileSync (unlike execa/runProcess, which shell out through
// cross-spawn) does not resolve npm's Windows .cmd shim on its own — same
// reason this file already spells out 'gh.cmd' below rather than just 'gh'.
const NPM_BIN = process.platform === 'win32' ? 'npm.cmd' : 'npm';

/** See the module comment for the measurements this number comes from. */
const REGISTRY_BACKED_TIMEOUT_MS = 120_000;

/* ------------------------------------------------------------------ */
/* Toolchain availability — same technique as rulePackFixture.test.ts  */
/* ------------------------------------------------------------------ */

/**
 * Resolved once, at collection time, so `it.skipIf` can report a skip as a
 * skip — this repo's established discipline everywhere else (see
 * `rulePackFixture.test.ts`'s header) and, until now, the one place it was
 * missing.
 *
 * Three tests below need a real, TRIVY-sourced CVE record and not merely a
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
const TRIVY_INSTALLED = await isInstalled('trivy');
const REQUIRE_SEMGREP = process.env['GUARDIAN_REQUIRE_SEMGREP'] === '1';

let repo: string; let binDir: string; let ghLog: string; let originDir: string | null;

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
  process.env['PATH'] = `${binDir}${process.platform === 'win32' ? ';' : ':'}${process.env['PATH'] ?? ''}`;
});

afterEach(() => {
  rmDir(repo);
  rmDir(binDir);
  if (originDir) rmDir(originDir);
});

/**
 * Adds a real BARE repo as `origin` so `git push` inside `openPr` can
 * genuinely succeed — none of the tests above needed this (they stop at
 * verification, or at a push that is EXPECTED to fail for lack of a remote),
 * but proving C1 means inspecting an actual committed diff, which means
 * actually reaching `created`.
 */
function addOriginRemote(): void {
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
function setupLodashRepo(): void {
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
async function seedRealDepsBefore(c: ReturnType<typeof ctx>): Promise<void> {
  const depsAudit = TOOLS.find((t) => t.name === 'deps_audit');
  const res = await depsAudit?.handler({ project_path: repo }, c as never);
  if (!res || !res.ok) {
    throw new Error(`setup: deps_audit against the real repo failed: ${JSON.stringify(res)}`);
  }
}

function ctx() {
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
function seedFinding(c: ReturnType<typeof ctx>, projectPath: string, finding: Finding): void {
  const scanId = randomUUID();
  c.storage.scans.insert({
    scan_id: scanId,
    scan_type: 'sast',
    project_path: projectPath,
    tree_hash: 'deadbeef',
  });
  c.storage.findings.bulkInsert([{ ...finding, scan_id: scanId }]);
  c.storage.scans.finalize({ scan_id: scanId, status: 'completed', tools_run: [], missing_tools: [] });
}

function semgrepFinding(over: Partial<Finding> = {}): Finding {
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

function ghLogContents(): string {
  return existsSync(ghLog) ? readFileSync(ghLog, 'utf8') : '';
}

function worktreeCount(): number {
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
function installGhStubThatReportsAnExistingPr(): void {
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

describe('create_fix_pr', () => {
  // Present in every run so the gate itself is visible; only EXECUTED when
  // the caller has asked for it. Without this, "trivy is missing" and "trivy
  // ran and agreed" are indistinguishable in the suite output — the exact
  // failure mode `rulePackFixture.test.ts`'s header describes, and the reason
  // that discipline exists in this repo at all.
  it.runIf(REQUIRE_SEMGREP)('GUARDIAN_REQUIRE_SEMGREP=1 — this suite must be runnable end to end', () => {
    expect(
      TRIVY_INSTALLED,
      'GUARDIAN_REQUIRE_SEMGREP=1 but trivy is not on PATH, so the three tests that need a ' +
        'real trivy-sourced CVE record (C1/I5, final review I1, final-review.md C1) would ' +
        'have been skipped.',
    ).toBe(true);
  });

  it('is registered', () => {
    expect(TOOLS.find((t) => t.name === 'create_fix_pr')).toBeTruthy();
  });

  it('refuses cleanly outside a git repository', async () => {
    const notRepo = mkdtempSync(join(tmpdir(), 'fixpr-notrepo-'));
    const mod = TOOLS.find((t) => t.name === 'create_fix_pr');
    const res = await mod?.handler({ project_path: notRepo }, ctx() as never);
    expect(res).toMatchObject({ ok: false, error: { code: 'not_a_git_repo' } });
    rmDir(notRepo);
  });

  it('with no findings, reports nothing to do and creates no worktree', async () => {
    const mod = TOOLS.find((t) => t.name === 'create_fix_pr');
    const res = await mod?.handler({ project_path: repo }, ctx() as never);
    expect(res).toMatchObject({ ok: true, groups: [] });
    expect(execFileSync('git', ['-C', repo, 'worktree', 'list'], { encoding: 'utf8' })
      .trim().split('\n')).toHaveLength(1);
  });

  it('apply:false never invokes gh for push or pr create', async () => {
    // The safety story. If this ever regresses, a dry run starts publishing.
    const mod = TOOLS.find((t) => t.name === 'create_fix_pr');
    await mod?.handler({ project_path: repo, apply: false }, ctx() as never);
    const log = existsSync(ghLog) ? readFileSync(ghLog, 'utf8') : '';
    expect(log).not.toMatch(/pr create/);
  });

  it('leaves no worktree behind on any path', async () => {
    const mod = TOOLS.find((t) => t.name === 'create_fix_pr');
    await mod?.handler({ project_path: repo, apply: false }, ctx() as never);
    const list = execFileSync('git', ['-C', repo, 'worktree', 'list'], { encoding: 'utf8' });
    expect(list.trim().split('\n')).toHaveLength(1);
  });

  // ------------------------------------------------------------------
  // Supplementary coverage. The four tests above never select a single
  // group — a bare repo with no seeded findings and no real outdated
  // dependency produces zero candidates every time, so they cannot tell a
  // correct `apply`/worktree-cleanup implementation from a broken one that
  // just happens to never reach the code that would exercise it. Everything
  // below seeds a real finding so at least one FixGroup is actually
  // selected and driven through worktree creation + `applyGroup`.
  //
  // `applyGroup` runs a REAL `semgrep --config auto --autofix --quiet`
  // for a `semgrep`-sourced group — there is no injection point for a fake
  // runner at the tool layer (that exists one level down, in Tasks 4–6's own
  // unit tests). Whether that call actually finds `semgrep` varies by host:
  // it is unreachable from this repo's own Bash-tool shell PATH but IS
  // reachable from a plain Node child process on the machine this suite was
  // developed on (a real, if slow, environment difference — not a mock).
  // Rather than assume either way, these tests assert only what holds
  // regardless of that outcome: exactly one group is selected, the worktree
  // is always cleaned up, and — the property that actually matters — `gh`
  // is never asked to create a pull request. Generous per-test timeouts
  // accommodate a real `--config auto` registry fetch (~3–9s observed).
  // ------------------------------------------------------------------

  it('excludes a source that was not requested', async () => {
    const c = ctx();
    seedFinding(c, repo, semgrepFinding());
    const mod = TOOLS.find((t) => t.name === 'create_fix_pr');
    const res = await mod?.handler({ project_path: repo, sources: ['deps'] }, c as never);
    expect(res).toMatchObject({ ok: true, groups: [], deferred: [] });
  });

  it('defaults severity_min to high, excluding a medium finding until asked for it', async () => {
    const c = ctx();
    seedFinding(c, repo, semgrepFinding({ severity: 'medium' }));
    const mod = TOOLS.find((t) => t.name === 'create_fix_pr');

    // sources: ['semgrep'] on both calls — severity filtering is orthogonal
    // to source filtering (already its own test above) and this keeps both
    // calls from also invoking deps_update_plan for no reason.
    const atDefault = await mod?.handler({ project_path: repo, sources: ['semgrep'] }, c as never);
    expect(atDefault).toMatchObject({ ok: true, groups: [] });

    const atMedium = await mod?.handler(
      { project_path: repo, sources: ['semgrep'], severity_min: 'medium' },
      c as never,
    );
    expect(atMedium).toMatchObject({ ok: true, groups: [{ key: 'semgrep' }] });
  }, REGISTRY_BACKED_TIMEOUT_MS);

  it('drives a real selected group through the worktree and cleans up, whatever the fix outcome', async () => {
    // The strongest form of the "no worktree survives" property: unlike the
    // brief's own zero-groups version of this assertion, a group is
    // GENUINELY selected and processed here. A wrong implementation that
    // forgets the `finally` (e.g. only removes the worktree on the success
    // path) passes the brief's test trivially and fails only this one.
    const c = ctx();
    seedFinding(c, repo, semgrepFinding());
    const mod = TOOLS.find((t) => t.name === 'create_fix_pr');
    const res = await mod?.handler({ project_path: repo, sources: ['semgrep'], apply: false }, c as never);

    expect(res).toMatchObject({ ok: true, applied: false });
    if (!res) throw new Error('create_fix_pr tool not found');
    const groups = okResult<{ groups: unknown[] }>(res).groups;
    expect(groups).toHaveLength(1);
    // pr stays null purely because apply is false — true whether or not the
    // fix itself verified, since the apply gate is checked unconditionally
    // before openPr is ever called.
    expect(groups[0]).toMatchObject({ key: 'semgrep', source: 'semgrep', pr: null });
    // A note explaining what happened is always present — never a silent null.
    expect(typeof (groups[0] as { note: string }).note).toBe('string');
    expect((groups[0] as { note: string }).note.length).toBeGreaterThan(0);

    expect(worktreeCount()).toBe(1);
    // apply is false AND this branch is brand new (first-ever run, no
    // collision), so `gh` is never touched at all — not even the existence
    // check `openPr` would otherwise start with. (`prExists` CAN run on a
    // dry run too, but only when `createWorktree` collides on an
    // already-kept branch — see createFixPr.ts's own module comment, I1 —
    // which cannot happen here.)
    expect(ghLogContents()).toBe('');
  }, REGISTRY_BACKED_TIMEOUT_MS);

  it('never lets gh create a PR with apply:true either, and still cleans up, whatever the fix outcome', async () => {
    // Complements the apply:false test above with the orthogonal gate:
    // even asked to publish, `gh pr create` is reached only after the fix
    // verifies AND (if it does) after a successful push — and this
    // throwaway repo has no `origin` remote, so a push can never actually
    // land. Either way — the fix failing to apply, or verification passing
    // but the push failing for lack of a remote — `gh pr create` must never
    // be invoked. That holds regardless of which of those two this host's
    // `semgrep` resolves to.
    const c = ctx();
    seedFinding(c, repo, semgrepFinding());
    const mod = TOOLS.find((t) => t.name === 'create_fix_pr');
    const res = await mod?.handler({ project_path: repo, sources: ['semgrep'], apply: true }, c as never);

    expect(res).toMatchObject({ ok: true, applied: true });
    if (!res) throw new Error('create_fix_pr tool not found');
    const groups = okResult<{ groups: unknown[] }>(res).groups;
    expect(groups).toHaveLength(1);

    expect(worktreeCount()).toBe(1);
    expect(ghLogContents()).not.toMatch(/pr create/);
  }, REGISTRY_BACKED_TIMEOUT_MS);

  it('refuses cleanly when project_path does not exist at all (a different code path from "exists but is not a git repo")', async () => {
    const mod = TOOLS.find((t) => t.name === 'create_fix_pr');
    const res = await mod?.handler(
      { project_path: join(repo, 'does-not-exist-xyz') },
      ctx() as never,
    );
    expect(res).toMatchObject({ ok: false, error: { code: 'not_a_git_repo' } });
  });

  // ------------------------------------------------------------------
  // task-7-review.md fix round: C1 (the re-scan's own report artifacts
  // committed into the PR), C2 (a dry run leaves the branch behind), I3
  // (the worktree re-scan pollutes the server's global "latest scan" view)
  // and I5 (the coverage check verifies the wrong tool for non-trivy deps
  // targets). All four need a group that reaches a REAL, non-empty file
  // diff — the semgrep fixture above never does (no reliable autofix rule
  // found), so these use a REAL, network-backed npm dependency bump
  // instead (see setupLodashRepo's own comment).
  // ------------------------------------------------------------------

  it('C2: a dry run leaves no local branch behind either, not just no worktree', async () => {
    const c = ctx();
    setupLodashRepo();
    await seedRealDepsBefore(c);
    const mod = TOOLS.find((t) => t.name === 'create_fix_pr');
    const res = await mod?.handler(
      { project_path: repo, sources: ['deps'], apply: false },
      c as never,
    );
    expect(res).toMatchObject({ ok: true, applied: false });
    if (!res) throw new Error('create_fix_pr tool not found');
    const groups = okResult<{ groups: { branch: string }[] }>(res).groups;
    expect(groups).toHaveLength(1);

    // Design §6, literally: "not a branch". Checked against the real repo's
    // OWN refs, not the tool's own report of what it did.
    const branches = execFileSync('git', ['-C', repo, 'branch', '--list'], { encoding: 'utf8' });
    expect(branches).not.toContain(groups[0]?.branch);
    expect(worktreeCount()).toBe(1);
  }, REGISTRY_BACKED_TIMEOUT_MS);

  it.skipIf(!TRIVY_INSTALLED)('C1/I5: opens a real pull request whose diff excludes dev-guardian\'s own scan report', async () => {
    const c = ctx();
    setupLodashRepo();
    addOriginRemote();
    await seedRealDepsBefore(c);
    const mod = TOOLS.find((t) => t.name === 'create_fix_pr');
    const res = await mod?.handler(
      { project_path: repo, sources: ['deps'], apply: true },
      c as never,
    ) as { ok: true; groups: Array<{
      outcome: string; pr: { status: string; url: string | null } | null; branch: string;
    }> };

    expect(res.ok).toBe(true);
    expect(res.groups).toHaveLength(1);
    const group = res.groups[0];
    // The real point of this fixture: verification genuinely passed (the
    // CVE is genuinely gone, nothing new appeared) and a PR was genuinely
    // opened — not a status this test assumes, one it measures. Reaching
    // this also confirms I5 did not spuriously block a target that WAS
    // genuinely re-checked (trivy did run) — I5's own dedicated test below
    // covers the negative (wpscan) side.
    expect(group).toMatchObject({ outcome: 'pr_created', pr: { status: 'created' } });
    // A real gh pr create call happened — the stub's own `echo %*`
    // re-quotes each argv token (`"pr" "create" …`), and its capture of a
    // multi-line --body argument truncates at the first embedded newline (a
    // real limitation of that mechanism) — see buildPrBody's own test for
    // why the verbatim not_run phrase (M7) is verified there instead.
    expect(ghLogContents()).toMatch(/"pr"\s+"create"/);

    // C1: the pushed commit's diff must be the real fix — never
    // dev-guardian's own .guardian/reports/** re-scan artifacts, whether
    // alongside the real change or (the actual defect) instead of it.
    const changed = execFileSync(
      'git',
      ['-C', originDir as string, 'diff-tree', '--no-commit-id', '--name-only', '-r', group?.branch ?? ''],
      { encoding: 'utf8' },
    ).trim().split('\n').filter((l) => l.length > 0);
    expect(changed).toContain('package.json');
    expect(changed.some((f) => f.startsWith('.guardian'))).toBe(false);
  }, REGISTRY_BACKED_TIMEOUT_MS);

  it.skipIf(!TRIVY_INSTALLED)('final review I1: a repeat run after a PR was created reports pr_exists, not worktree_failed', async () => {
    // Same fixture as C1/I5 above, continued past `pr_created`: KEEPS_BRANCH
    // deliberately leaves the branch behind once a PR exists — correctly, it
    // is what the PR points at — so a repeat run's `createWorktree` collides
    // on that same deterministic branch name. Before this fix, that collision
    // was reported verbatim as `worktree_failed` (a raw git-internals
    // message) because `prExists` was never consulted; `pr.ts`'s own
    // `--state all` idempotency search — built for exactly this moment —
    // was unreachable for the entire life of the open PR.
    const c = ctx();
    setupLodashRepo();
    addOriginRemote();
    await seedRealDepsBefore(c);
    const mod = TOOLS.find((t) => t.name === 'create_fix_pr');
    type Result = { ok: true; groups: Array<{
      outcome: string; branch: string; note: string;
      pr: { status: string; url: string | null } | null;
    }> };

    // RUN 1 — apply:true, genuinely reaches a created PR.
    const first = await mod?.handler(
      { project_path: repo, sources: ['deps'], apply: true },
      c as never,
    ) as Result;
    expect(first.groups[0]).toMatchObject({ outcome: 'pr_created', pr: { status: 'created' } });
    const branch = first.groups[0]?.branch as string;
    expect(
      execFileSync('git', ['-C', repo, 'branch', '--list'], { encoding: 'utf8' }),
    ).toContain(branch);

    // From here on `gh pr list` must report a hit — what a real GitHub
    // remote would now genuinely show, which the beforeEach's own stateless
    // stub (always empty stdout) cannot simulate.
    installGhStubThatReportsAnExistingPr();

    // RUN 2 — apply:true again, same findings, therefore the SAME
    // deterministic branch (design §5).
    const second = await mod?.handler(
      { project_path: repo, sources: ['deps'], apply: true },
      c as never,
    ) as Result;
    expect(second.groups[0]).toMatchObject({
      outcome: 'pr_exists', branch, pr: { status: 'exists', url: null },
    });
    expect(second.groups[0]?.note.toLowerCase()).toContain('already exists');

    // RUN 3 — the SAFE DEFAULT, apply:false. Design §6's `apply` boundary is
    // stated in terms of what leaves the machine (commit/push/`gh pr
    // create`), not in terms of `gh` being touched at all, so a cautious
    // preview must be told the truth too, not just an `apply:true` retry.
    const third = await mod?.handler(
      { project_path: repo, sources: ['deps'], apply: false },
      c as never,
    ) as Result;
    expect(third.groups[0]).toMatchObject({
      outcome: 'pr_exists', branch, pr: { status: 'exists', url: null },
    });

    // Exactly one PR was ever created (run 1) — runs 2 and 3 both recognised
    // the existing one instead of attempting a duplicate (the stub fails
    // loudly on a second `pr create`, so a wrong implementation would show up
    // here as a thrown/rejected outcome, not a silent pass).
    expect(ghLogContents().match(/"pr"\s+"create"/g) ?? []).toHaveLength(1);
    // ...and `prExists` really was reached on both repeat runs — run 1's own
    // `openPr` existence check, plus one per repeat run: the review's own
    // gh.log evidence, inverted.
    expect(ghLogContents().match(/"pr"\s+"list"/g) ?? []).toHaveLength(3);

    // No worktree survives any of the three runs, and the PR's own branch is
    // still exactly where it was — neither repeat run touched it (nothing
    // KEEPS_BRANCH would want deleted, and this code path never reaches the
    // `finally` that deletes it — no worktree was ever created on it).
    expect(worktreeCount()).toBe(1);
    expect(
      execFileSync('git', ['-C', repo, 'branch', '--list'], { encoding: 'utf8' }),
    ).toContain(branch);
  }, REGISTRY_BACKED_TIMEOUT_MS);

  it('I3: does not repoint the server\'s global "latest scan" view at the verification worktree', async () => {
    const c = ctx();
    setupLodashRepo();
    await seedRealDepsBefore(c);

    const beforeLatest = c.storage.scans.getLatest();
    const beforeOpenCount = c.storage.findings.listOpen().length;
    expect(beforeLatest?.project_path).toBe(repo);
    expect(beforeOpenCount).toBeGreaterThan(0);

    const mod = TOOLS.find((t) => t.name === 'create_fix_pr');
    // apply:false on purpose — I3's own defect is not gated by apply at all
    // (the re-scan runs regardless), so the SAFE DEFAULT must not leak this.
    await mod?.handler({ project_path: repo, sources: ['deps'], apply: false }, c as never);

    const afterLatest = c.storage.scans.getLatest();
    const afterOpenCount = c.storage.findings.listOpen().length;
    // Unchanged: still the real project, still the real (pre-fix) findings —
    // not the worktree, and not zero.
    expect(afterLatest?.scan_id).toBe(beforeLatest?.scan_id);
    expect(afterLatest?.project_path).toBe(repo);
    expect(afterOpenCount).toBe(beforeOpenCount);
  }, REGISTRY_BACKED_TIMEOUT_MS);

  it.skipIf(!TRIVY_INSTALLED)('final-review.md C1: a dry run does not change what risk_score reports either — not just getLatest/listOpen', async () => {
    // task-7-review.md I3 (the test directly above) fixed getLatest() and
    // listOpen(), both queried by scans.getLatestStmt / findings.listOpen*
    // Stmt. risk_score does NOT read getLatest() for its CVE source, though:
    // it reads listHistory(50).find(s => ['deps','security_full'].includes
    // (s.scan_type)) (riskScore.ts#findLatestOfType), and listHistoryStmt
    // shipped with no WHERE clause at all — I3's fix never touched it. So the
    // exact same worktree re-scan I3 already proves does not leak into
    // getLatest()/listOpen() could still win risk_score's OWN CVE lookup.
    // Measured, before this fix, on a real project: risk_score's score fell
    // from 44 (high) to 31 (medium) and active_cves from 5 to 0, after
    // nothing but a dry run — and it did not self-correct, because the
    // contaminating row is never deleted.
    //
    // Asserted the way design §10 actually states the guarantee — "Nothing
    // the tool does in dry-run mode may change what … risk_score report[s]"
    // names risk_score itself, so this calls the real tool and diffs its
    // whole output, rather than re-checking the two repo methods I3 already
    // covers (which would stay green even with listHistoryStmt still broken —
    // that is exactly how the original gap shipped unnoticed).
    const c = ctx();
    setupLodashRepo();
    await seedRealDepsBefore(c);

    const riskScoreTool = TOOLS.find((t) => t.name === 'risk_score');
    const beforeRaw = await riskScoreTool?.handler({}, c as never);
    if (!beforeRaw) throw new Error('risk_score tool not found');
    const before = okResult<{ components: { cves: { active_cves: number } } }>(beforeRaw);
    // Not vacuous: there must be a real, non-zero signal at risk of being
    // silently zeroed before asserting that nothing zeroes it.
    expect(before.components.cves.active_cves).toBeGreaterThan(0);

    const mod = TOOLS.find((t) => t.name === 'create_fix_pr');
    await mod?.handler({ project_path: repo, sources: ['deps'], apply: false }, c as never);

    const after = await riskScoreTool?.handler({}, c as never);
    expect(after).toEqual(before);
  }, REGISTRY_BACKED_TIMEOUT_MS);

  it('I5: a deps target whose scanner deps_audit never covers at all (wpscan) is never judged resolved just because trivy ran fine', async () => {
    // The review's own "worse than reported" case: deps_audit does not
    // attempt wpscan at all, so a wpscan-sourced target must never be
    // trusted as resolved merely because trivy (a DIFFERENT scanner)
    // completed. mentionsPackage (candidates.ts) pairs by package-name text
    // match only, not by ecosystem, so a wpscan-tool finding that happens to
    // mention "lodash" pairs with the same real npm upgrade step the other
    // tests here use — deliberately, to exercise this without needing a
    // real WordPress install.
    const c = ctx();
    setupLodashRepo();
    const scanId = randomUUID();
    c.storage.scans.insert({ scan_id: scanId, scan_type: 'wp_vuln_check', project_path: repo, tree_hash: 'deadbeef' });
    c.storage.findings.bulkInsert([{
      fingerprint: 'fp-wpscan-lodash',
      tool: 'wpscan',
      severity: 'high',
      category: 'security',
      title: 'lodash vulnerable plugin bundle',
      fix_available: true,
      scan_id: scanId,
    }]);
    c.storage.scans.finalize({ scan_id: scanId, status: 'completed', tools_run: [], missing_tools: [] });

    const mod = TOOLS.find((t) => t.name === 'create_fix_pr');
    const res = await mod?.handler(
      { project_path: repo, sources: ['deps'], apply: false },
      c as never,
    ) as { ok: true; groups: Array<{ outcome: string; scan: unknown; note: string }> };

    expect(res.ok).toBe(true);
    expect(res.groups).toHaveLength(1);
    // Never verified, and specifically NOT via a passing scan differential —
    // the wrong implementation this test guards against reports
    // outcome: 'verified_dry_run' (or worse, on a real run, opens a PR)
    // because it only ever checked whether trivy ran.
    expect(res.groups[0]).toMatchObject({ outcome: 'verification_failed', scan: null });
    expect(res.groups[0]?.note).toContain('wpscan');
  }, REGISTRY_BACKED_TIMEOUT_MS);
});

describe('buildPrBody (task-7-review.md M7)', () => {
  // Direct, fast, deterministic — see buildPrBody's own doc comment for why
  // this is tested here rather than only through a real `gh pr create` call:
  // the stub `gh.cmd` this file's own tests use truncates a multi-line
  // --body argument at its first embedded newline, so the integration test
  // above can prove `gh pr create` was reached but not what its body said.

  const group: FixGroup = {
    source: 'deps',
    key: 'npm',
    severity: 'high',
    hash: 'abc123def456',
    candidates: [{
      source: 'deps', fingerprints: ['a'.repeat(64)], severity: 'high',
      command: 'npm install lodash@4.18.1', label: 'lodash 4.17.20 -> 4.18.1',
    }],
  };
  const finding: Finding = {
    fingerprint: 'a'.repeat(64), tool: 'trivy', rule_id: 'CVE-2021-23337',
    severity: 'high', category: 'security', title: 'command injection via template',
    file_path: 'package-lock.json', fix_available: true,
  };

  it('states the required phrase VERBATIM when the test outcome is not_run', () => {
    const body = buildPrBody({
      group, findings: [finding], commands: ['npm install lodash@4.18.1'],
      scan: { passed: true, resolved: [finding.fingerprint], still_present: [], new_findings: [] },
      tests: { outcome: 'not_run', command: null, origin: null, output_head: null },
    });
    // Character-for-character, diffed against the brief's own quoted text.
    expect(body).toContain('behaviour was not verified: this project declares no test command');
  });

  it('states the findings covered, the exact commands run, and the scan differential counts', () => {
    const body = buildPrBody({
      group, findings: [finding], commands: ['npm install lodash@4.18.1'],
      scan: { passed: true, resolved: [finding.fingerprint], still_present: [],
        new_findings: [{ fingerprint: 'b'.repeat(64), severity: 'high', title: 'new CVE' }] },
      tests: { outcome: 'passed', command: 'npm test --silent', origin: 'package.json scripts.test', output_head: null },
    });
    expect(body).toContain('command injection via template');
    expect(body).toContain('npm install lodash@4.18.1');
    expect(body).toContain('Resolved: 1');
    expect(body).toContain('New findings introduced: 1');
    expect(body).toContain('new CVE');
    expect(body).toContain('Passed: `npm test --silent`');
  });
});
