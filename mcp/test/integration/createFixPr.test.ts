import { describe, expect, it, beforeEach, afterEach } from 'vitest';
import { execFileSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync, chmodSync, existsSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { openDatabase } from '../../src/storage/db.js';
import { Storage } from '../../src/storage/index.js';
import { buildPrBody } from '../../src/tools/createFixPr.js';
import { TOOLS } from '../../src/tools/index.js';
import type { FixGroup } from '../../src/fixpr/types.js';
import type { Finding } from '../../src/types.js';
import '../../src/registerAll.js';

// execFileSync (unlike execa/runProcess, which shell out through
// cross-spawn) does not resolve npm's Windows .cmd shim on its own — same
// reason this file already spells out 'gh.cmd' below rather than just 'gh'.
const NPM_BIN = process.platform === 'win32' ? 'npm.cmd' : 'npm';

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
  rmSync(repo, { recursive: true, force: true });
  rmSync(binDir, { recursive: true, force: true });
  if (originDir) rmSync(originDir, { recursive: true, force: true });
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
  const { db } = openDatabase({ inMemory: true });
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

describe('create_fix_pr', () => {
  it('is registered', () => {
    expect(TOOLS.find((t) => t.name === 'create_fix_pr')).toBeTruthy();
  });

  it('refuses cleanly outside a git repository', async () => {
    const notRepo = mkdtempSync(join(tmpdir(), 'fixpr-notrepo-'));
    const mod = TOOLS.find((t) => t.name === 'create_fix_pr');
    const res = await mod?.handler({ project_path: notRepo }, ctx() as never);
    expect(res).toMatchObject({ ok: false, error: { code: 'not_a_git_repo' } });
    rmSync(notRepo, { recursive: true, force: true });
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
  }, 45_000);

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
    const groups = (res as { groups: unknown[] }).groups;
    expect(groups).toHaveLength(1);
    // pr stays null purely because apply is false — true whether or not the
    // fix itself verified, since the apply gate is checked unconditionally
    // before openPr is ever called.
    expect(groups[0]).toMatchObject({ key: 'semgrep', source: 'semgrep', pr: null });
    // A note explaining what happened is always present — never a silent null.
    expect(typeof (groups[0] as { note: string }).note).toBe('string');
    expect((groups[0] as { note: string }).note.length).toBeGreaterThan(0);

    expect(worktreeCount()).toBe(1);
    // apply is false, so `gh` is never touched at all — not even the
    // existence check `openPr` would otherwise start with.
    expect(ghLogContents()).toBe('');
  }, 45_000);

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
    const groups = (res as { groups: unknown[] }).groups;
    expect(groups).toHaveLength(1);

    expect(worktreeCount()).toBe(1);
    expect(ghLogContents()).not.toMatch(/pr create/);
  }, 45_000);

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
    const groups = (res as { groups: { branch: string }[] }).groups;
    expect(groups).toHaveLength(1);

    // Design §6, literally: "not a branch". Checked against the real repo's
    // OWN refs, not the tool's own report of what it did.
    const branches = execFileSync('git', ['-C', repo, 'branch', '--list'], { encoding: 'utf8' });
    expect(branches).not.toContain(groups[0]?.branch);
    expect(worktreeCount()).toBe(1);
  }, 30_000);

  it('C1/I5: opens a real pull request whose diff excludes dev-guardian\'s own scan report', async () => {
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
  }, 30_000);

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
  }, 30_000);

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
  }, 30_000);
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
