import { describe, expect, it, beforeEach, afterEach } from 'vitest';
import { execFileSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync, chmodSync, existsSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { openDatabase } from '../../src/storage/db.js';
import { Storage } from '../../src/storage/index.js';
import { TOOLS } from '../../src/tools/index.js';
import type { Finding } from '../../src/types.js';
import '../../src/registerAll.js';

let repo: string; let binDir: string; let ghLog: string;

beforeEach(() => {
  repo = mkdtempSync(join(tmpdir(), 'fixpr-tool-'));
  execFileSync('git', ['init', '-q', '-b', 'main', repo]);
  execFileSync('git', ['-C', repo, 'config', 'user.email', 't@example.com']);
  execFileSync('git', ['-C', repo, 'config', 'user.name', 'T']);
  writeFileSync(join(repo, 'package.json'), JSON.stringify({ name: 'x', version: '1.0.0' }));
  execFileSync('git', ['-C', repo, 'add', '.']);
  execFileSync('git', ['-C', repo, 'commit', '-q', '-m', 'first']);

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
});

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
});
