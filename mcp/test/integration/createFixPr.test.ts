/**
 * `create_fix_pr` driven end to end against a real git repo, a real npm
 * registry and the real scanners: selection, refusals, the filtered breakdown,
 * the plan runners and the PR body.
 *
 * One of four files split from what was `createFixPr.test.ts` so that vitest
 * runs them in parallel; the harness, and where the time goes, are in
 * `test/helpers/createFixPrHarness.ts`.
 */
import { describe, expect, it } from 'vitest';
import { execFileSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { mkdtempSync, writeFileSync, existsSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { buildPrBody } from '../../src/tools/createFixPr.js';
import { TOOLS } from '../../src/tools/index.js';
import type { FixGroup } from '../../src/fixpr/types.js';
import type { Finding } from '../../src/types.js';
import { okResult } from '../helpers/toolResult.js';
import { rmDirOrDefer } from '../helpers/tempDir.js';
import {
  ctx,
  DOTNET_INSTALLED,
  ghLog,
  ghLogContents,
  REGISTRY_BACKED_TIMEOUT_MS,
  repo,
  seedFinding,
  seedFindings,
  semgrepFinding,
  setupLodashRepo,
  useFixPrRepo,
  worktreeCount,
} from '../helpers/createFixPrHarness.js';

useFixPrRepo();

describe('create_fix_pr', () => {
  it('is registered', () => {
    expect(TOOLS.find((t) => t.name === 'create_fix_pr')).toBeTruthy();
  });

  it('refuses cleanly outside a git repository', async () => {
    const notRepo = mkdtempSync(join(tmpdir(), 'fixpr-notrepo-'));
    const mod = TOOLS.find((t) => t.name === 'create_fix_pr');
    const res = await mod?.handler({ project_path: notRepo }, ctx() as never);
    expect(res).toMatchObject({ ok: false, error: { code: 'not_a_git_repo' } });
    rmDirOrDefer(notRepo);
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

  it('says what the severity floor filtered out, instead of returning an unexplained empty result', async () => {
    // The defect this closes: `severity_min` defaults to `high`, the 1.9.0
    // audit took the ERROR tier (the only tier that maps to `high`) from 20
    // rules of 34 to 4 of 58, and a default run on a project whose findings
    // are all `medium` came back with `groups: []` and nothing at all saying
    // 40 findings had been filtered. Selects no group, so no worktree, no
    // scanner and no registry round-trip — this is a report about the
    // findings, produced before any of that would have run.
    const c = ctx();
    seedFindings(c, repo, [
      ...Array.from({ length: 3 }, (_unused, i) =>
        semgrepFinding({ severity: 'medium', fingerprint: `fp-med-${i}` }),
      ),
      semgrepFinding({ severity: 'low', fingerprint: 'fp-low-1' }),
    ]);
    const mod = TOOLS.find((t) => t.name === 'create_fix_pr');

    const res = await mod?.handler({ project_path: repo, sources: ['semgrep'] }, c as never);
    expect(res).toMatchObject({
      ok: true,
      groups: [],
      filtered: {
        considered: 4,
        candidates: 0,
        excluded: 4,
        by_reason: { below_severity_min: 4, no_fix_available: 0, no_fix_source: 0 },
        below_severity_min: { suggested_severity_min: 'medium', recovered_by_suggestion: 3 },
      },
    });
    if (!res) throw new Error('create_fix_pr tool not found');
    const reason = okResult<{ filtered_reason: string | null }>(res).filtered_reason;
    expect(reason).toBeTypeOf('string');
    expect(String(reason)).toContain('3 medium, 1 low');
    expect(String(reason)).toContain('severity_min "medium"');
  });

  it('reports the breakdown on a partial run too, not only an empty one', async () => {
    // A run that acts on 1 of 3 is nearly as opaque as one that acts on 0.
    const c = ctx();
    seedFindings(c, repo, [
      semgrepFinding({ fingerprint: 'fp-high-1' }),
      semgrepFinding({ severity: 'medium', fingerprint: 'fp-med-a' }),
      semgrepFinding({ fix_available: false, fingerprint: 'fp-nofix-a' }),
    ]);
    const mod = TOOLS.find((t) => t.name === 'create_fix_pr');

    const res = await mod?.handler({ project_path: repo, sources: ['semgrep'] }, c as never);
    if (!res) throw new Error('create_fix_pr tool not found');
    const payload = okResult<{ filtered: unknown; filtered_reason: string | null }>(res);
    expect(payload.filtered).toMatchObject({
      considered: 3,
      candidates: 1,
      excluded: 2,
      by_reason: { below_severity_min: 1, no_fix_available: 1, no_fix_source: 0 },
    });
    expect(String(payload.filtered_reason)).toContain('no scanner-produced fix');
  }, REGISTRY_BACKED_TIMEOUT_MS);

  it('accounts for every finding even when nothing was excluded', async () => {
    const c = ctx();
    const mod = TOOLS.find((t) => t.name === 'create_fix_pr');
    const res = await mod?.handler({ project_path: repo, sources: ['semgrep'] }, c as never);
    if (!res) throw new Error('create_fix_pr tool not found');
    // filtered_reason is null iff nothing was excluded — the same contract
    // deferred_reason already keeps with deferred.
    const payload = okResult<{ filtered: unknown; filtered_reason: string | null }>(res);
    expect(payload.filtered_reason).toBeNull();
    expect(payload.filtered).toMatchObject({ considered: 0, candidates: 0, excluded: 0 });
  });

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

  it('I5 / Task 11 items 2-3: a WPScan finding that merely MENTIONS an npm package never becomes a candidate at all', async () => {
    // The review's own "worse than reported" case: deps_audit does not
    // attempt wpscan at all, so a wpscan-sourced target must never be
    // trusted as resolved merely because trivy (a DIFFERENT scanner)
    // completed. It used to pair by text ("lodash" in its title) with the
    // real npm lodash step and reach verification; pairing is structural now
    // (a WPScan component has no ecosystem this tool upgrades), and nothing
    // can re-scan it with the scanner that found it — so it is accounted for
    // in `filtered`, never processed.
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
    ) as { ok: true; groups: unknown[]; filtered: { by_reason: { no_fix_source: number } } };

    expect(res.ok).toBe(true);
    expect(res.groups).toEqual([]);
    expect(res.filtered.by_reason.no_fix_source).toBe(1);
  }, REGISTRY_BACKED_TIMEOUT_MS);

  it('Task 11 fix round 2: a plan runner that failed is reported, and its findings are never labelled "no_fix_source"', async () => {
    const c = ctx();
    const scanId = randomUUID();
    c.storage.scans.insert({ scan_id: scanId, scan_type: 'deps_audit', project_path: repo, tree_hash: 'h' });
    c.storage.findings.bulkInsert([
      {
        scan_id: scanId, fingerprint: 'fp-composer', tool: 'trivy', rule_id: 'CVE-2099-1', severity: 'high',
        category: 'security', subcategory: 'cve', title: 'psr/log vulnerable', fix_available: true,
        file_path: 'composer.lock', snippet: 'psr/log@1.0.0->1.1.0',
      },
      {
        scan_id: scanId, fingerprint: 'fp-npm', tool: 'trivy', rule_id: 'CVE-2099-2', severity: 'high',
        category: 'security', subcategory: 'cve', title: 'left-pad vulnerable', fix_available: true,
        file_path: 'package-lock.json', snippet: 'left-pad@1.0.0->1.1.0',
      },
    ]);
    c.storage.scans.finalize({ scan_id: scanId, status: 'completed', tools_run: [], missing_tools: [] });
    const failure = { ecosystem: 'composer', code: 'exit_1', reason: '`composer outdated --locked` exited 1' };
    const planTool = TOOLS.find((t) => t.name === 'deps_update_plan');
    if (planTool === undefined) throw new Error('deps_update_plan not registered');
    const original = planTool.handler;
    planTool.handler = async () => ({ ok: true, plan: [], runner_failures: [failure] });
    try {
      const res = await TOOLS.find((t) => t.name === 'create_fix_pr')?.handler(
        { project_path: repo, sources: ['deps'] }, c as never,
      ) as { ok: true; deps_plan_runner_failures?: unknown[]; filtered: { by_reason: Record<string, number> }; filtered_reason: string };
      expect(res.deps_plan_runner_failures).toEqual([failure]);
      // The composer finding: its runner failed. The npm one: planned fine,
      // no step for it — that one really has no fix source.
      expect(res.filtered.by_reason).toMatchObject({ upgrade_plan_failed: 1, no_fix_source: 1 });
      expect(res.filtered_reason).toContain('upgrade plan could not be computed');
    } finally {
      planTool.handler = original;
    }
  });

  it('Task 24 item 5: KEV, then EPSS, decide which group the cap keeps and which fix of a group is applied first', async () => {
    // Two ecosystems, every finding `high`: severity alone ties, and the old
    // order (the groups' keys) attempted composer and deferred npm. npm's
    // lodash CVE is CISA KEV-listed, so npm's group goes first; inside it,
    // lodash's upgrade is applied before left-pad's. The upgrade commands name
    // a binary that does not exist, so each attempt stops at its first
    // command — which is exactly what `commands` then shows.
    const c = ctx();
    const scanId = randomUUID();
    c.storage.scans.insert({ scan_id: scanId, scan_type: 'deps_audit', project_path: repo, tree_hash: 'h' });
    const dep = (fingerprint: string, cve: string, pkg: string, file: string) => ({
      scan_id: scanId, fingerprint, tool: 'trivy', rule_id: cve, severity: 'high' as const,
      category: 'security' as const, subcategory: 'cve', title: `${pkg} vulnerable`, fix_available: true,
      file_path: file, snippet: `${pkg}@1.0.0->1.1.0`,
    });
    c.storage.findings.bulkInsert([
      dep('a'.repeat(64), 'CVE-2099-11', 'psr/log', 'composer.lock'),
      dep('b'.repeat(64), 'CVE-2099-21', 'left-pad', 'package-lock.json'),
      dep('c'.repeat(64), 'CVE-2099-22', 'lodash', 'package-lock.json'),
    ]);
    c.storage.scans.finalize({ scan_id: scanId, status: 'completed', tools_run: [{ name: 'trivy', status: 'ok' }], missing_tools: [] });
    // Fresh cached intel: served without a network call (the suite runs with GUARDIAN_OFFLINE=1).
    const now = new Date().toISOString();
    c.storage.cveIntel.upsertMany([
      { cve_id: 'CVE-2099-11', kev: false, epss_score: 0.3, fetched_at: now },
      { cve_id: 'CVE-2099-21', kev: false, epss_score: 0.1, fetched_at: now },
      { cve_id: 'CVE-2099-22', kev: true, epss_score: 0.2, fetched_at: now },
    ]);
    const missing = 'guardian-no-such-package-manager';
    const planStep = (ecosystem: string, pkg: string) => ({
      package_name: pkg, installed_version: '1.0.0', latest_version: '1.1.0', classification: 'security',
      ecosystem, upgrade_command: `${missing} upgrade ${pkg}`,
    });
    const planTool = TOOLS.find((t) => t.name === 'deps_update_plan');
    if (planTool === undefined) throw new Error('deps_update_plan not registered');
    const original = planTool.handler;
    planTool.handler = async () => ({
      ok: true,
      plan: [planStep('composer', 'psr/log'), planStep('npm', 'left-pad'), planStep('npm', 'lodash')],
      runner_failures: [],
    });
    try {
      const res = await TOOLS.find((t) => t.name === 'create_fix_pr')?.handler(
        { project_path: repo, sources: ['deps'], max_prs: 1 }, c as never,
      ) as { ok: true; groups: Array<{ key: string; outcome: string; commands: string[] }>; deferred: Array<{ key: string }> };
      expect(res.groups.map((g) => g.key)).toEqual(['npm']);
      expect(res.deferred.map((g) => g.key)).toEqual(['composer']);
      expect(res.groups[0]?.outcome).toBe('apply_failed');
      expect(res.groups[0]?.commands).toEqual([`${missing} upgrade lodash`]);
      expect(worktreeCount()).toBe(1);
    } finally {
      planTool.handler = original;
    }
  }, REGISTRY_BACKED_TIMEOUT_MS);

  it.skipIf(!DOTNET_INSTALLED)(
    'Task 11 fix round 1 (item 1): a dry run never runs deps_update_plan\'s dotnet restore in the user\'s project',
    async () => {
      // deps_update_plan's .NET branch runs `dotnet restore` where it is
      // pointed: obj/ appeared in the user's project on every dry run.
      writeFileSync(
        join(repo, 'App.csproj'),
        '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net10.0</TargetFramework></PropertyGroup></Project>\n',
      );
      execFileSync('git', ['-C', repo, 'add', '.']);
      execFileSync('git', ['-C', repo, 'commit', '-q', '-m', 'dotnet']);
      const c = ctx();
      const scanId = randomUUID();
      c.storage.scans.insert({ scan_id: scanId, scan_type: 'deps_audit', project_path: repo, tree_hash: 'h' });
      c.storage.findings.bulkInsert([{
        scan_id: scanId, fingerprint: 'fp-nuget', tool: 'dotnet-list-package', rule_id: 'GHSA-5crp-9r3c-p9vr',
        severity: 'high', category: 'security', subcategory: 'dependency', title: 'Newtonsoft.Json vulnerable',
        file_path: 'App.csproj', snippet: 'Newtonsoft.Json@12.0.1', fix_available: true,
      }]);
      c.storage.scans.finalize({ scan_id: scanId, status: 'completed', tools_run: [], missing_tools: [] });

      const res = await TOOLS.find((t) => t.name === 'create_fix_pr')?.handler(
        { project_path: repo, sources: ['deps'], apply: false }, c as never,
      );
      expect(res?.ok).toBe(true);
      expect(existsSync(join(repo, 'obj'))).toBe(false);
      expect(execFileSync('git', ['-C', repo, 'status', '--porcelain'], { encoding: 'utf8' })).toBe('');
      expect(worktreeCount()).toBe(1);
    },
    REGISTRY_BACKED_TIMEOUT_MS,
  );
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
