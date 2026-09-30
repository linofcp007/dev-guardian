/**
 * `create_fix_pr` driven end to end against a real git repo, a real npm
 * registry and the real scanners: a semgrep fix, applied and re-verified with
 * the project's own registered rules.
 *
 * One of four files split from what was `createFixPr.test.ts` so that vitest
 * runs them in parallel; the harness, and where the time goes, are in
 * `test/helpers/createFixPrHarness.ts`.
 */
import { afterEach, describe, expect, it } from 'vitest';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, chmodSync, existsSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { TOOLS } from '../../src/tools/index.js';
import { rmDirOrDefer } from '../helpers/tempDir.js';
import {
  ctx,
  REGISTRY_BACKED_TIMEOUT_MS,
  repo,
  REQUIRE_SEMGREP,
  SEMGREP_INSTALLED,
  useFixPrRepo,
  worktreeCount,
} from '../helpers/createFixPrHarness.js';

useFixPrRepo();

describe('create_fix_pr', () => {
  // ------------------------------------------------------------------
  // Task 11 (2026-09-25 review), end to end with the REAL Semgrep and only
  // local rules (no registry, metrics off): the project registers its own
  // autofix rule, scan_sast finds a target, and create_fix_pr's dry run
  //   - applies ONLY that rule's autofix (item 4),
  //   - re-verifies with the SAME tool and packs — scan_sast, local_only,
  //     the project's registered rules, which the worktree's own path does
  //     not have (item 2),
  //   - changes nothing outside its worktree: no ref written (a
  //     reference-transaction hook logs every one), no test run in the
  //     user's tree, no scan rows left behind (item 1).
  // ------------------------------------------------------------------

  const FIXABLE_RULE = [
    '  - id: no-eval-fixable',
    '    pattern: eval($X)',
    '    message: eval is dangerous',
    '    languages: [javascript]',
    '    severity: ERROR',
    '    fix: safeEval($X)',
  ];
  const RULE_ON_FIXED_CODE = [
    '  - id: safe-eval-appeared',
    '    pattern: safeEval($X)',
    '    message: safeEval appeared',
    '    languages: [javascript]',
    '    severity: WARNING',
  ];

  /** Commits app.js (one eval) and a package.json whose test ALWAYS fails
   *  after writing a marker into its working directory; registers a rules
   *  file that lives OUTSIDE the repository; seeds the open set with a real
   *  local-only scan_sast. Returns the reference-transaction log path. */
  async function setupLocalRuleRepo(c: ReturnType<typeof ctx>, rules: string[]): Promise<string> {
    writeFileSync(join(repo, 'app.js'), 'eval(userInput);\n');
    writeFileSync(join(repo, 'package.json'), JSON.stringify({
      name: 'x', version: '1.0.0',
      scripts: { test: 'node -e "require(\'fs\').writeFileSync(\'ran-here.txt\',\'x\');process.exit(1)"' },
    }));
    writeFileSync(join(repo, '.gitignore'), '.guardian/\n');
    execFileSync('git', ['-C', repo, 'add', '.']);
    execFileSync('git', ['-C', repo, 'commit', '-q', '-m', 'app']);

    const rulesDir = mkdtempSync(join(tmpdir(), 'fixpr-rules-'));
    extraDirs.push(rulesDir);
    const rulesFile = join(rulesDir, 'house.yml');
    writeFileSync(rulesFile, ['rules:', ...rules, ''].join('\n'));
    const reg = await TOOLS.find((t) => t.name === 'register_custom_rules')?.handler(
      { project_path: repo, paths: [rulesFile] }, c as never,
    );
    expect(reg).toMatchObject({ ok: true, registered: [rulesFile] });

    const sast = await TOOLS.find((t) => t.name === 'scan_sast')?.handler(
      { project_path: repo, local_only: true, force: true }, c as never,
    ) as { ok: boolean; scan_id: string };
    expect(sast.ok).toBe(true);
    expect(c.storage.findings.listByScan(sast.scan_id).map((f) => f.title)).toContain('eval is dangerous');

    const log = join(repo, '.git', 'ref-transactions.log');
    const hook = join(repo, '.git', 'hooks', 'reference-transaction');
    writeFileSync(hook, `#!/bin/sh\necho "$1" >> "${log.replace(/\\/g, '/')}"\ncat >> "${log.replace(/\\/g, '/')}"\n`);
    if (process.platform !== 'win32') chmodSync(hook, 0o755);
    return log;
  }

  const extraDirs: string[] = [];
  afterEach(() => { for (const d of extraDirs.splice(0)) rmDirOrDefer(d); });

  it.skipIf(!REQUIRE_SEMGREP && !SEMGREP_INSTALLED)(
    'Task 11: a dry run applies only the target rule, re-verifies with the same local packs, and changes nothing outside its worktree',
    async () => {
      const c = ctx();
      const log = await setupLocalRuleRepo(c, FIXABLE_RULE);
      const statusBefore = execFileSync('git', ['-C', repo, 'status', '--porcelain'], { encoding: 'utf8' });

      const res = await TOOLS.find((t) => t.name === 'create_fix_pr')?.handler(
        { project_path: repo, sources: ['semgrep'], apply: false }, c as never,
      ) as { ok: true; groups: Array<{
        outcome: string; note: string; commands: string[];
        scan: { passed: boolean; resolved: string[] } | null; tests: { outcome: string } | null;
      }> };

      expect(res.ok).toBe(true);
      const group = res.groups[0];
      expect(group?.outcome, group?.note).toBe('verified_dry_run');
      expect(group?.scan).toMatchObject({ passed: true });
      expect(group?.scan?.resolved).toHaveLength(1);
      // The autofix pass: this rule only, metrics off, never --config auto.
      expect(group?.commands.join('\n')).toContain('--metrics=off');
      expect(group?.commands.join('\n')).toContain('no-eval-fixable from house.yml');
      expect(group?.commands.join('\n')).not.toMatch(/config[= ]auto/);
      // The failing test was compared against a pristine base tree — the
      // marker it writes never appeared in the user's project.
      expect(group?.tests?.outcome).toBe('already_failing');
      expect(existsSync(join(repo, 'ran-here.txt'))).toBe(false);
      // Nothing outside the worktree changed: no ref, no file, no scan row.
      const refs = existsSync(log) ? readFileSync(log, 'utf8') : '';
      expect(refs).not.toContain('refs/heads/');
      expect(execFileSync('git', ['-C', repo, 'status', '--porcelain'], { encoding: 'utf8' })).toBe(statusBefore);
      expect(readFileSync(join(repo, 'app.js'), 'utf8')).toBe('eval(userInput);\n');
      expect(c.storage.scans.listHistory(100).every((s) => s.project_path === repo)).toBe(true);
      expect(worktreeCount()).toBe(1);
    },
    REGISTRY_BACKED_TIMEOUT_MS,
  );

  it.skipIf(!REQUIRE_SEMGREP && !SEMGREP_INSTALLED)(
    "Task 11 item 2: the re-scan runs the project's own registered rules — a rule the fix trips is a new finding, not a pass",
    async () => {
      // The worktree is another path: registration does not follow it. Only
      // a re-scan with the ORIGINAL project's rule configuration runs the
      // second rule, which fires on exactly the code the fix wrote.
      const c = ctx();
      await setupLocalRuleRepo(c, [...FIXABLE_RULE, ...RULE_ON_FIXED_CODE]);

      const res = await TOOLS.find((t) => t.name === 'create_fix_pr')?.handler(
        { project_path: repo, sources: ['semgrep'], apply: false }, c as never,
      ) as { ok: true; groups: Array<{ outcome: string; note: string; scan: { new_findings: Array<{ title: string }> } | null }> };

      const group = res.groups[0];
      expect(group?.outcome, group?.note).toBe('not_verified');
      expect(group?.scan?.new_findings.map((f) => f.title)).toContain('safeEval appeared');
    },
    REGISTRY_BACKED_TIMEOUT_MS,
  );

  it.skipIf(!REQUIRE_SEMGREP && !SEMGREP_INSTALLED)(
    'Task 11 fix round 1 (item 7): a target in a file with uncommitted changes is never verified — excluded and reported',
    async () => {
      // "Before" is the working-tree scan; the fix and its re-scan run on
      // HEAD. A target whose file differs from HEAD would compare two
      // different files and could read "resolved" without being fixed.
      const c = ctx();
      await setupLocalRuleRepo(c, FIXABLE_RULE);
      // Uncommitted: the eval moves down a line and a second one appears.
      writeFileSync(join(repo, 'app.js'), '// local edit\neval(userInput);\neval(other);\n');
      const rescan = await TOOLS.find((t) => t.name === 'scan_sast')?.handler(
        { project_path: repo, local_only: true, force: true }, c as never,
      );
      expect(rescan?.ok).toBe(true);

      const res = await TOOLS.find((t) => t.name === 'create_fix_pr')?.handler(
        { project_path: repo, sources: ['semgrep'], apply: false }, c as never,
      ) as { ok: true; groups: unknown[]; filtered: { by_reason: Record<string, number> }; filtered_reason: string | null };

      expect(res.groups).toEqual([]);
      expect(res.filtered.by_reason['uncommitted_changes']).toBe(2);
      expect(res.filtered_reason).toContain('uncommitted');
      expect(worktreeCount()).toBe(1);
    },
    REGISTRY_BACKED_TIMEOUT_MS,
  );
});
