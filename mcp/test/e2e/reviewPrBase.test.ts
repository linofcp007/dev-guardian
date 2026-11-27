/**
 * `review_pr`'s merge-base comparison (3.18.0, DG-12) end to end, with REAL
 * Semgrep (`local_only`, a one-rule `.semgrep.yml`) on a real branch: each
 * Semgrep finding of the head judged against a Semgrep run over the same
 * files at the merge base — with head checked out, and from a checkout of a
 * head that is not (two temporary trees: each side's rule ids from its own
 * working directory). SKIPPED without Semgrep on PATH;
 * `GUARDIAN_REQUIRE_SEMGREP=1` turns that into a failure.
 */

import { execa } from 'execa';
import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { PluginContext } from '../../src/context.js';
import { GuardianDatabase as Database } from '../../src/storage/db.js';
import { runMigrations } from '../../src/storage/migrations/runner.js';
import { Storage } from '../../src/storage/index.js';
import { TOOLS } from '../../src/tools/index.js';
import { resetScannerCache } from '../../src/tools/scanHelpers.js';
import type { ToolRun } from '../../src/types.js';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';
import { isInstalled } from '../helpers/toolchain.js';

afterAll(cleanupTempDirs);
beforeAll(async () => {
  await import('../../src/tools/reviewPr.js');
  resetScannerCache();
});

const SLOW = 300_000;
const SEMGREP_INSTALLED = await isInstalled('semgrep');
const REQUIRE_SEMGREP = process.env['GUARDIAN_REQUIRE_SEMGREP'] === '1';

const RULES = `rules:
  - id: fixture-exec
    languages: [javascript]
    severity: ERROR
    message: exec of a command line
    pattern: exec(...)
`;

const lines = (...l: string[]): string => `${l.join('\n')}\n`;

interface Introduced {
  compared: boolean;
  reason?: string;
  counts?: { introduced: number; preexisting: number; unknown: number; not_compared: number };
  preexisting?: Array<{ file_path?: string; line_start?: number }>;
}

async function git(cwd: string, ...args: string[]): Promise<string> {
  return (await execa('git', ['-c', 'core.autocrlf=false', ...args], { cwd })).stdout;
}

function write(dir: string, rel: string, content: string): void {
  const abs = join(dir, rel);
  mkdirSync(join(abs, '..'), { recursive: true });
  writeFileSync(abs, content);
}

/** Every file the merge-base run's reports say Semgrep scanned (`<report dir>/base/`). */
function baseScanned(reportPaths: readonly string[]): string[] {
  const dir = join(reportPaths[0] ?? '', 'base');
  if (!existsSync(dir)) return [];
  const scanned: string[] = [];
  for (const name of readdirSync(dir)) {
    if (!name.endsWith('.json')) continue;
    const doc = JSON.parse(readFileSync(join(dir, name), 'utf8')) as { paths?: { scanned?: string[] } };
    scanned.push(...(doc.paths?.scanned ?? []).map((p) => p.replace(/\\/g, '/')));
  }
  return scanned.sort();
}

describe('review_pr: introduced, judged at the merge base (real Semgrep)', () => {
  it.runIf(REQUIRE_SEMGREP)('GUARDIAN_REQUIRE_SEMGREP=1 — semgrep must be on PATH', () => {
    expect(SEMGREP_INSTALLED).toBe(true);
  });

  it.skipIf(!SEMGREP_INSTALLED)(
    'old findings preexisting (a shifted one, a renamed file), new ones introduced; the base run reads the 3 files holding a head result — head checked out or not',
    async () => {
      const dir = makeTempDir('review-pr-base-');
      await git(dir, 'init', '-q');
      await git(dir, 'symbolic-ref', 'HEAD', 'refs/heads/main');
      await git(dir, 'config', 'user.email', 'guardian-test@example.com');
      await git(dir, 'config', 'user.name', 'Guardian Test');
      await git(dir, 'config', 'commit.gpgsign', 'false');
      await git(dir, 'config', 'core.autocrlf', 'false');
      write(dir, '.semgrep.yml', RULES);
      const header = "const { exec } = require('child_process');";
      write(dir, 'a.js', lines(header, 'function run(cmd) {', '  exec(cmd);', '}', 'module.exports = { run };'));
      write(dir, 'b.js', lines('module.exports = 1;'));
      write(dir, 'd.js', lines(header, 'function go(line) {', '  exec(line);', '}', 'module.exports = { go };', '// a file long enough', '// for git to see a rename', '// when it moves'));
      // Its sink line reads the same as a.js's later one: a new source into an old sink keeps the identity.
      write(dir, 'e.js', lines(header, 'function shell(cmd) {', '  exec(cmd);', '}', 'module.exports = { shell };'));
      await git(dir, 'add', '-A');
      await git(dir, 'commit', '-q', '-m', 'base');
      await git(dir, 'checkout', '-q', '-b', 'feature');

      // a.js: a line above the old sink (it shifts down), and a new sink of its own.
      write(dir, 'a.js', lines(header, '// a comment above', 'function run(cmd) {', '  exec(cmd);', "  exec('rm -rf ' + cmd);", '}', 'module.exports = { run };'));
      write(dir, 'b.js', lines('module.exports = 2;'));
      write(dir, 'c.js', lines(header, "exec('ls ' + process.argv[2]);"));
      await git(dir, 'mv', 'd.js', 'moved.js');
      // e.js: the sink unchanged, a new source flowing into it — the limit the skill names.
      write(dir, 'e.js', lines(header, 'function shell(cmd) {', '  cmd = process.argv[2];', '  exec(cmd);', '}', 'module.exports = { shell };'));
      await git(dir, 'add', '-A');
      await git(dir, 'commit', '-q', '-m', 'feature');

      const db = new Database(':memory:');
      runMigrations(db);
      const plugin: PluginContext = { storage: new Storage(db), shell: null, scriptsDir: dir, progressNotifier: { send: () => {} } };
      const tool = TOOLS.find((t) => t.name === 'review_pr');
      if (!tool) throw new Error('review_pr not registered');

      const check = (r: unknown): void => {
        expect((r as { ok: boolean }).ok, JSON.stringify(r)).toBe(true);
        const res = r as { tools_run: ToolRun[]; report_paths: string[]; introduced: Introduced; findings_count_by_severity: Record<string, number> };
        expect(res.tools_run.find((t) => t.name === 'semgrep')?.status, JSON.stringify(res.tools_run)).toBe('ok');
        expect(res.introduced.compared, JSON.stringify(res.introduced)).toBe(true);
        // a.js: the old sink (shifted) preexisting, the new one introduced; c.js added: introduced; the renamed file
        // preexisting; e.js: the old sink with a new source still preexisting (the limit, pinned).
        expect(res.introduced.counts).toEqual({ introduced: 2, preexisting: 3, unknown: 0, not_compared: 0 });
        expect(res.introduced.preexisting?.map((f) => `${f.file_path}:${f.line_start}`).sort()).toEqual(['a.js:4', 'e.js:4', 'moved.js:3']);
        // The base run read the modified and renamed files holding a head result — a.js, d.js (its old name),
        // e.js — never b.js (no head result) nor c.js (added): a count, the cost bound.
        expect(baseScanned(res.report_paths)).toEqual(['a.js', 'd.js', 'e.js']);
        // Nothing is hidden: all five findings stay in the review's own counts.
        expect(Object.values(res.findings_count_by_severity).reduce((a, b) => a + b, 0)).toBe(5);
        expect(JSON.stringify(res.introduced)).not.toMatch(/guardian-review-/);
      };

      check(await tool.handler({ project_path: dir, base_ref: 'main', local_only: true }, plugin));
      // The same branch reviewed while main is checked out: both sides from temporary trees.
      await git(dir, 'checkout', '-q', 'main');
      check(await tool.handler({ project_path: dir, base_ref: 'main', head_ref: 'feature', local_only: true, force: true }, plugin));
    },
    SLOW,
  );

  // 3.18.0 review 1 (DGBASE-2 / DGBASE-3), the reviewer's probe shapes in one branch: the identity alone read a new
  // hard-coded secret (a credential rule keys it without its line) and a new line identical to an old one as
  // preexisting. A finding on a line the change added is introduced; a flagged line the diff kept is the limit.
  it.skipIf(!SEMGREP_INSTALLED)(
    'a new secret in a new function and a new identical sink above an old one are introduced; the sink a replaced function keeps is the limit',
    async () => {
      const dir = makeTempDir('review-pr-added-');
      await git(dir, 'init', '-q');
      await git(dir, 'symbolic-ref', 'HEAD', 'refs/heads/main');
      await git(dir, 'config', 'user.email', 'guardian-test@example.com');
      await git(dir, 'config', 'user.name', 'Guardian Test');
      await git(dir, 'config', 'commit.gpgsign', 'false');
      await git(dir, 'config', 'core.autocrlf', 'false');
      write(
        dir,
        '.semgrep.yml',
        `${RULES}  - id: hardcoded-jwt-secret
    languages: [javascript]
    severity: ERROR
    message: a JWT signed with a literal secret
    pattern: jwt.sign($P, "...")
`,
      );
      const H = ["const jwt = require('jsonwebtoken');", "const { exec } = require('child_process');"];
      write(dir, 'auth.js', lines(...H, 'function login(u) {', "  return jwt.sign({ u }, 'old-literal-1');", '}', 'module.exports = { login };'));
      write(dir, 'twice.js', lines(...H, 'function a(cmd) {', '  exec(cmd);', '}', 'module.exports = { a };'));
      write(dir, 'mv.js', lines(...H, 'function old(cmd) {', '  exec(cmd);', '}', 'module.exports = { old };'));
      await git(dir, 'add', '-A');
      await git(dir, 'commit', '-q', '-m', 'base');
      await git(dir, 'checkout', '-q', '-b', 'feature');
      write(
        dir,
        'auth.js',
        lines(
          ...H,
          'function login(u) {',
          '  return jwt.sign({ u }, process.env.JWT_SECRET);',
          '}',
          'function adminToken() {',
          "  return jwt.sign({ admin: true }, 'brand-new-admin-literal');",
          '}',
          'module.exports = { login, adminToken };',
        ),
      );
      write(dir, 'twice.js', lines(...H, 'function fresh(req) {', '  const cmd = req.query.c;', '  exec(cmd);', '}', 'function a(cmd) {', '  exec(cmd);', '}', 'module.exports = { a, fresh };'));
      write(dir, 'mv.js', lines(...H, 'function handler(req) {', '  const cmd = req.query.c;', '  exec(cmd);', '}', 'module.exports = { handler };'));
      await git(dir, 'add', '-A');
      await git(dir, 'commit', '-q', '-m', 'feature');

      const db = new Database(':memory:');
      runMigrations(db);
      const plugin: PluginContext = { storage: new Storage(db), shell: null, scriptsDir: dir, progressNotifier: { send: () => {} } };
      const tool = TOOLS.find((t) => t.name === 'review_pr');
      if (!tool) throw new Error('review_pr not registered');
      const check = (r: unknown): void => {
        expect((r as { ok: boolean }).ok, JSON.stringify(r)).toBe(true);
        const res = r as { introduced: Introduced };
        expect(res.introduced.compared, JSON.stringify(res.introduced)).toBe(true);
        // auth.js:7 (the new secret) and twice.js:5 (the new identical sink) introduced; twice.js:8 (the old sink)
        // and mv.js:5 (a kept line in a replaced function — the limit, pinned) preexisting.
        expect(res.introduced.counts).toEqual({ introduced: 2, preexisting: 2, unknown: 0, not_compared: 0 });
        expect(res.introduced.preexisting?.map((f) => `${f.file_path}:${f.line_start}`).sort()).toEqual(['mv.js:5', 'twice.js:8']);
      };
      check(await tool.handler({ project_path: dir, base_ref: 'main', local_only: true }, plugin));
      await git(dir, 'checkout', '-q', 'main');
      check(await tool.handler({ project_path: dir, base_ref: 'main', head_ref: 'feature', local_only: true, force: true }, plugin));
    },
    SLOW,
  );
});
