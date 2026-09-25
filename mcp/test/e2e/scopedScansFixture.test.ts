/**
 * Scoped scans and `.guardianignore` end to end with REAL Semgrep: the
 * `--exclude=/<path>` flag the exclusion plan emits is the one measured on
 * Semgrep 1.176.1, and this is where that measurement stays true — an
 * excluded tree must not appear in the report's `paths.scanned` at all, and
 * a scoped run must scan exactly its files.
 *
 * `local_only` with a one-rule `.semgrep.yml`, so the run is offline and the
 * expected findings are exact. SKIPPED without Semgrep on PATH;
 * `GUARDIAN_REQUIRE_SEMGREP=1` turns that into a failure.
 */

import { execa } from 'execa';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import type { PluginContext } from '../../src/context.js';
import { resolveProjectPath } from '../../src/platform/projectPath.js';
import { GuardianDatabase as Database } from '../../src/storage/db.js';
import { runMigrations } from '../../src/storage/migrations/runner.js';
import { Storage } from '../../src/storage/index.js';
import { TOOLS } from '../../src/tools/index.js';
import { resetScannerCache } from '../../src/tools/scanHelpers.js';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';
import { isInstalled } from '../helpers/toolchain.js';

/** Real Semgrep runs, several per test: a file-level ceiling (see vitest.config.ts). */
vi.setConfig({ testTimeout: 300_000 });

afterAll(cleanupTempDirs);
beforeAll(async () => {
  await import('../../src/tools/scanSast.js');
  resetScannerCache();
});

const SEMGREP_INSTALLED = await isInstalled('semgrep');
const REQUIRE_SEMGREP = process.env['GUARDIAN_REQUIRE_SEMGREP'] === '1';

const RULES = `rules:
  - id: no-eval
    languages: [python]
    severity: ERROR
    message: eval on dynamic input
    pattern: eval(...)
`;

function write(dir: string, rel: string, content: string): void {
  const abs = join(dir, rel);
  mkdirSync(join(abs, '..'), { recursive: true });
  writeFileSync(abs, content);
}

async function git(cwd: string, ...args: string[]): Promise<void> {
  await execa('git', args, { cwd });
}

function plugin(dir: string): PluginContext {
  const db = new Database(':memory:');
  runMigrations(db);
  return { storage: new Storage(db), shell: null, scriptsDir: dir, progressNotifier: { send: () => {} } };
}

interface Result {
  scan_id: string;
  coverage: string;
  report_paths: string[];
  scope?: { files: number };
  exclusions?: { excluded_files: number; findings_excluded: number };
}

async function sast(dir: string, p: PluginContext, input: Record<string, unknown> = {}): Promise<Result> {
  const tool = TOOLS.find((t) => t.name === 'scan_sast');
  if (!tool) throw new Error('scan_sast not registered');
  const r = await tool.handler({ project_path: dir, local_only: true, force: true, ...input }, p);
  if (!r.ok) throw new Error(JSON.stringify(r.error));
  return r as unknown as Result;
}

/** Files Semgrep itself says it scanned, from every report of the run, project-relative. */
function scannedBySemgrep(project: string, res: Result): string[] {
  const reportDir = res.report_paths[0] ?? '';
  const root = `${project.replace(/\\/g, '/')}/`;
  const out: string[] = [];
  for (const name of ['sast.json', 'sast-001.json']) {
    let raw: { paths?: { scanned?: string[] } };
    try {
      raw = JSON.parse(readFileSync(join(reportDir, name), 'utf8')) as { paths?: { scanned?: string[] } };
    } catch {
      continue; // this run did not write that report
    }
    for (const p of raw.paths?.scanned ?? []) {
      const posix = p.replace(/\\/g, '/');
      out.push(posix.toLowerCase().startsWith(root.toLowerCase()) ? posix.slice(root.length) : posix);
    }
  }
  return out.sort();
}

const semgrepFiles = (p: PluginContext, scanId: string): string[] =>
  p.storage.findings
    .listByScan(scanId)
    .filter((f) => f.tool === 'semgrep')
    .map((f) => f.file_path ?? '')
    .sort();

describe('scoped scans and .guardianignore with real Semgrep', () => {
  it.runIf(REQUIRE_SEMGREP)('GUARDIAN_REQUIRE_SEMGREP=1 — semgrep must be on PATH', () => {
    expect(SEMGREP_INSTALLED).toBe(true);
  });

  it.skipIf(!SEMGREP_INSTALLED)('an excluded tree is never scanned, a scope scans exactly its files', async () => {
    const dir = resolveProjectPath(makeTempDir('scoped-e2e-')).path;
    await git(dir, 'init', '-q');
    await git(dir, 'config', 'user.email', 'guardian-test@example.com');
    await git(dir, 'config', 'user.name', 'Guardian Test');
    await git(dir, 'config', 'commit.gpgsign', 'false');
    write(dir, '.semgrep.yml', RULES);
    write(dir, '.guardianignore', '# deliberately vulnerable\nfixtures/\n');
    write(dir, 'fixtures/vuln.py', 'eval(user_input)\n');
    write(dir, 'app.py', 'x = 1\n');
    write(dir, 'lib/x.py', 'eval(user_input)\n');
    await git(dir, 'add', '-A');
    await git(dir, 'commit', '-q', '-m', 'base');
    const p = plugin(dir);

    // Whole project: Semgrep never opened the excluded tree.
    const whole = await sast(dir, p);
    expect(scannedBySemgrep(dir, whole)).toEqual(['app.py', 'lib/x.py']);
    expect(semgrepFiles(p, whole.scan_id)).toEqual(['lib/x.py']);
    expect(whole.exclusions).toMatchObject({ excluded_files: 1, findings_excluded: 0 });

    // scope.paths: exactly those files.
    const scoped = await sast(dir, p, { scope: { paths: ['lib'] } });
    expect(scannedBySemgrep(dir, scoped)).toEqual(['lib/x.py']);
    expect(semgrepFiles(p, scoped.scan_id)).toEqual(['lib/x.py']);
    expect(scoped.scope).toMatchObject({ files: 1 });

    // scope.diff: only the uncommitted change.
    write(dir, 'app.py', 'eval(user_input)\n');
    const diff = await sast(dir, p, { scope: { diff: {} } });
    expect(scannedBySemgrep(dir, diff)).toEqual(['app.py']);
    expect(semgrepFiles(p, diff.scan_id)).toEqual(['app.py']);
    expect(diff.coverage).not.toBe('none');
  });

  it.skipIf(!SEMGREP_INSTALLED)('a project in a subdirectory of its repository: excludes land where the ignore file means', async () => {
    // Semgrep anchors a leading-`/` --exclude at the GIT ROOT. Unprefixed,
    // `/fixtures` excluded nothing and `/sub/lib` (meant for <project>/sub/lib)
    // excluded the kept <project>/lib — a finding silently lost.
    const repoRoot = makeTempDir('scoped-e2e-sub-');
    await git(repoRoot, 'init', '-q');
    await git(repoRoot, 'config', 'user.email', 'guardian-test@example.com');
    await git(repoRoot, 'config', 'user.name', 'Guardian Test');
    await git(repoRoot, 'config', 'commit.gpgsign', 'false');
    const project = join(repoRoot, 'sub');
    write(project, '.semgrep.yml', RULES);
    write(project, '.guardianignore', 'fixtures/\n/sub/lib/\n');
    write(project, 'fixtures/vuln.py', 'eval(user_input)\n');
    write(project, 'sub/lib/y.py', 'eval(user_input)\n');
    write(project, 'lib/ok.py', 'eval(user_input)\n');
    write(project, 'app.py', 'x = 1\n');
    await git(repoRoot, 'add', '-A');
    await git(repoRoot, 'commit', '-q', '-m', 'base');
    const canonical = resolveProjectPath(project).path;
    const p = plugin(canonical);

    const whole = await sast(canonical, p);
    expect(scannedBySemgrep(canonical, whole)).toEqual(['app.py', 'lib/ok.py']);
    expect(semgrepFiles(p, whole.scan_id)).toEqual(['lib/ok.py']);
    expect(whole.exclusions).toMatchObject({ excluded_files: 2, findings_excluded: 0 });
  });
});
