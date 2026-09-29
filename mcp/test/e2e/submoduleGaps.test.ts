/**
 * Review M2, against the REAL Semgrep and gitleaks on PATH: a git
 * submodule's contents are invisible to both — Semgrep lists targets with
 * `git ls-files`, which shows a submodule as one gitlink, and gitleaks reads
 * the superproject's commits and uncommitted files, neither of which holds
 * the submodule's files — yet the scans read coverage full. A submodule that
 * is initialised and has content is now named as a gap ("submodule contents
 * not scanned"), and still not scanned.
 */

import { execa } from 'execa';
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import type { PluginContext } from '../../src/context.js';
import { resolveProjectPath } from '../../src/platform/projectPath.js';
import { GuardianDatabase as Database } from '../../src/storage/db.js';
import { runMigrations } from '../../src/storage/migrations/runner.js';
import { Storage } from '../../src/storage/index.js';
import { TOOLS } from '../../src/tools/index.js';
import { resetScannerCache } from '../../src/tools/scanHelpers.js';
import type { ToolRun } from '../../src/types.js';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';
import { isInstalled } from '../helpers/toolchain.js';

vi.setConfig({ testTimeout: 300_000 });

afterAll(cleanupTempDirs);
beforeAll(async () => {
  await import('../../src/tools/scanSast.js');
  await import('../../src/tools/scanSecrets.js');
  await import('../../src/tools/bugHunt.js');
  await import('../../src/tools/scanWordpress.js');
  await import('../../src/tools/reviewPr.js');
  resetScannerCache();
});

const SEMGREP = await isInstalled('semgrep');
const GITLEAKS = await isInstalled('gitleaks');

const RULES = `rules:
  - id: no-eval
    languages: [python]
    severity: ERROR
    message: eval on dynamic input
    pattern: eval(...)
`;
const AWS_KEY_ID = ['AKIA', 'IOSFODNN7', 'ABCDEFG'].join('');

async function git(cwd: string, ...args: string[]): Promise<void> {
  await execa('git', ['-c', 'protocol.file.allow=always', ...args], { cwd });
}

async function repo(prefix: string, files: Record<string, string>): Promise<string> {
  const dir = resolveProjectPath(makeTempDir(prefix)).path;
  await git(dir, 'init', '-q');
  await git(dir, 'config', 'user.email', 'guardian-test@example.com');
  await git(dir, 'config', 'user.name', 'Guardian Test');
  await git(dir, 'config', 'commit.gpgsign', 'false');
  for (const [rel, body] of Object.entries(files)) {
    mkdirSync(dirname(join(dir, rel)), { recursive: true });
    writeFileSync(join(dir, rel), body);
  }
  await git(dir, 'add', '-A');
  await git(dir, 'commit', '-q', '-m', 'initial');
  return dir;
}

/** A superproject with `.semgrep.yml` and one clean file, and `vendor/lib` a submodule holding an eval and a key. */
async function superproject(): Promise<string> {
  const lib = await repo('submodule-lib-', { 'danger.py': 'eval(user_input)\n', 'config.ini': `aws_access_key_id = ${AWS_KEY_ID}\n` });
  const top = await repo('submodule-top-', { '.semgrep.yml': RULES, 'app.py': 'x = 1\n' });
  await git(top, 'submodule', 'add', '-q', `file://${lib.replace(/\\/g, '/')}`, 'vendor/lib');
  await git(top, 'commit', '-q', '-m', 'add submodule');
  return top;
}

function plugin(dir: string): PluginContext {
  const db = new Database(':memory:');
  runMigrations(db);
  return { storage: new Storage(db), shell: null, scriptsDir: dir, progressNotifier: { send: () => {} } };
}

async function run(name: string, dir: string, input: Record<string, unknown> = {}): Promise<{ tools_run: ToolRun[]; missing_tools: string[]; coverage: string }> {
  const tool = TOOLS.find((t) => t.name === name);
  if (!tool) throw new Error(`${name} not registered`);
  const r = await tool.handler({ project_path: dir, force: true, ...input }, plugin(dir));
  if (!r.ok) throw new Error(JSON.stringify(r.error));
  return r as unknown as { tools_run: ToolRun[]; missing_tools: string[]; coverage: string };
}

describe('initialised submodules are a named gap (real scanners)', () => {
  it.skipIf(!SEMGREP)('scan_sast: partial, "submodule contents not scanned: vendor/lib"', async () => {
    const top = await superproject();
    const r = await run('scan_sast', top, { local_only: true });
    const semgrep = r.tools_run.find((t) => t.name === 'semgrep');
    expect(semgrep?.status).toBe('ok');
    expect(semgrep?.reason).toMatch(/submodule contents not scanned: vendor\/lib/);
    expect(r.missing_tools).toContain('semgrep');
    expect(r.coverage).toBe('partial');
  });

  it.skipIf(!GITLEAKS)('scan_secrets: partial, the submodule named', async () => {
    const top = await superproject();
    const r = await run('scan_secrets', top);
    const history = r.tools_run.find((t) => t.name === 'gitleaks');
    expect(history?.reason).toMatch(/submodule contents not scanned: vendor\/lib/);
    expect(r.missing_tools).toContain('gitleaks');
    expect(r.coverage).toBe('partial');
  });

  // Round 2: every Semgrep and gitleaks caller, through one shared place
  // (runners/semgrepCoverageGaps.ts; the gitleaks runner for secrets).
  it.skipIf(!SEMGREP)('bug_hunt: partial, the submodule named', async () => {
    const top = await superproject();
    const r = await run('bug_hunt', top);
    const semgrep = r.tools_run.find((t) => t.name === 'semgrep');
    expect(semgrep?.reason).toMatch(/submodule contents not scanned: vendor\/lib/);
    expect(r.missing_tools).toContain('semgrep');
    expect(r.coverage).not.toBe('full');
  });

  it.skipIf(!SEMGREP)('scan_wordpress: semgrep-wp partial, the submodule named', async () => {
    const lib = await repo('submodule-wplib-', { 'lib.php': '<?php\necho 1;\n' });
    const top = await repo('submodule-wp-', { 'readme.txt': '=== Acme ===\n', 'acme.php': '<?php\n/* Plugin Name: Acme */\n' });
    await git(top, 'submodule', 'add', '-q', `file://${lib.replace(/\\/g, '/')}`, 'lib');
    await git(top, 'commit', '-q', '-m', 'add submodule');
    const r = await run('scan_wordpress', top);
    const semgrep = r.tools_run.find((t) => t.name === 'semgrep-wp');
    expect(semgrep?.reason).toMatch(/submodule contents not scanned: lib/);
    expect(r.missing_tools).toContain('semgrep-wp');
  });

  it.skipIf(!SEMGREP || !GITLEAKS)(
    'review_pr: a diff that bumps a submodule names it for gitleaks; one that does not, does not',
    async () => {
      const top = await superproject();
      await git(top, 'branch', '-q', '-M', 'main');
      // A PR that only changes an ordinary file: no submodule gap.
      await git(top, 'checkout', '-q', '-b', 'plain');
      writeFileSync(join(top, 'app.py'), 'x = 2\n');
      await git(top, 'commit', '-q', '-am', 'plain change');
      const plain = await run('review_pr', top, { base_ref: 'main', local_only: true });
      for (const t of plain.tools_run) expect(t.reason ?? '').not.toMatch(/submodule/);

      // A PR that bumps the submodule: its contents changed and none was read.
      await git(top, 'checkout', '-q', 'main');
      await git(top, 'checkout', '-q', '-b', 'bump');
      const sub = join(top, 'vendor', 'lib');
      await git(sub, 'config', 'user.email', 'guardian-test@example.com');
      await git(sub, 'config', 'user.name', 'Guardian Test');
      await git(sub, 'config', 'commit.gpgsign', 'false');
      writeFileSync(join(sub, 'more.py'), 'x = 3\n');
      await git(sub, 'add', '-A');
      await git(sub, 'commit', '-q', '-m', 'more');
      await git(top, 'add', 'vendor/lib');
      await git(top, 'commit', '-q', '-m', 'bump lib');
      const bumped = await run('review_pr', top, { base_ref: 'main', local_only: true });
      expect(bumped.tools_run.find((t) => t.name === 'gitleaks')?.reason).toMatch(/submodule contents not scanned: vendor\/lib/);
      expect(bumped.tools_run.find((t) => t.name === 'semgrep')?.reason).toMatch(/submodule contents not scanned: vendor\/lib/);
      expect(bumped.missing_tools).toContain('gitleaks');
      expect(bumped.coverage).not.toBe('full');
    },
  );

  // Round 4, item 6: a submodule the project's .guardianignore excludes is no gap.
  it.skipIf(!SEMGREP || !GITLEAKS)('a submodule .guardianignore excludes is no gap, for Semgrep and gitleaks', async () => {
    for (const pattern of ['vendor/lib', 'vendor/', 'vendor/lib/**']) {
      const top = await superproject();
      writeFileSync(join(top, '.guardianignore'), `${pattern}\n`);
      await git(top, 'add', '.guardianignore');
      await git(top, 'commit', '-q', '-m', 'ignore the submodule');
      const sast = await run('scan_sast', top, { local_only: true });
      expect(sast.tools_run.find((t) => t.name === 'semgrep')?.reason ?? '', pattern).not.toMatch(/submodule/);
      expect(sast.missing_tools, pattern).not.toContain('semgrep');
      const secrets = await run('scan_secrets', top);
      for (const t of secrets.tools_run) expect(t.reason ?? '', pattern).not.toMatch(/submodule/);
      expect(secrets.missing_tools, pattern).not.toContain('gitleaks');
    }
  });

  it.skipIf(!SEMGREP)('a submodule declared but not initialised (no content) is no gap', async () => {
    const top = await superproject();
    const clone = resolveProjectPath(makeTempDir('submodule-clone-')).path;
    await git(clone, 'clone', '-q', `file://${top.replace(/\\/g, '/')}`, '.');
    const r = await run('scan_sast', clone, { local_only: true });
    expect(r.tools_run.find((t) => t.name === 'semgrep')?.reason ?? '').not.toMatch(/submodule/);
    expect(r.coverage).toBe('full');
  });
});
