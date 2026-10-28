/**
 * Review 10, finding 1 (HIGH, a 3.3.0 regression): every folder NAMED
 * `.guardian` — at any depth — was left out of Semgrep (`--exclude=.guardian`,
 * unanchored) and of gitleaks' working-tree pass, so a pull request adding
 * `lib/.guardian/handler.js` with a command injection passed the CI gate with
 * exit 0 and coverage `full`, and `map_attack_surface` never saw its routes.
 *
 * Only the ROOT `.guardian/`'s generated output is left out now, by exact
 * project-relative path (`platform/guardianOutput.ts`), and a file git tracks
 * there is a named gap. Against the REAL scanners, each test gated on the one
 * it needs (`GUARDIAN_REQUIRE_SEMGREP=1` turns a missing Semgrep into a
 * failure).
 */

import { execa } from 'execa';
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import type { PluginContext } from '../../src/context.js';
import { resolveProjectPath } from '../../src/platform/projectPath.js';
import { semgrepScanFlags } from '../../src/runners/semgrepRun.js';
import { GuardianDatabase as Database } from '../../src/storage/db.js';
import { runMigrations } from '../../src/storage/migrations/runner.js';
import { Storage } from '../../src/storage/index.js';
import { TOOLS } from '../../src/tools/index.js';
import { resetScannerCache } from '../../src/tools/scanHelpers.js';
import type { AttackSurfaceSnapshot, Finding, ToolRun } from '../../src/types.js';
import { runSemgrep } from '../helpers/semgrep.js';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';
import { isInstalled } from '../helpers/toolchain.js';

vi.setConfig({ testTimeout: 300_000 });

afterAll(cleanupTempDirs);
beforeAll(async () => {
  await import('../../src/tools/scanSast.js');
  await import('../../src/tools/scanSecrets.js');
  await import('../../src/tools/mapAttackSurface.js');
  resetScannerCache();
});

const SEMGREP_INSTALLED = await isInstalled('semgrep');
const GITLEAKS_INSTALLED = await isInstalled('gitleaks');
const REQUIRE_SEMGREP = process.env['GUARDIAN_REQUIRE_SEMGREP'] === '1';
const SCRIPTS_DIR = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..', '..', 'scripts');

const RULE = `rules:
  - id: guardian-test-exec
    languages: [javascript]
    severity: ERROR
    message: exec of input
    pattern: exec(...)
`;
const EXEC = "const { exec } = require('child_process');\nexec('cat ' + process.argv[2]);\n";

function tree(prefix: string, files: Record<string, string>): string {
  const dir = resolveProjectPath(makeTempDir(prefix)).path;
  for (const [rel, body] of Object.entries(files)) {
    mkdirSync(dirname(join(dir, ...rel.split('/'))), { recursive: true });
    writeFileSync(join(dir, ...rel.split('/')), body);
  }
  return dir;
}

async function git(cwd: string, ...args: string[]): Promise<void> {
  await execa('git', args, { cwd });
}

async function repo(prefix: string, files: Record<string, string>): Promise<string> {
  const dir = tree(prefix, files);
  await git(dir, 'init', '-q');
  await git(dir, 'config', 'user.email', 'guardian-test@example.com');
  await git(dir, 'config', 'user.name', 'Guardian Test');
  await git(dir, 'config', 'commit.gpgsign', 'false');
  await git(dir, 'config', 'core.autocrlf', 'false');
  await git(dir, 'add', '-A');
  await git(dir, 'commit', '-q', '-m', 'initial');
  return dir;
}

function plugin(): PluginContext {
  const db = new Database(':memory:');
  runMigrations(db);
  return { storage: new Storage(db), shell: null, scriptsDir: SCRIPTS_DIR, progressNotifier: { send: () => {} } };
}

interface Out {
  scan_id: string;
  tools_run: ToolRun[];
  missing_tools: string[];
  snapshot_id?: number | null;
}

async function run(name: string, input: Record<string, unknown>, p: PluginContext): Promise<Out> {
  const tool = TOOLS.find((t) => t.name === name);
  if (!tool) throw new Error(`${name} not registered`);
  const r = await tool.handler(input, p);
  if (!r.ok) throw new Error(JSON.stringify(r.error));
  return r as unknown as Out;
}

const files = (findings: Finding[], tool: string): string[] =>
  [...new Set(findings.filter((f) => f.tool === tool).map((f) => (f.file_path ?? '').split('\\').join('/')))].sort();

/** The project-relative paths of a Semgrep `--json` report's results. */
function resultPaths(stdout: string, root: string): string[] {
  const report = JSON.parse(stdout) as { results: Array<{ path: string }> };
  const prefix = `${root.split('\\').join('/').toLowerCase()}/`;
  return [
    ...new Set(
      report.results.map((r) => {
        const p = r.path.split('\\').join('/');
        return p.toLowerCase().startsWith(prefix) ? p.slice(prefix.length) : p.replace(/^\.\//, '');
      }),
    ),
  ].sort();
}

const LAYOUT: Record<string, string> = {
  'rule.yml': RULE,
  'index.js': EXEC,
  'lib/.guardian/handler.js': EXEC,
  'lib/.guardian/reports/old.js': EXEC,
  '.guardian/handler.js': EXEC,
  '.guardian/reports/sast-1/old.js': EXEC,
  '.guardian/dashboard.html': '<script>exec(1)</script>\n',
};

describe('Semgrep reads every .guardian folder but the root one’s generated output (real Semgrep)', () => {
  it.runIf(REQUIRE_SEMGREP)('GUARDIAN_REQUIRE_SEMGREP=1 — this suite must be runnable', () => {
    expect(SEMGREP_INSTALLED, 'GUARDIAN_REQUIRE_SEMGREP=1 but semgrep is not on PATH').toBe(true);
  });

  it.skipIf(!SEMGREP_INSTALLED)('`--exclude=/.guardian` anchors at the GIT ROOT: in a sub-project it excludes nothing of the project’s own', async () => {
    // The anchoring the exclusion is designed around (platform/guardianOutput.ts).
    // At the repository root a leading slash does leave the root .guardian
    // out — and only it (spawned without a shell; from Git Bash, MSYS turns
    // `/.guardian` into a Windows path and it excludes nothing anywhere).
    const atRoot = await repo('guardian-dir-quirk-', LAYOUT);
    const r = runSemgrep(['scan', '--metrics=off', '--config', join(atRoot, 'rule.yml'), '--exclude=/.guardian', '--json', '--quiet', atRoot], { cwd: atRoot });
    expect(r.status, r.stderr.slice(-2000)).toBe(0);
    expect(resultPaths(r.stdout, atRoot)).toEqual(['index.js', 'lib/.guardian/handler.js', 'lib/.guardian/reports/old.js']);

    // One level down, the same flag names `<repo>/.guardian`: nothing here.
    const top = await repo('guardian-dir-quirk-mono-', Object.fromEntries(Object.entries(LAYOUT).map(([k, v]) => [`pkg/${k}`, v])));
    const sub = join(top, 'pkg');
    const s = runSemgrep(['scan', '--metrics=off', '--config', join(sub, 'rule.yml'), '--exclude=/.guardian', '--json', '--quiet', sub], { cwd: sub });
    expect(s.status, s.stderr.slice(-2000)).toBe(0);
    expect(resultPaths(s.stdout, sub)).toContain('.guardian/reports/sast-1/old.js');
  });

  for (const inGit of [false, true]) {
    it.skipIf(!SEMGREP_INSTALLED)(`the scan flags leave out exactly the root output — ${inGit ? 'in a git work tree' : 'outside git'}`, async () => {
      const dir = inGit ? await repo('guardian-dir-git-', LAYOUT) : tree('guardian-dir-plain-', LAYOUT);
      const flags = semgrepScanFlags(dir).args;
      expect(flags).not.toContain('--exclude=.guardian');
      const r = runSemgrep(['scan', '--metrics=off', '--config', join(dir, 'rule.yml'), ...flags, '--json', '--quiet', dir], { cwd: dir });
      expect(r.status, r.stderr.slice(-2000)).toBe(0);
      expect(resultPaths(r.stdout, dir)).toEqual([
        '.guardian/handler.js',
        'index.js',
        'lib/.guardian/handler.js',
        'lib/.guardian/reports/old.js',
      ]);
    });
  }

  it.skipIf(!SEMGREP_INSTALLED)('a project below its repository root: a nested .guardian is still read', async () => {
    const top = await repo('guardian-dir-mono-', Object.fromEntries(Object.entries(LAYOUT).map(([k, v]) => [`packages/api/${k}`, v])));
    const dir = join(top, 'packages', 'api');
    const r = runSemgrep(['scan', '--metrics=off', '--config', join(dir, 'rule.yml'), ...semgrepScanFlags(dir).args, '--json', '--quiet', dir], { cwd: dir });
    expect(r.status, r.stderr.slice(-2000) + r.stdout.slice(0, 2000)).toBe(0);
    const found = resultPaths(r.stdout, dir);
    expect(found).toContain('lib/.guardian/handler.js');
    expect(found).toContain('lib/.guardian/reports/old.js');
  });
});

describe('scan_sast and map_attack_surface read lib/.guardian (real Semgrep)', () => {
  it.skipIf(!SEMGREP_INSTALLED)('a command injection in lib/.guardian/handler.js is a finding; the root reports are not', async () => {
    const dir = await repo('guardian-dir-sast-', {
      '.semgrep.yml': RULE,
      'index.js': "require('./lib/.guardian/handler.js');\n",
      'lib/.guardian/handler.js': EXEC,
    });
    // A report of an earlier run, untracked and not ignored (a CLI-only project).
    mkdirSync(join(dir, '.guardian', 'reports', 'sast-0'), { recursive: true });
    writeFileSync(join(dir, '.guardian', 'reports', 'sast-0', 'copy.js'), EXEC);
    const p = plugin();
    const out = await run('scan_sast', { project_path: dir, force: true, local_only: true }, p);
    const findings = p.storage.findings.listByScan(out.scan_id);
    expect(files(findings, 'semgrep')).toEqual(['lib/.guardian/handler.js']);
    expect(out.missing_tools).not.toContain('semgrep');
  });

  it.skipIf(!SEMGREP_INSTALLED)('a file git TRACKS in the root .guardian/reports is a named gap, never a silent pass', async () => {
    const dir = await repo('guardian-dir-tracked-', { '.semgrep.yml': RULE, 'index.js': "require('./.guardian/reports/evil.js');\n" });
    mkdirSync(join(dir, '.guardian', 'reports'), { recursive: true });
    writeFileSync(join(dir, '.guardian', 'reports', 'evil.js'), EXEC);
    await git(dir, 'add', '-f', '.guardian/reports/evil.js');
    await git(dir, 'commit', '-q', '-m', 'hide code in the reports');
    const p = plugin();
    const out = await run('scan_sast', { project_path: dir, force: true, local_only: true }, p);
    const semgrep = out.tools_run.find((t) => t.name === 'semgrep');
    expect(out.missing_tools).toContain('semgrep');
    expect(semgrep?.reason).toMatch(/1 file\(s\) git tracks in \.guardian\/'s generated output were not scanned: \.guardian\/reports\/evil\.js/);
    expect(semgrep?.unscanned).toEqual({ guardian_output: 1 });
  });

  it.skipIf(!SEMGREP_INSTALLED)('map_attack_surface maps a route declared in lib/.guardian', async () => {
    const dir = await repo('guardian-dir-surface-', {
      'index.js': "const express = require('express');\nconst app = express();\napp.get('/visible', (req, res) => res.send('a'));\n",
      'lib/.guardian/routes.js': "const express = require('express');\nconst app = express();\napp.post('/hidden', (req, res) => res.send('b'));\n",
    });
    const p = plugin();
    const out = await run('map_attack_surface', { project_path: dir, force: true }, p);
    const id = out.snapshot_id;
    expect(id, JSON.stringify(out.tools_run)).not.toBeNull();
    const snapshot: AttackSurfaceSnapshot | undefined = id == null ? undefined : p.storage.surface.getById(id)?.snapshot;
    const root = `${dir.split('\\').join('/')}/`;
    const routes = (snapshot?.routes ?? [])
      .map((r) => `${r.method} ${r.path_raw} ${r.file.split('\\').join('/').replace(root, '')}`)
      .sort();
    expect(routes).toEqual(['GET /visible index.js', 'POST /hidden lib/.guardian/routes.js']);
  });
});

describe('gitleaks reads an uncommitted file in lib/.guardian (real gitleaks)', () => {
  it.skipIf(!GITLEAKS_INSTALLED)('the working-tree pass scans lib/.guardian and leaves the root reports out', async () => {
    const dir = await repo('guardian-dir-secrets-', { 'index.js': 'module.exports = 1;\n' });
    const key = `const key = "${'AKIA'}${'ZXCVBNMLKJHGFDSA'}";\n`;
    mkdirSync(join(dir, 'lib', '.guardian'), { recursive: true });
    writeFileSync(join(dir, 'lib', '.guardian', 'creds.js'), key);
    mkdirSync(join(dir, '.guardian', 'reports', 'secrets-0'), { recursive: true });
    writeFileSync(join(dir, '.guardian', 'reports', 'secrets-0', 'copy.js'), key);
    const p = plugin();
    const out = await run('scan_secrets', { project_path: dir, force: true }, p);
    expect(files(p.storage.findings.listByScan(out.scan_id), 'gitleaks')).toEqual(['lib/.guardian/creds.js']);
  });
});
