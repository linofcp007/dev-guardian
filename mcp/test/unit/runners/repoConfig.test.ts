/**
 * Round 5, item 2: every repository configuration a scanner honours is named
 * on its run, one way (`runners/repoConfig.ts`).
 *
 *   - For every runner in `REPO_CONFIG`: a project holding each of its files
 *     gets exactly those files named — nested ones wherever they sit, a
 *     shared file (`pyproject.toml`) only with its section.
 *   - For every scanner spawned in `src/`: it has an entry, or says in
 *     `NO_REPO_CONFIG` why it reads none; and the file that spawns it names
 *     what it reads. A scanner added without either fails here.
 */

import { execa } from 'execa';
import { mkdirSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, describe, expect, it } from 'vitest';
import {
  honouredFiles,
  honouredHandedFiles,
  honouredNote,
  NO_REPO_CONFIG,
  REPO_CONFIG,
  withProjectConfig,
  type RepoConfigFile,
  type RepoConfigRunner,
} from '../../../src/runners/repoConfig.js';
import { cleanupTempDirs, makeTempDir } from '../../helpers/tempDir.js';

afterAll(cleanupTempDirs);

function tree(files: Record<string, string>): string {
  const dir = makeTempDir('repo-config-');
  for (const [rel, body] of Object.entries(files)) {
    mkdirSync(dirname(join(dir, rel)), { recursive: true });
    writeFileSync(join(dir, rel), body);
  }
  return dir;
}

/** Where the table test puts a spec's file: a handed one under a concrete name (`requirements*.txt` names a kind). */
function pathFor(spec: RepoConfigFile, i: number): string {
  if (spec.handed === true) return `h${i}/requirements.txt`;
  return spec.nested === true ? `n${i}/${spec.file}` : spec.file;
}

/** Text that satisfies a spec's `when`, or a plain line. */
function bodyFor(spec: RepoConfigFile): string {
  if (spec.when === undefined) return '# config\n';
  const src = spec.when.source;
  if (src.includes('tool\\.ruff')) return '[tool.ruff]\nline-length = 100\n';
  if (src.includes('tool\\.radon')) return '[tool.radon]\nexclude = "x"\n';
  if (src.includes('radon')) return '[radon]\nexclude = x\n';
  if (src.includes('jscpd')) return '{"name":"x","jscpd":{"threshold":1}}';
  if (src.includes('eslintConfig')) return '{"name":"x","eslintConfig":{}}';
  if (src.includes('index-url')) return '--index-url https://pypi.example.internal/simple\nrequests==2.0.0\n';
  throw new Error(`no body for ${spec.file}`);
}

const RUNNERS = Object.keys(REPO_CONFIG) as RepoConfigRunner[];

describe('REPO_CONFIG: each runner names exactly the files it reads', () => {
  it.each(RUNNERS)('%s', async (runner) => {
    const specs = REPO_CONFIG[runner];
    const files: Record<string, string> = {};
    const expected: string[] = [];
    const handed: string[] = [];
    specs.forEach((spec, i) => {
      // A nested file sits below the root (its own directory: file names that
      // differ only in case cannot share one on every file system).
      const path = pathFor(spec, i);
      if (files[path] !== undefined) return; // one shared root file, two sections: the first wins
      files[path] = bodyFor(spec);
      expected.push(path);
      if (spec.handed === true) handed.push(path);
    });
    const dir = tree(files);
    const found = [...(await honouredFiles(dir, runner)), ...honouredHandedFiles(dir, runner, handed)];
    const run = withProjectConfig({ name: runner, status: 'ok' }, found);
    expect([...(run.honoured_config ?? [])].sort()).toEqual([...expected].sort());
    expect(run.reason).toMatch(/^honoured the project's /);
  });

  it.each(RUNNERS.flatMap((runner) => REPO_CONFIG[runner].filter((s) => s.when !== undefined).map((s) => [runner, s.file] as const)))(
    '%s: a %s without its section is not named',
    async (runner, file) => {
      const spec = REPO_CONFIG[runner].find((s) => s.file === file);
      const path = spec?.handed === true ? 'requirements.txt' : spec?.nested === true ? `sub/${file}` : file;
      const dir = tree({ [path]: file.endsWith('.json') ? '{"name":"x"}' : '[other]\nx = 1\n' });
      expect((await honouredFiles(dir, runner)).map((f) => f.path)).not.toContain(path);
      expect(honouredHandedFiles(dir, runner, [path]).map((f) => f.path)).not.toContain(path);
    },
  );

  it('a handed file is named only among the files handed, never looked for', async () => {
    const dir = tree({ 'requirements.txt': '--extra-index-url https://x.example/simple\n', 'other.txt': '-i https://x.example/simple\n' });
    expect(await honouredFiles(dir, 'pip-audit')).toEqual([]);
    expect(honouredHandedFiles(dir, 'pip-audit', ['requirements.txt', 'missing.txt']).map((f) => f.path)).toEqual([
      'requirements.txt',
    ]);
    expect(honouredHandedFiles(dir, 'npm', ['requirements.txt'])).toEqual([]);
  });

  it('matches names exactly: a NuGet.Config is named as NuGet.Config, once', async () => {
    const dir = tree({ 'NuGet.Config': '<configuration/>' });
    expect((await honouredFiles(dir, 'dotnet')).map((f) => f.path)).toEqual(['NuGet.Config']);
  });

  it("in a git work tree, git's own listing: untracked files count, gitignored ones do not", async () => {
    const dir = tree({
      '.semgrepignore': 'x/\n',
      'sub/.semgrepignore': 'deep/\n',
      'new/.semgrepignore': 'y/\n',
      'gen/.semgrepignore': 'z/\n',
      '.gitignore': 'gen/\n',
    });
    await execa('git', ['init', '-q'], { cwd: dir });
    await execa('git', ['add', '.semgrepignore', 'sub/.semgrepignore', '.gitignore'], { cwd: dir });
    expect((await honouredFiles(dir, 'semgrep')).map((f) => f.path)).toEqual([
      '.semgrepignore',
      'new/.semgrepignore',
      'sub/.semgrepignore',
    ]);
  });
});

describe('the one wording', () => {
  it('names at most five files, then says how many more', () => {
    const files = Array.from({ length: 7 }, (_, i) => ({ path: `d${i}/.semgrepignore`, decides: 'its patterns decide which files are scanned' }));
    expect(honouredNote(files)).toBe(
      "honoured the project's d0/.semgrepignore, d1/.semgrepignore, d2/.semgrepignore, d3/.semgrepignore, " +
        'd4/.semgrepignore (its patterns decide which files are scanned) and 2 more',
    );
  });

  it('is applied once, however many times a run passes through', () => {
    const files = [{ path: '.guardianignore', decides: 'its entries are not scanned or reported' }];
    const once = withProjectConfig({ name: 'semgrep', status: 'ok', reason: 'x' }, files);
    expect(withProjectConfig(once, files)).toEqual(once);
    expect(once).toEqual({
      name: 'semgrep',
      status: 'ok',
      reason: "x; honoured the project's .guardianignore (its entries are not scanned or reported)",
      honoured_config: ['.guardianignore'],
    });
  });
});

// ---------------------------------------------------------------- every spawn in src/

const SRC = fileURLToPath(new URL('../../../src/', import.meta.url));

function tsFiles(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((e) => {
    const abs = join(dir, e.name);
    if (e.isDirectory()) return tsFiles(abs);
    return e.name.endsWith('.ts') ? [abs] : [];
  });
}

/**
 * Every `command: '<x>'` / `binary: '<x>'` in `src/` — the process spawns —
 * classified: the runner whose configuration it reads (`REPO_CONFIG`), a
 * scanner that reads none (`NO_REPO_CONFIG`), or no scanner at all. Keyed
 * `file|command`, so one binary used two ways (dotnet) is judged by each.
 */
const SPAWNS: Readonly<Record<string, RepoConfigRunner | 'none' | `reads none here: ${string}` | `not a scanner: ${string}`>> = {
  'runners/trivyRun.ts|trivy': 'trivy',
  'runners/gitleaksScan.ts|gitleaks': 'gitleaks',
  'tools/scanSast.ts|bandit': 'bandit',
  // The --ini a caller passes (scan_sast's, the whole-project run's) is named by that caller, in tools/scanSast.ts.
  'runners/fileBatchScan.ts|bandit': 'reads none here: explicit file targets — Bandit looks for a .bandit only below a directory target',
  'tools/scanContainers.ts|hadolint': 'hadolint',
  'tools/scanIac.ts|zizmor': 'zizmor',
  'tools/scanIac.ts|actionlint': 'actionlint',
  'tools/depsAudit.ts|npm': 'npm',
  'tools/depsAudit.ts|dotnet': 'dotnet',
  'tools/depsAudit.ts|pip-audit': 'pip-audit',
  'tools/scanSast.ts|dotnet': 'dotnet-analyzers',
  'tools/scanSast.ts|docker': 'none',
  'surface/scanSemgrep.ts|docker': 'none',
  'tools/qualityCheck.ts|ruff': 'ruff',
  'tools/qualityCheck.ts|jscpd': 'jscpd',
  'tools/qualityCheck.ts|radon': 'radon',
  'tools/qualityCheck.ts|staticcheck': 'staticcheck',
  'runners/syftRun.ts|syft': 'none',
  'tools/scanWordpress.ts|phpcs': 'none',
  'tools/wpVulnCheck.ts|wpscan': 'none',
  'runners/cosignCheck.ts|cosign': 'none',
  'tools/perfCheck.ts|lighthouse': 'none',
  'tools/perfCheck.ts|k6': 'none',
  'tools/checkToolchain.ts|docker': 'not a scanner: a version probe',
  'tools/checkToolchain.ts|node': 'not a scanner: a version probe',
  'tools/checkToolchain.ts|python': 'not a scanner: a version probe',
  'tools/checkToolchain.ts|python3': 'not a scanner: a version probe',
  'tools/wpAudit.ts|wp': 'not a scanner: WP-CLI reads the WordPress install, not the repository',
  'tools/wpAudit.ts|Checksum_Core_Command': 'not a scanner: a WP-CLI class name in its output, not a spawn',
  'tools/wpCronAudit.ts|wp': 'not a scanner: WP-CLI reads the WordPress install',
  'tools/wpPluginCheck.ts|wp': 'not a scanner: WP-CLI reads the WordPress install',
  'tools/wpVulnCheck.ts|wp': 'not a scanner: WP-CLI reads the WordPress install',
  'tools/precommitInstall.ts|pre-commit': 'not a scanner: installs the hooks',
  'tools/createGithubIssues.ts|gh': 'not a scanner: GitHub CLI',
  // git itself is spawned as GIT_COMMAND, never a literal — test/unit/platform/gitSpawnSites.test.ts.
  'fixpr/pr.ts|gh': 'not a scanner: GitHub CLI',
  'fixpr/testEnv.ts|npm': 'not a scanner: installs a worktree for the project test command',
  'fixpr/testCommand.ts|npm': 'not a scanner: the project test command',
  'fixpr/testCommand.ts|cargo': 'not a scanner: the project test command',
  'fixpr/testCommand.ts|go': 'not a scanner: the project test command',
  'fixpr/testCommand.ts|pytest': 'not a scanner: the project test command',
  'hostsetup/mcpConfig.ts|node': 'not a scanner: an MCP host entry',
};

/** Files skipped whole: the toolchain installer and the shell probe start no scan. */
const NOT_SCANNING_FILES = new Set(['runners/installCatalog.ts', 'platform/shellProbe.ts']);

const SPAWN = /\b(?:command|binary):\s*'([A-Za-z0-9_.-]+)'/g;

function spawnsInSrc(): Array<{ file: string; command: string }> {
  const out: Array<{ file: string; command: string }> = [];
  for (const path of tsFiles(SRC)) {
    const file = relative(SRC, path).split('\\').join('/');
    if (NOT_SCANNING_FILES.has(file)) continue;
    const text = readFileSync(path, 'utf8');
    for (const m of text.matchAll(SPAWN)) {
      const command = m[1];
      if (command !== undefined && !out.some((s) => s.file === file && s.command === command)) out.push({ file, command });
    }
  }
  return out;
}

/** How the file that spawns `runner` shows it names what the runner read. */
function namesIt(text: string, runner: RepoConfigRunner): boolean {
  if (runner === 'trivy') return true; // every caller: see the trivy test below
  return /\b(?:nameRepoConfig|honouredRootFiles|honouredFiles|honouredHandedFiles)\(/.test(text) && text.includes(`'${runner}'`);
}

describe('every scanner spawned in src/ is accounted for', () => {
  const spawns = spawnsInSrc();

  it('each spawn is classified, and a scanner that reads none says why', () => {
    const unclassified = spawns.filter((s) => SPAWNS[`${s.file}|${s.command}`] === undefined).map((s) => `${s.file}|${s.command}`);
    expect(unclassified).toEqual([]);
    for (const [key, verdict] of Object.entries(SPAWNS)) {
      if (verdict === 'none') expect(NO_REPO_CONFIG[key.split('|')[1] ?? ''], key).toBeDefined();
    }
  });

  it('the file that spawns a runner with configuration names it', () => {
    const silent: string[] = [];
    for (const s of spawns) {
      const verdict = SPAWNS[`${s.file}|${s.command}`];
      if (verdict === undefined || verdict === 'none' || verdict.startsWith('not a scanner') || verdict.startsWith('reads none here')) {
        continue;
      }
      const runner = verdict as RepoConfigRunner;
      if (!namesIt(readFileSync(join(SRC, s.file), 'utf8'), runner)) silent.push(`${s.file}: ${runner}`);
    }
    expect(silent).toEqual([]);
  });

  it('Trivy: every caller that honours .trivyignore names it', () => {
    const silent = tsFiles(SRC)
      .map((path) => ({ file: relative(SRC, path).split('\\').join('/'), text: readFileSync(path, 'utf8') }))
      .filter(({ text }) => /\bignoreFrom:/.test(text))
      .filter(({ text }) => !/\b(?:withHonoured|judgeTrivyFs|judgeTrivyConfig)\(/.test(text))
      .map(({ file }) => file);
    expect(silent).toEqual([]);
  });

  it('Semgrep and ESLint, spawned through helpers, name theirs too', () => {
    const gaps = readFileSync(join(SRC, 'runners/semgrepCoverageGaps.ts'), 'utf8');
    expect(gaps).toMatch(/honouredFiles\(projectPath, 'semgrep'\)/);
    const quality = readFileSync(join(SRC, 'tools/qualityCheck.ts'), 'utf8');
    expect(quality).toMatch(/QUALITY_RUNNERS[^=]*=\s*\[[^\]]*'eslint'/);
  });

  it('no REPO_CONFIG entry is stale: each runner is spawned somewhere (the factory applies .guardianignore)', () => {
    const used = new Set(Object.values(SPAWNS));
    const stale = RUNNERS.filter((r) => r !== 'guardian' && r !== 'semgrep' && r !== 'eslint' && !used.has(r));
    expect(stale).toEqual([]);
  });
});
