/**
 * Every process dev-guardian starts, and how git inside it is kept from
 * running what a scanned repository's own configuration names (review 3.0,
 * W2E-git; `platform/gitSafety.ts`).
 *
 * Git is started in exactly two ways: by `platform/gitSafety.ts` itself
 * (`execGit`, `execGitSync` — the probe, then git with the overrides), or by
 * `runners/processRunner.ts#runProcess`, which hardens EVERY child it starts —
 * a git named `GIT_COMMAND`, and a scanner or package manager that runs git
 * on its own. This test fails when:
 *
 *   - a raw spawn primitive (`execa`, `spawn`, `spawnSync`, `execFile`,
 *     `execFileSync`, `execSync`, `fork`) appears in a file, or in a number,
 *     `SITES` does not name — each one is classified with the reason its
 *     child is not a git process in a scanned project, or is hardened where
 *     it stands;
 *   - git is named as the command of a raw spawn anywhere but the helper, in
 *     `mcp/src`, `cli/` or `hooks/`;
 *   - a `runProcess`-shaped spawn spells git as a literal instead of
 *     `GIT_COMMAND`;
 *   - `gitHardening: false` appears anywhere but the one place that runs the
 *     project's own code by design, or `'except-hooks-path'` anywhere but the
 *     one child whose job is installing hooks.
 *
 * Counted per file, not per line, so an unrelated edit does not move it; a
 * converted or deleted site must leave the list too.
 */
import { readdirSync, readFileSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { buildSemgrepDockerArgs, DEFAULT_SEMGREP_IMAGE } from '../../../src/runners/dockerScanner.js';

const REPO = resolve(fileURLToPath(new URL('.', import.meta.url)), '..', '..', '..', '..');

type Kind =
  /** The hardening itself. */
  | 'helper'
  /** Hardened where it stands: `applyGitSafety` on the child's environment. */
  | 'hardened'
  /** Starts no git and reads no scanned project: a version probe, a process-table query, an installer. */
  | 'no-repository'
  /** Runs the project's own code (or a program its configuration names) BY DESIGN, at the user's request. */
  | 'project-code';

const SITES: Readonly<Record<string, { count: number; kind: Kind; reason: string }>> = {
  'mcp/src/platform/gitSafety.ts': {
    count: 4,
    kind: 'helper',
    reason:
      'the configuration probe and the submodule listing (sync, and async through one spawn helper), ' +
      'and git itself with the overrides applied',
  },
  'mcp/src/runners/processRunner.ts': {
    count: 1,
    kind: 'hardened',
    reason: 'runProcess: applyGitSafety on every child, for its cwd and gitRepos, unless gitHardening: false',
  },
  'mcp/src/tools/depsUpdatePlan.ts': {
    count: 1,
    kind: 'hardened',
    reason: 'execPackageManager: npm/pnpm/composer/cargo/go/bundle/dotnet in the project, applyGitSafety for it',
  },
  'mcp/src/runners/windowsTreeKill.ts': {
    count: 3,
    kind: 'no-repository',
    reason: "Git Bash's ps and grep over process tables, and taskkill: no git, no project",
  },
  'mcp/src/runners/trivyRun.ts': { count: 1, kind: 'no-repository', reason: '`trivy --version`: reads no project' },
  'mcp/src/platform/shellProbe.ts': { count: 1, kind: 'no-repository', reason: "a shell's own version probe" },
  'mcp/src/mcpaudit/launch.ts': { count: 1, kind: 'no-repository', reason: '`node -e statSync`: is a command path a file' },
  'mcp/src/skillaudit/ingest.ts': {
    count: 2,
    kind: 'no-repository',
    reason: 'tar / unzip extract a skill archive into a temp directory; its git clone goes through execGit',
  },
  'mcp/src/tools/installToolchain.ts': { count: 2, kind: 'no-repository', reason: '`wsl -l`, `pipx ensurepath`: the installer, in no project' },
  'mcp/src/ci/appRunner.ts': {
    count: 2,
    kind: 'project-code',
    reason: "the project's own application, started for the DAST gate — its code runs by design; taskkill stops that tree",
  },
  'mcp/src/mcpaudit/stdioTransport.ts': {
    count: 1,
    kind: 'project-code',
    reason: 'the MCP server an audited configuration names, launched for the probe the user asked for',
  },
  'cli/dev-guardian.mjs': { count: 1, kind: 'no-repository', reason: 'opens the dashboard URL in a browser' },
};

/** The one `gitHardening: false`, and why. */
const UNHARDENED: Readonly<Record<string, { count: number; reason: string }>> = {
  'mcp/src/fixpr/verify.ts': {
    count: 2,
    reason: "create_fix_pr's test command (worktree and base tree): the project's own code, whose own tests use git as they will",
  },
};

/** The one `gitHardening: 'except-hooks-path'`, and why. */
const EXCEPT_HOOKS_PATH: Readonly<Record<string, { count: number; reason: string }>> = {
  'mcp/src/tools/precommitInstall.ts': {
    count: 2,
    reason:
      '`pre-commit install` puts hooks where git says they go (its job) and refuses with core.hooksPath set; ' +
      'its git calls are rev-parse and `config core.hooksPath` — no index write, no hook (measured, 4.6.0)',
  },
};

function files(dir: string, ext: RegExp): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((e) => {
    const abs = join(dir, e.name);
    if (e.isDirectory()) return files(abs, ext);
    return ext.test(e.name) ? [abs] : [];
  });
}

const SOURCES: Array<{ rel: string; text: string }> = [
  ...files(join(REPO, 'mcp', 'src'), /\.ts$/),
  ...files(join(REPO, 'cli'), /\.mjs$/),
  ...files(join(REPO, 'hooks'), /\.mjs$/),
].map((abs) => ({ rel: relative(REPO, abs).split('\\').join('/'), text: readFileSync(abs, 'utf8') }));

/** The text with comments blanked (line and block), so a spawn mentioned in prose is not one. */
function code(text: string): string {
  return text.replace(/\/\*[\s\S]*?\*\//g, (m) => m.replace(/[^\n]/g, ' ')).replace(/(^|[^:'"`])\/\/.*$/gm, '$1');
}

/** A call to a raw spawn primitive — not a method (`.spawn(`), not `thread::spawn(`. */
const RAW_SPAWN = /(?<![.\w:])(?:execa|execaSync|spawn|spawnSync|execFile|execFileSync|execSync|fork)\(/g;
/** A raw spawn whose command is git: `'git'`, or an expression that falls back to it (`opts.git ?? 'git'`). */
const RAW_GIT_SPAWN = /(?<![.\w:])(?:execa|execaSync|spawn|spawnSync|execFile|execFileSync|execSync|fork)\(\s*(?:[^,()]*\?\?\s*)?['"`]git(?:\.exe)?['"`]/;
/** A runProcess-shaped spawn spelling git as a literal. */
const LITERAL_GIT_COMMAND = /\bcommand:\s*['"`]git(?:\.exe)?['"`]/;

function count(text: string, re: RegExp): number {
  return [...code(text).matchAll(re)].length;
}

describe('every raw spawn is classified (platform/gitSafety.ts)', () => {
  it('a file spawns raw exactly as often as SITES says, and no other file does', () => {
    const found: Record<string, number> = {};
    for (const { rel, text } of SOURCES) {
      const n = count(text, RAW_SPAWN);
      if (n > 0) found[rel] = n;
    }
    const expected = Object.fromEntries(Object.entries(SITES).map(([rel, s]) => [rel, s.count]));
    expect(found).toEqual(expected);
  });

  it('git is spawned raw only by the helper', () => {
    const offenders = SOURCES.filter(({ rel }) => rel !== 'mcp/src/platform/gitSafety.ts')
      .filter(({ text }) => RAW_GIT_SPAWN.test(code(text)))
      .map(({ rel }) => rel);
    expect(offenders).toEqual([]);
  });

  it('a git spawned through runProcess is named GIT_COMMAND', () => {
    const offenders = SOURCES.filter(({ text }) => LITERAL_GIT_COMMAND.test(code(text))).map(({ rel }) => rel);
    expect(offenders).toEqual([]);
  });

  it('gitHardening: false appears only where the project runs its own code', () => {
    const found: Record<string, number> = {};
    for (const { rel, text } of SOURCES) {
      const n = count(text, /\bgitHardening:\s*false\b/g);
      if (n > 0) found[rel] = n;
    }
    expect(found).toEqual(Object.fromEntries(Object.entries(UNHARDENED).map(([rel, s]) => [rel, s.count])));
  });

  it("gitHardening: 'except-hooks-path' appears only where the child's job is installing hooks", () => {
    const found: Record<string, number> = {};
    for (const { rel, text } of SOURCES) {
      const n = count(text, /\bgitHardening:\s*'except-hooks-path'/g);
      if (n > 0) found[rel] = n;
    }
    expect(found).toEqual(Object.fromEntries(Object.entries(EXCEPT_HOOKS_PATH).map(([rel, s]) => [rel, s.count])));
  });

  it('the hardened sites harden: runProcess and execPackageManager apply the overrides to the child they start', () => {
    const src = (rel: string): string => code(SOURCES.find((s) => s.rel === rel)?.text ?? '');
    const runner = src('mcp/src/runners/processRunner.ts');
    expect(runner).toMatch(/gitSafetyFor\(\[options\.cwd, \.\.\.\(options\.gitRepos \?\? \[\]\)\]/);
    expect(runner).toMatch(/env = applyGitSafety\(safety, base\)/);
    const pm = src('mcp/src/tools/depsUpdatePlan.ts');
    expect(pm).toMatch(/const env = applyGitSafety\(safety, base\);/);
    expect(pm).toMatch(/return execa\(commandFor\(command, env\), args, \{[^}]*\benv, extendEnv: false/);
  });

  it('the hook and the CLI run git only through the helper they import from dist', () => {
    const hook = SOURCES.find((s) => s.rel === 'hooks/guardian-hook.mjs')?.text ?? '';
    expect(hook).toMatch(/import\(pathToFileURL\(join\(DIST_PLATFORM, 'gitSafety\.js'\)\)\.href\)/);
    const cli = SOURCES.find((s) => s.rel === 'cli/dev-guardian.mjs')?.text ?? '';
    expect(cli).toMatch(/import \{ execGitSync \} from '\.\.\/mcp\/dist\/platform\/gitSafety\.js'/);
  });

  it('every reason is written down', () => {
    for (const s of [...Object.values(SITES), ...Object.values(UNHARDENED), ...Object.values(EXCEPT_HOOKS_PATH)]) {
      expect(s.reason.length).toBeGreaterThan(20);
    }
  });
});

describe('the patterns catch what they are for (positive controls)', () => {
  it('RAW_SPAWN', () => {
    expect(count("const r = await execa('npm', ['ci']);", RAW_SPAWN)).toBe(1);
    expect(count('spawnSync(opts.git ?? GIT_COMMAND, args)', RAW_SPAWN)).toBe(1);
    expect(count('child.spawn(x); thread::spawn(f); re.exec(s)', RAW_SPAWN)).toBe(0);
    expect(count('// execa(\'git\') in a comment\n/* spawn( */', RAW_SPAWN)).toBe(0);
  });
  it('RAW_GIT_SPAWN', () => {
    expect(RAW_GIT_SPAWN.test("execa('git', ['status'])")).toBe(true);
    expect(RAW_GIT_SPAWN.test("spawnSync(\n    opts.git ?? 'git',\n    ['ls-files'])")).toBe(true);
    expect(RAW_GIT_SPAWN.test("execFileSync('git.exe', [])")).toBe(true);
    expect(RAW_GIT_SPAWN.test("execa('gitleaks', ['detect'])")).toBe(false);
    expect(RAW_GIT_SPAWN.test('spawnSync(GIT_COMMAND, args)')).toBe(false);
  });
  it('LITERAL_GIT_COMMAND', () => {
    expect(LITERAL_GIT_COMMAND.test("run({ command: 'git', args })")).toBe(true);
    expect(LITERAL_GIT_COMMAND.test("run({ command: 'gitleaks', args })")).toBe(false);
    expect(LITERAL_GIT_COMMAND.test('run({ command: GIT_COMMAND, args })')).toBe(false);
  });
});

describe('a git inside the Docker Semgrep fallback gets the same overrides', () => {
  it('the static layer by default, with a hooks path that exists in no container, before the image', () => {
    const args = buildSemgrepDockerArgs({ projectPath: '/p', outFileHost: '/p/out.json' });
    const count = args.indexOf('GIT_CONFIG_COUNT=7');
    expect(count).toBeGreaterThan(0);
    expect(args[count - 1]).toBe('-e');
    expect(count).toBeLessThan(args.indexOf(DEFAULT_SEMGREP_IMAGE));
    expect(args).toContain('GIT_CONFIG_VALUE_1=/dev/null/no-git-hooks');
    expect(args).toContain('GIT_CONFIG_VALUE_0=false');
  });
});
