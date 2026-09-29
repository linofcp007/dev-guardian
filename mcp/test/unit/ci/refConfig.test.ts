/**
 * `ci/refConfig.ts` against real repositories: what `--baseline-ref` and
 * `--rules-ref` read from the ref, what they copy, and which of the tree's
 * configuration changes they name. No scanner runs here — `ciRefGate.test.ts`
 * (e2e) runs the gate itself.
 */

import { execa } from 'execa';
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, describe, expect, it, vi } from 'vitest';

import {
  CiRefError,
  configDifferences,
  copyConfigFromRef,
  FROM_REF_FILES,
  GATE_CONFIG,
  readAtRef,
  readBaselineAtRef,
  resolveCiRef,
} from '../../../src/ci/refConfig.js';
import { languagesFromFilesAsync } from '../../../src/frameworks/projectLanguages.js';
import { REPO_CONFIG, type RepoConfigRunner } from '../../../src/runners/repoConfig.js';
import { cleanupTempDirs, makeTempDir } from '../../helpers/tempDir.js';

/**
 * Real repositories: every test spawns git a dozen or more times, ~150 ms a
 * spawn on an idle Windows machine. A file-level ceiling for a loaded run.
 */
vi.setConfig({ testTimeout: 60_000 });

afterAll(cleanupTempDirs);

async function git(cwd: string, ...args: string[]): Promise<string> {
  const r = await execa('git', args, { cwd });
  return r.stdout;
}

async function newRepo(prefix: string): Promise<string> {
  const dir = makeTempDir(prefix);
  await git(dir, 'init', '-q');
  await git(dir, 'config', 'user.email', 'guardian-test@example.com');
  await git(dir, 'config', 'user.name', 'Guardian Test');
  await git(dir, 'config', 'commit.gpgsign', 'false');
  await git(dir, 'config', 'core.autocrlf', 'false');
  return dir;
}

function write(root: string, rel: string, text: string): void {
  const path = join(root, ...rel.split('/'));
  mkdirSync(join(path, '..'), { recursive: true });
  writeFileSync(path, text);
}

async function commitAll(dir: string, message: string): Promise<string> {
  await git(dir, 'add', '-A');
  await git(dir, 'commit', '-q', '-m', message);
  return (await git(dir, 'rev-parse', 'HEAD')).trim();
}

/** Adds a symbolic link to the index (no file-system link needed: Windows runs this too). */
async function commitLink(dir: string, rel: string, target: string): Promise<string> {
  const blob = (await execa('git', ['hash-object', '-w', '--stdin'], { cwd: dir, input: target })).stdout.trim();
  await git(dir, 'update-index', '--add', '--cacheinfo', `120000,${blob},${rel}`);
  await git(dir, 'commit', '-q', '-m', `link ${rel}`);
  return (await git(dir, 'rev-parse', 'HEAD')).trim();
}

const BASELINE = (entries: unknown[]): string =>
  `${JSON.stringify({ version: 1, generated_at: '2026-09-29T00:00:00.000Z', entries }, null, 2)}\n`;

describe('resolveCiRef', () => {
  it('resolves a ref to its commit, and the project to its place in the repository', async () => {
    const repo = await newRepo('refcfg-resolve-');
    write(repo, 'sub/a.txt', 'a\n');
    const base = await commitAll(repo, 'base');
    await expect(resolveCiRef(repo, 'HEAD', '--baseline-ref')).resolves.toEqual({ ref: 'HEAD', commit: base, prefix: '' });
    await expect(resolveCiRef(join(repo, 'sub'), base.slice(0, 10), '--rules-ref')).resolves.toEqual({
      ref: base.slice(0, 10),
      commit: base,
      prefix: 'sub/',
    });
  });

  it('a ref that names no commit is an error naming the flag and what to fetch — never "no baseline"', async () => {
    const repo = await newRepo('refcfg-noref-');
    write(repo, 'a.txt', 'a\n');
    await commitAll(repo, 'base');
    const e = await resolveCiRef(repo, 'origin/main', '--baseline-ref').catch((err: unknown) => err);
    expect(e).toBeInstanceOf(CiRefError);
    expect(String(e)).toMatch(/--baseline-ref origin\/main: names no commit/);
    expect(String(e)).toMatch(/fetch it first/);
  });

  it('refuses a ref spelt like an option, an empty one, and a project outside git', async () => {
    const repo = await newRepo('refcfg-opt-');
    write(repo, 'a.txt', 'a\n');
    await commitAll(repo, 'base');
    await expect(resolveCiRef(repo, '--output=x', '--rules-ref')).rejects.toThrow(/takes a git ref, not an option/);
    await expect(resolveCiRef(repo, '', '--rules-ref')).rejects.toThrow(/requires a value/);
    const plain = makeTempDir('refcfg-plain-');
    await expect(resolveCiRef(plain, 'HEAD', '--baseline-ref')).rejects.toThrow(/not inside a git work tree/);
  });
});

describe('readBaselineAtRef', () => {
  it("reads the ref's baseline, never the tree's — and says the tree's differs", async () => {
    const repo = await newRepo('refcfg-baseline-');
    write(repo, '.guardian/baseline.json', BASELINE([]));
    const base = await commitAll(repo, 'base');
    // The pull request adopts its own findings.
    write(repo, '.guardian/baseline.json', BASELINE([{ fingerprint: 'f', severity: 'high', title: 'mine', added: 'x' }]));
    await commitAll(repo, 'pr');
    const at = await resolveCiRef(repo, base, '--baseline-ref');
    const read = await readBaselineAtRef(repo, at);
    expect(read.text).toBe(BASELINE([]));
    expect(read.treeDiffers).toBe(true);
  });

  it('none at the ref is no baseline (null), whatever the tree holds — committed or not', async () => {
    const repo = await newRepo('refcfg-nobaseline-');
    write(repo, 'a.txt', 'a\n');
    const base = await commitAll(repo, 'base');
    write(repo, '.guardian/baseline.json', BASELINE([]));
    const at = await resolveCiRef(repo, base, '--baseline-ref');
    // Untracked in the tree: still "differs", still not read.
    expect(await readBaselineAtRef(repo, at)).toEqual({ text: null, treeDiffers: true });
  });

  it('an unchanged baseline does not differ', async () => {
    const repo = await newRepo('refcfg-same-');
    write(repo, '.guardian/baseline.json', BASELINE([]));
    const base = await commitAll(repo, 'base');
    const read = await readBaselineAtRef(repo, await resolveCiRef(repo, base, '--baseline-ref'));
    expect(read).toEqual({ text: BASELINE([]), treeDiffers: false });
  });

  it("a project in a subdirectory reads its own .guardian/baseline.json at the ref, not the repository root's", async () => {
    const repo = await newRepo('refcfg-sub-');
    write(repo, '.guardian/baseline.json', BASELINE([{ fingerprint: 'root', severity: 'low', title: 'r', added: 'x' }]));
    write(repo, 'api/.guardian/baseline.json', BASELINE([]));
    const base = await commitAll(repo, 'base');
    const read = await readBaselineAtRef(join(repo, 'api'), await resolveCiRef(join(repo, 'api'), base, '--baseline-ref'));
    expect(read.text).toBe(BASELINE([]));
  });
});

describe('readAtRef', () => {
  it('refuses a file over the limit before reading it', async () => {
    const repo = await newRepo('refcfg-big-');
    write(repo, '.semgrep.yml', 'x'.repeat(2048));
    const base = await commitAll(repo, 'base');
    const at = await resolveCiRef(repo, base, '--rules-ref');
    await expect(readAtRef(repo, at, '.semgrep.yml', 1024)).rejects.toThrow(/\.semgrep\.yml at .* is 2048 bytes, over the 1024-byte limit/);
  });

  it('follows a symbolic link once inside the repository, and refuses one that leaves it', async () => {
    const repo = await newRepo('refcfg-link-');
    write(repo, 'config/semgrep.yml', 'rules: []\n');
    await commitAll(repo, 'base');
    const inside = await commitLink(repo, '.semgrep.yml', 'config/semgrep.yml');
    expect((await readAtRef(repo, await resolveCiRef(repo, inside, '--rules-ref'), '.semgrep.yml', 1024))?.toString()).toBe(
      'rules: []\n',
    );
    const outside = await commitLink(repo, '.trivyignore', '../../etc/passwd');
    await expect(readAtRef(repo, await resolveCiRef(repo, outside, '--rules-ref'), '.trivyignore', 1024)).rejects.toThrow(
      /symbolic link out of the repository/,
    );
  });

  it('refuses a directory where a file is expected', async () => {
    const repo = await newRepo('refcfg-dir-');
    write(repo, '.bandit/x', 'x\n');
    const base = await commitAll(repo, 'base');
    await expect(readAtRef(repo, await resolveCiRef(repo, base, '--rules-ref'), '.bandit', 1024)).rejects.toThrow(/not a file/);
  });
});

describe('copyConfigFromRef', () => {
  it("copies the ref's rules and ignore files — the tree's changes, additions and deletions are not in the copy", async () => {
    const repo = await newRepo('refcfg-copy-');
    write(repo, '.semgrep.yml', 'rules:\n  - id: base-rule\n');
    write(repo, '.trivyignore', 'CVE-BASE\n');
    write(repo, '.dev-guardian/configs.json', JSON.stringify({
      schema_version: 1,
      entries: [
        { target: 'rules/team.yml', source: 'semgrep/base.yml', plugin_version: '3.0.0', source_sha256: 'a', target_sha256: 'b', recorded_at: 'x', provenance: 'copied' },
      ],
    }));
    write(repo, 'rules/team.yml', 'rules:\n  - id: team-rule\n');
    const base = await commitAll(repo, 'base');
    // The pull request: weakens the rules, adds an ignore file, drops .trivyignore.
    write(repo, '.semgrep.yml', 'rules:\n  - id: harmless\n');
    write(repo, 'rules/team.yml', 'rules:\n  - id: harmless-too\n');
    write(repo, '.guardianignore', 'src/\n');
    rmSync(join(repo, '.trivyignore'));
    await commitAll(repo, 'pr');

    const into = join(makeTempDir('refcfg-into-'), 'copy');
    const copy = await copyConfigFromRef(repo, await resolveCiRef(repo, base, '--rules-ref'), into);
    expect(copy.root).toBe(into);
    expect([...copy.copied].sort()).toEqual(['.dev-guardian/configs.json', '.semgrep.yml', '.trivyignore', 'rules/team.yml']);
    expect([...copy.absent].sort()).toEqual(['.bandit', '.guardianignore', '.semgrep.yaml']);
    expect(readFileSync(join(into, '.semgrep.yml'), 'utf8')).toContain('base-rule');
    expect(readFileSync(join(into, 'rules', 'team.yml'), 'utf8')).toContain('team-rule');
    expect(readFileSync(join(into, '.trivyignore'), 'utf8')).toBe('CVE-BASE\n');
    expect(existsSync(join(into, '.guardianignore'))).toBe(false);
  });

  it('a manifest at the ref naming rules outside the project stops the run, never reads there', async () => {
    const repo = await newRepo('refcfg-escape-');
    write(repo, '.dev-guardian/configs.json', JSON.stringify({
      schema_version: 1,
      entries: [
        { target: '../outside.yml', source: 'semgrep/base.yml', plugin_version: '3.0.0', source_sha256: 'a', target_sha256: 'b', recorded_at: 'x', provenance: 'copied' },
      ],
    }));
    const base = await commitAll(repo, 'base');
    const into = join(makeTempDir('refcfg-into-'), 'copy');
    await expect(copyConfigFromRef(repo, await resolveCiRef(repo, base, '--rules-ref'), into)).rejects.toThrow(
      /records the Semgrep rules '\.\.\/outside\.yml', which is not a path inside the project/,
    );
  });
});

describe('configDifferences', () => {
  it('names each configuration file the tree changes, and which copy the scan read', async () => {
    const repo = await newRepo('refcfg-diff-');
    write(repo, '.semgrep.yml', 'rules:\n  - id: base-rule\n');
    write(repo, 'src/.semgrepignore', 'vendor/\n');
    write(repo, '.gitleaks.toml', '[extend]\nuseDefault = true\n');
    write(repo, 'README.md', '# x\n');
    const base = await commitAll(repo, 'base');
    write(repo, '.semgrep.yml', 'rules:\n  - id: harmless\n'); // from the ref: not applied
    write(repo, 'src/.semgrepignore', 'vendor/\nlib/\n'); // the tree's: applied
    rmSync(join(repo, '.gitleaks.toml')); // the tree's: applied
    write(repo, 'README.md', '# changed, not configuration\n');
    await commitAll(repo, 'pr');
    write(repo, '.gitleaksignore', 'abc:leak.txt:aws-access-token:1\n'); // untracked, still read by gitleaks

    const at = await resolveCiRef(repo, base, '--rules-ref');
    const copy = await copyConfigFromRef(repo, at, join(makeTempDir('refcfg-into-'), 'copy'));
    expect(await configDifferences(repo, at, copy)).toEqual([
      { path: '.gitleaks.toml', change: 'deleted', applied: 'tree', read_by: ['gitleaks'] },
      { path: '.gitleaksignore', change: 'added', applied: 'tree', read_by: ['gitleaks'] },
      { path: '.semgrep.yml', change: 'modified', applied: 'ref', read_by: ['semgrep'] },
      { path: 'src/.semgrepignore', change: 'modified', applied: 'tree', read_by: ['semgrep'] },
    ]);
  });

  it('a .gitleaksignore git ignores is still read by gitleaks, so it is still named', async () => {
    const repo = await newRepo('refcfg-ignored-');
    write(repo, '.gitignore', '.gitleaksignore\n');
    write(repo, 'README.md', '# x\n');
    const base = await commitAll(repo, 'base');
    // Present, untracked and ignored: neither `git diff` nor the untracked listing shows it.
    write(repo, '.gitleaksignore', 'abc:leak.txt:aws-access-token:1\n');
    const at = await resolveCiRef(repo, base, '--rules-ref');
    const copy = await copyConfigFromRef(repo, at, join(makeTempDir('refcfg-into-'), 'copy'));
    expect(await configDifferences(repo, at, copy)).toEqual([
      { path: '.gitleaksignore', change: 'added', applied: 'tree', read_by: ['gitleaks'] },
    ]);
  });

  it('nothing changed: nothing named', async () => {
    const repo = await newRepo('refcfg-nodiff-');
    write(repo, '.semgrep.yml', 'rules: []\n');
    const base = await commitAll(repo, 'base');
    const at = await resolveCiRef(repo, base, '--rules-ref');
    const copy = await copyConfigFromRef(repo, at, join(makeTempDir('refcfg-into-'), 'copy'));
    expect(await configDifferences(repo, at, copy)).toEqual([]);
  });
});

describe("the language report reads the ref's .guardianignore under --rules-ref", () => {
  it("a language only an excluded tree holds counts again when the ref's copy does not exclude it", async () => {
    const tree = makeTempDir('refcfg-langs-');
    write(tree, 'app/main.py', 'print(1)\n');
    write(tree, 'web/index.js', 'module.exports = 1;\n');
    // The pull request's own .guardianignore hides its Python.
    write(tree, '.guardianignore', 'app/\n');
    const own = await languagesFromFilesAsync(tree, { useGit: false });
    expect(own.languages).not.toContain('python');
    const fromRef = await languagesFromFilesAsync(tree, { useGit: false, guardianIgnoreFrom: makeTempDir('refcfg-langs-ref-') });
    expect(fromRef.languages).toContain('python');
    expect(fromRef.languages).toContain('javascript');
  });
});

describe('GATE_CONFIG is complete by construction', () => {
  it('classifies every runner of REPO_CONFIG', () => {
    expect(Object.keys(GATE_CONFIG).sort()).toEqual(Object.keys(REPO_CONFIG).sort());
  });

  it("the runners read from the ref read exactly files FROM_REF_FILES copies", () => {
    for (const [runner, where] of Object.entries(GATE_CONFIG) as Array<[RepoConfigRunner, string]>) {
      if (where !== 'ref') continue;
      for (const spec of REPO_CONFIG[runner]) {
        expect(spec.nested, `${runner}: ${spec.file}`).not.toBe(true);
        expect(FROM_REF_FILES, `${runner}: ${spec.file}`).toContain(spec.file);
      }
    }
  });

  it('no gate runner reads a file only when its text matches (`when`): a difference is named by path alone', () => {
    for (const [runner, where] of Object.entries(GATE_CONFIG) as Array<[RepoConfigRunner, string]>) {
      if (where === 'not_in_gate') continue;
      for (const spec of REPO_CONFIG[runner]) expect(spec.when, `${runner}: ${spec.file}`).toBeUndefined();
    }
  });
});
