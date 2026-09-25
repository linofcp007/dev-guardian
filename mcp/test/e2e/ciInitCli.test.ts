/**
 * End-to-end tests of `cli/dev-guardian.mjs ci-init` (Task 21), invoked as a
 * REAL SUBPROCESS — same pattern as `mcpConfigCli.test.ts`.
 *
 * `ci-init` writes a CI pipeline for the PROJECT BEING SCANNED, never for
 * this repo (Global Constraint 7 — no GitHub Actions here). Every test
 * below passes `--project <a throwaway temp dir>`, never the repo root, so
 * a regression that accidentally targeted this repo would show up as a
 * wrong `--project` value, not as a file landing in the real tree.
 */

import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parse as parseYaml } from 'yaml';
import { afterEach, describe, expect, it } from 'vitest';

const REPO_ROOT = resolve(fileURLToPath(new URL('../../..', import.meta.url)));
const CLI = resolve(REPO_ROOT, 'cli', 'dev-guardian.mjs');
const TIMEOUT_MS = 15_000;

const tempDirs: string[] = [];
function makeProject(): string {
  const dir = mkdtempSync(join(tmpdir(), 'guardian-ci-init-'));
  tempDirs.push(dir);
  return dir;
}
afterEach(() => {
  for (const d of tempDirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

function runCli(args: string[]) {
  const r = spawnSync(process.execPath, [CLI, ...args], {
    encoding: 'utf8',
    env: { ...process.env, NO_COLOR: '1' },
    timeout: TIMEOUT_MS,
  });
  return { status: r.status, stdout: r.stdout ?? '', stderr: r.stderr ?? '' };
}

describe('ci-init: usage errors', () => {
  it('exits 1 on a missing target', () => {
    const project = makeProject();
    const r = runCli(['ci-init', '--project', project]);
    expect(r.status).toBe(1);
    expect(r.stderr).toMatch(/Missing or unknown ci-init target/);
  });

  it('exits 1 on an unknown target', () => {
    const project = makeProject();
    const r = runCli(['ci-init', 'jenkins', '--project', project]);
    expect(r.status).toBe(1);
    expect(r.stderr).toMatch(/unknown ci-init target: jenkins/);
  });

  it('--project with no value exits 3 with a clean usage error, never an uncaught TypeError', () => {
    const r = runCli(['ci-init', 'github', '--project']);
    expect(r.status).toBe(3);
    expect(r.stderr).toMatch(/--project requires a value/);
    expect(r.stderr).not.toMatch(/TypeError|ERR_INVALID_ARG_TYPE|at Object|at async/);
  });

  it('an unknown flag exits 3', () => {
    const project = makeProject();
    const r = runCli(['ci-init', 'github', '--project', project, '--bogus']);
    expect(r.status).toBe(3);
    expect(r.stderr).toMatch(/Unknown flag: --bogus/);
  });
});

describe('ci-init: refuses to target dev-guardian\'s own repository', () => {
  it('exits 3 and writes nothing when --project resolves to this repo', () => {
    const r = runCli(['ci-init', 'github', '--project', REPO_ROOT]);
    expect(r.status).toBe(3);
    expect(r.stderr).toMatch(/never for dev-guardian's own repository/);
    expect(existsSync(join(REPO_ROOT, '.github', 'workflows', 'dev-guardian.yml'))).toBe(false);
  });

  it('a subdirectory of this repo also refuses — containment, not mere equality', () => {
    // Regression: an earlier version of this check compared with `===`
    // alone, so `--project <repo>/mcp` passed straight through and
    // `--write` would have created `.github/workflows/dev-guardian.yml`
    // inside this repo's own tree — exactly what Global Constraint 7
    // forbids, one directory removed from the obvious case.
    const r = runCli(['ci-init', 'github', '--project', join(REPO_ROOT, 'mcp')]);
    expect(r.status).toBe(3);
    expect(r.stderr).toMatch(/never for dev-guardian's own repository/);
    expect(existsSync(join(REPO_ROOT, 'mcp', '.github', 'workflows', 'dev-guardian.yml'))).toBe(false);
  });

});

describe('ci-init: preview (no --write)', () => {
  it('prints the rendered pipeline to stdout and writes nothing', () => {
    const project = makeProject();
    const r = runCli(['ci-init', 'github', '--project', project]);
    expect(r.status).toBe(0);
    expect(r.stdout).toMatch(/name: dev-guardian/);
    expect(existsSync(join(project, '.github', 'workflows', 'dev-guardian.yml'))).toBe(false);
  });
});

describe('ci-init: --write / --force', () => {
  it('writes github -> .github/workflows/dev-guardian.yml', () => {
    const project = makeProject();
    const r = runCli(['ci-init', 'github', '--project', project, '--write']);
    expect(r.status).toBe(0);
    const outPath = join(project, '.github', 'workflows', 'dev-guardian.yml');
    expect(existsSync(outPath)).toBe(true);
    expect(r.stdout).toMatch(/Wrote github pipeline to/);
  });

  it('writes gitlab -> .gitlab-ci.yml', () => {
    const project = makeProject();
    const r = runCli(['ci-init', 'gitlab', '--project', project, '--write']);
    expect(r.status).toBe(0);
    expect(existsSync(join(project, '.gitlab-ci.yml'))).toBe(true);
  });

  it('writes bitbucket -> bitbucket-pipelines.yml', () => {
    const project = makeProject();
    const r = runCli(['ci-init', 'bitbucket', '--project', project, '--write']);
    expect(r.status).toBe(0);
    expect(existsSync(join(project, 'bitbucket-pipelines.yml'))).toBe(true);
  });

  it('refuses to overwrite an existing pipeline file without --force', () => {
    const project = makeProject();
    const first = runCli(['ci-init', 'github', '--project', project, '--write']);
    expect(first.status).toBe(0);
    const outPath = join(project, '.github', 'workflows', 'dev-guardian.yml');
    const before = readFileSync(outPath, 'utf8');

    const second = runCli(['ci-init', 'github', '--project', project, '--write']);
    expect(second.status).toBe(1);
    expect(second.stderr).toMatch(/refusing to overwrite existing pipeline file/);
    expect(readFileSync(outPath, 'utf8')).toBe(before); // untouched
  });

  it('--force overwrites an existing pipeline file', () => {
    const project = makeProject();
    runCli(['ci-init', 'github', '--project', project, '--write']);
    const outPath = join(project, '.github', 'workflows', 'dev-guardian.yml');

    const r = runCli(['ci-init', 'github', '--project', project, '--write', '--force']);
    expect(r.status).toBe(0);
    expect(existsSync(outPath)).toBe(true);
  });
});

describe('ci-init: generated pipelines are valid YAML with the pinned values substituted', () => {
  it.each(['github', 'gitlab', 'bitbucket'] as const)('%s: no unresolved {{PLACEHOLDER}} tokens, parses as YAML', (target) => {
    const project = makeProject();
    const r = runCli(['ci-init', target, '--project', project]);
    expect(r.status).toBe(0);
    expect(r.stdout).not.toMatch(/\{\{[A-Z0-9_]+\}\}/);
    // Strip this test's own leading "# <target> pipeline -> <path>" preview
    // banner and trailing "# Paste this..." line before parsing as YAML.
    const body = r.stdout.split('\n').slice(2, -2).join('\n');
    expect(() => parseYaml(body)).not.toThrow();
  });

  it('github: actions pinned by full 40-hex commit SHA, never a floating tag like @v7', () => {
    const project = makeProject();
    const r = runCli(['ci-init', 'github', '--project', project]);
    const shaLines = r.stdout.match(/uses: [^\s]+@([0-9a-f]{40})/g) ?? [];
    expect(shaLines.length).toBeGreaterThanOrEqual(3); // checkout, setup-node, upload-sarif
    expect(r.stdout).not.toMatch(/uses: actions\/checkout@v\d/);
    expect(r.stdout).not.toMatch(/uses: actions\/setup-node@v\d/);
  });

  it('every target pins Trivy/gitleaks/actionlint by version + sha256, and semgrep/zizmor by exact version', () => {
    for (const target of ['github', 'gitlab', 'bitbucket']) {
      const project = makeProject();
      const r = runCli(['ci-init', target, '--project', project]);
      expect(r.stdout, target).toMatch(/sha256sum -c -/);
      expect(r.stdout, target).toMatch(/semgrep==\d+\.\d+\.\d+/);
      expect(r.stdout, target).toMatch(/zizmor==\d+\.\d+\.\d+/);
    }
  });

  it('clones dev-guardian at a v-prefixed, quoted tag matching .claude-plugin/plugin.json, never `main`', () => {
    const plugin = JSON.parse(readFileSync(resolve(REPO_ROOT, '.claude-plugin', 'plugin.json'), 'utf8')) as {
      version: string;
    };
    const project = makeProject();
    const r = runCli(['ci-init', 'github', '--project', project]);
    expect(r.stdout).toContain(`--branch "v${plugin.version}"`);
    expect(r.stdout).not.toMatch(/--branch main\b/);
  });

  it.each(['github', 'gitlab', 'bitbucket'] as const)(
    '%s: dev-guardian is cloned OUTSIDE the scanned checkout, never into a subdirectory of it (would self-scan)',
    (target) => {
      const project = makeProject();
      const r = runCli(['ci-init', target, '--project', project]);
      const cloneLine = r.stdout.split('\n').find((l) => l.includes('git clone'));
      expect(cloneLine, target).toBeDefined();
      const destination = (cloneLine ?? '').trim().split(/\s+/).pop();
      // Regression: an earlier version cloned to a bare relative
      // "dev-guardian" directory (inside the checkout, since every step
      // here runs with the checkout as cwd), which `dev-guardian scan
      // --project .` would then scan as part of the target project —
      // including dev-guardian's OWN source, history and
      // deliberately-vulnerable test fixtures.
      expect(destination, target).not.toBe('dev-guardian');
      expect(destination, target).not.toBe('"dev-guardian"');
      expect(destination, target).toMatch(/\$(RUNNER_TEMP|DEV_GUARDIAN_HOME)"?$|\/tmp\/dev-guardian"?$/);
      // The scan step's --project stays "." (the checkout) regardless of
      // where the clone went — only the clone's OWN location moved.
      expect(r.stdout, target).toMatch(/scan[\s\S]{0,40}--project \./);
    },
  );
});

describe('ci-init: snapshot of the rendered templates', () => {
  it.each(['github', 'gitlab', 'bitbucket'] as const)('%s renders exactly as expected', (target) => {
    const project = makeProject();
    const r = runCli(['ci-init', target, '--project', project]);
    expect(r.status).toBe(0);
    // Drop the preview banner (which embeds this run's own temp-dir path,
    // never stable across runs/machines) before snapshotting.
    const body = r.stdout.split('\n').slice(2).join('\n');
    expect(body).toMatchSnapshot();
  });
});
