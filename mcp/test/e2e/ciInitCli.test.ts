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
import {
  existsSync,
  linkSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parse as parseYaml } from 'yaml';
import { afterEach, describe, expect, it } from 'vitest';
import { detectOs } from '../../src/platform/osDetect.js';
import { candidatesFor } from '../../src/platform/shellProbe.js';
import { isWslLauncher, resolveExecutable } from '../helpers/resolveExecutable.js';
import { rmDirOrDefer } from '../helpers/tempDir.js';
import { isInstalled } from '../helpers/toolchain.js';

const REPO_ROOT = resolve(fileURLToPath(new URL('../../..', import.meta.url)));
const CLI = resolve(REPO_ROOT, 'cli', 'dev-guardian.mjs');
const TIMEOUT_MS = 15_000;
const ACTIONLINT_INSTALLED = await isInstalled('actionlint');
const ZIZMOR_INSTALLED = await isInstalled('zizmor');

/**
 * A bash that can actually run a script, chosen the way the server chooses one
 * (`platform/shellProbe.ts`): Git Bash first on Windows, then `bash` on PATH —
 * never WSL, whose Linux view of the filesystem cannot see these Windows temp
 * paths. From PowerShell, bare `bash` is `C:\Windows\System32\bash.exe`, the
 * WSL launcher, which with no distro installed fails every script: the five
 * probe tests below used to fail there for a reason that had nothing to do with
 * the probe. `null` when no candidate runs `bash -c 'exit 0'` — the tests that
 * need it are then skipped, visibly, with that reason in their name.
 *
 * Each candidate is resolved to an ABSOLUTE path first, and that path is both
 * probed and later spawned: a bare name can resolve to a different binary the
 * second time (the WSL launcher in System32, ahead of Git's `bin` on PATH), so
 * probing `bash` and spawning `bash` could test one program and run another.
 * A candidate that resolves to the WSL launcher is skipped outright.
 */
const PROBE_BASH: string | null = (() => {
  for (const candidate of candidatesFor(detectOs())) {
    if (candidate.needs_wsl_path_translate) continue;
    const abs = resolveExecutable(candidate.command);
    if (abs === null || (process.platform === 'win32' && isWslLauncher(abs))) continue;
    const r = spawnSync(abs, [...candidate.args_prefix, '-c', 'exit 0'], {
      stdio: 'ignore',
      timeout: 10_000,
    });
    if (r.error === undefined && r.status === 0) return abs;
  }
  return null;
})();
const NO_BASH_REASON = "skipped: no bash here can run `bash -c 'exit 0'` (Git Bash absent; bash on PATH is the WSL stub)";

const tempDirs: string[] = [];
function makeProject(): string {
  const dir = mkdtempSync(join(tmpdir(), 'guardian-ci-init-'));
  tempDirs.push(dir);
  return dir;
}
afterEach(() => {
  for (const d of tempDirs.splice(0)) rmDirOrDefer(d);
});

// Fix round 2: this repo bumps `.claude-plugin/plugin.json`'s `version`
// and tags the release SEPARATELY (version committed first, tag pushed
// later) — for most of that window, `resolveDevGuardianCommitSha` has no
// answer (neither this checkout's own tags nor the network has the
// not-yet-existing tag), and every test below would exit 3 for a reason
// that has nothing to do with what it is testing. `GUARDIAN_CI_INIT_PIN_SHA`
// (the CLI's own test seam — see its doc comment) sidesteps that: a fixed,
// obviously-fake-but-correctly-shaped SHA, injected by default here so the
// whole suite is independent of whether THIS run's `plugin.json` version
// happens to have a real tag yet. The one test that must exercise REAL
// resolution (`ci-init: real tag-to-SHA resolution`, below) calls
// `runCliNoPin` instead, deliberately without this override.
const PINNED_TEST_SHA = 'a'.repeat(40);

function runCli(args: string[], envOverrides: Record<string, string> = {}) {
  const r = spawnSync(process.execPath, [CLI, ...args], {
    encoding: 'utf8',
    env: { ...process.env, NO_COLOR: '1', GUARDIAN_CI_INIT_PIN_SHA: PINNED_TEST_SHA, ...envOverrides },
    timeout: TIMEOUT_MS,
  });
  return { status: r.status, stdout: r.stdout ?? '', stderr: r.stderr ?? '' };
}

/** `runCli`, but WITHOUT the pinned-SHA test seam — exercises real tag-to-SHA resolution. */
function runCliNoPin(args: string[]) {
  // Omitted, not emptied — `''` would still hit the seam in the CLI (it
  // only checks `!== undefined`) and fail COMMIT_SHA_SHAPE.
  const { GUARDIAN_CI_INIT_PIN_SHA: _unused, ...restEnv } = process.env;
  const env = { ...restEnv, NO_COLOR: '1' };
  const r = spawnSync(process.execPath, [CLI, ...args], { encoding: 'utf8', env, timeout: TIMEOUT_MS });
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

/** The rendered pipeline body, banner and trailer stripped, as the real YAML document a host would read. */
function renderedBody(project: string, target: string): string {
  const r = runCli(['ci-init', target, '--project', project]);
  expect(r.status, r.stderr).toBe(0);
  return r.stdout.split('\n').slice(2, -2).join('\n');
}

describe('ci-init fix round 1: the GitHub template is accepted by real actionlint/zizmor (skip when not installed)', () => {
  // Regression: the workflow-level `env: DEV_GUARDIAN_HOME: ${{ runner.temp }}/…`
  // this template used to have is rejected outright by GitHub itself —
  // "context 'runner' is not allowed here" — actionlint catches the exact
  // same defect. Fixed by moving it into a step that appends to
  // $GITHUB_ENV instead of a workflow/job-level `env:` block.
  it('no `runner.` context expression appears in the workflow-level env: block (static, no tool needed)', () => {
    const project = makeProject();
    const body = renderedBody(project, 'github');
    const doc = parseYaml(body) as { env?: unknown; jobs?: Record<string, { env?: unknown }> };
    if (doc.env !== undefined) {
      expect(JSON.stringify(doc.env)).not.toMatch(/runner\./);
    }
    for (const job of Object.values(doc.jobs ?? {})) {
      if (job.env !== undefined) expect(JSON.stringify(job.env)).not.toMatch(/runner\./);
    }
  });

  it.skipIf(!ACTIONLINT_INSTALLED)('actionlint accepts the rendered GitHub template with zero errors', () => {
    const project = makeProject();
    const r = runCli(['ci-init', 'github', '--project', project, '--write']);
    expect(r.status).toBe(0);
    const workflowPath = join(project, '.github', 'workflows', 'dev-guardian.yml');
    const result = spawnSync('actionlint', [workflowPath], { encoding: 'utf8' });
    expect(result.status, `actionlint stdout:\n${result.stdout}\nstderr:\n${result.stderr}`).toBe(0);
  });

  it.skipIf(!ZIZMOR_INSTALLED)('zizmor accepts the rendered GitHub template with zero findings', () => {
    const project = makeProject();
    const r = runCli(['ci-init', 'github', '--project', project, '--write']);
    expect(r.status).toBe(0);
    const workflowPath = join(project, '.github', 'workflows', 'dev-guardian.yml');
    const result = spawnSync('zizmor', ['--format=json', workflowPath], { encoding: 'utf8' });
    const findings: unknown = JSON.parse(result.stdout.trim().length > 0 ? result.stdout : '[]');
    expect(findings, `zizmor findings:\n${JSON.stringify(findings, null, 2)}`).toEqual([]);
  });
});

describe('ci-init fix round 1: scanner installs never write into the scanned checkout', () => {
  // Regression: every template used to curl/tar straight into the CURRENT
  // DIRECTORY (the checkout, since every step here runs with it as cwd) —
  // leaving untracked trivy/trivy.tar.gz (~50 MB)/gitleaks/actionlint
  // files there. gitleaks' own working-tree pass then saw those as
  // untracked files well over its size limit, which is a gap
  // (missing_tools), which drops `dev-guardian scan`'s own coverage below
  // `full` and exits 2 on EVERY run, on any project, regardless of the
  // project's own content.
  it.each(['github', 'gitlab', 'bitbucket'] as const)('%s: curl/tar/install all target a scratch directory, never a bare relative filename', (target) => {
    const project = makeProject();
    const body = renderedBody(project, target);
    expect(body).not.toMatch(/-o\s+"\$name\.tar\.gz"/);
    expect(body).not.toMatch(/tar -xzf\s+"\$name\.tar\.gz"\s+"\$member"/);
    expect(body).not.toMatch(/install -m 0755\s+"\$member"/);
    expect(body).toMatch(/dir="(\$RUNNER_TEMP\/dev-guardian-scanners|\/tmp\/dev-guardian-scanners)"/);
    expect(body).toMatch(/-o "\$dir\/\$name\.tar\.gz"/);
    expect(body).toMatch(/tar -xzf "\$dir\/\$name\.tar\.gz" -C "\$dir" "\$member"/);
    expect(body).toMatch(/install -m 0755 "\$dir\/\$member"/);
  });
});

describe('ci-init fix round 1: full-history clone (gitleaks needs commit history, not a shallow grafted boundary)', () => {
  it('github: actions/checkout sets fetch-depth: 0', () => {
    const project = makeProject();
    const doc = parseYaml(renderedBody(project, 'github')) as {
      jobs: Record<string, { steps: Array<{ uses?: string; with?: Record<string, unknown> }> }>;
    };
    // Every checkout, not the first: a shallow one makes `scan` exit 2
    // (the history pass names its boundary — docs/ci.md).
    const checkouts = Object.values(doc.jobs)
      .flatMap((j) => j.steps)
      .filter((s) => s.uses?.startsWith('actions/checkout@'));
    expect(checkouts.length).toBeGreaterThan(0);
    for (const checkout of checkouts) {
      expect(checkout.with?.['fetch-depth']).toBe(0);
      expect(checkout.with?.['persist-credentials']).toBe(false);
    }
  });

  it('gitlab: GIT_DEPTH is "0"', () => {
    const project = makeProject();
    const doc = parseYaml(renderedBody(project, 'gitlab')) as {
      ['dev-guardian']: { variables: Record<string, unknown> };
    };
    expect(doc['dev-guardian'].variables['GIT_DEPTH']).toBe('0');
  });

  it('bitbucket: clone.depth is "full" at the top level', () => {
    const project = makeProject();
    const doc = parseYaml(renderedBody(project, 'bitbucket')) as { clone: { depth: unknown } };
    expect(doc.clone.depth).toBe('full');
  });
});

describe('ci-init fix round 1: bandit always installed; .NET SDK conditional (github) or documented (gitlab/bitbucket)', () => {
  it.each(['github', 'gitlab', 'bitbucket'] as const)('%s: bandit[toml] is pipx-installed unconditionally', (target) => {
    const project = makeProject();
    const body = renderedBody(project, target);
    expect(body).toMatch(/pipx install "bandit\[toml\]==\d+\.\d+\.\d+"/);
  });

  it('github: .NET SDK setup is present, gated on a root .csproj/.fsproj/.sln/.slnx probe', () => {
    const project = makeProject();
    const doc = parseYaml(renderedBody(project, 'github')) as {
      jobs: Record<string, { steps: Array<{ uses?: string; if?: string; run?: string; id?: string }> }>;
    };
    const steps = Object.values(doc.jobs).flatMap((j) => j.steps);
    const probe = steps.find((s) => s.id === 'dotnet_probe');
    expect(probe?.run).toMatch(/find . -maxdepth 1/);
    expect(probe?.run).toMatch(/-iname '\*\.csproj'/);
    expect(probe?.run).toMatch(/-iname '\*\.fsproj'/);
    expect(probe?.run).toMatch(/-iname '\*\.sln'/);
    expect(probe?.run).toMatch(/-iname '\*\.slnx'/);
    const setup = steps.find((s) => s.uses?.startsWith('actions/setup-dotnet@'));
    expect(setup?.if).toBe("steps.dotnet_probe.outputs.found == 'true'");
  });

  // Fix round 2: the FIRST version of this probe used
  // `ls -- *.csproj *.fsproj *.sln *.slnx`, which reports "found" only when
  // ALL FOUR extensions are present — a directory holding only App.csproj
  // (no .fsproj/.sln/.slnx) made it print "found=false", the opposite of
  // correct. A string-matching test would not have caught this: the OLD
  // script's text still mentioned every extension. Only actually RUNNING
  // the extracted script against a real directory catches it.
  describe.skipIf(PROBE_BASH === null)(`github: the .NET probe script, actually executed against real directories${PROBE_BASH === null ? ` (${NO_BASH_REASON})` : ''}`, () => {
    function extractProbeScript(project: string): string {
      const doc = parseYaml(renderedBody(project, 'github')) as {
        jobs: Record<string, { steps: Array<{ id?: string; run?: string }> }>;
      };
      const steps = Object.values(doc.jobs).flatMap((j) => j.steps);
      const script = steps.find((s) => s.id === 'dotnet_probe')?.run;
      if (script === undefined) throw new Error('dotnet_probe step not found in rendered template');
      return script;
    }

    function runProbe(project: string, files: string[]): string {
      for (const f of files) writeFileSync(join(project, f), '', 'utf8');
      const script = extractProbeScript(project);
      const outputFile = join(project, '.github_output_test');
      // The block is skipped when PROBE_BASH is null; never fall back to a bare `bash`.
      if (PROBE_BASH === null) throw new Error(NO_BASH_REASON);
      const result = spawnSync(PROBE_BASH, ['-c', script], {
        cwd: project,
        env: { ...process.env, GITHUB_OUTPUT: outputFile },
        encoding: 'utf8',
      });
      expect(result.status, `probe script failed:\n${script}\nstderr: ${result.stderr}`).toBe(0);
      return readFileSync(outputFile, 'utf8').trim();
    }

    it.each([
      ['only a .csproj', ['App.csproj'], 'found=true'],
      ['only a .fsproj', ['App.fsproj'], 'found=true'],
      ['only a .sln', ['App.sln'], 'found=true'],
      ['only a .slnx', ['App.slnx'], 'found=true'],
      ['no .NET project files at all', [], 'found=false'],
    ] as const)('%s -> %s', (_label, files, expected) => {
      const project = makeProject();
      expect(runProbe(project, [...files])).toBe(expected);
    });
  });

  it.each(['gitlab', 'bitbucket'] as const)('%s: documents the .NET SDK requirement instead of installing it', (target) => {
    const project = makeProject();
    const body = renderedBody(project, target);
    expect(body.toLowerCase()).toMatch(/\.net sdk/);
    expect(body).toContain('dotnet-sdk');
    // Header prose wraps across comment lines, so this checks the two
    // words are both present near each other rather than requiring an
    // exact "named gap" substring the YAML line-wrap would break.
    expect(body).toMatch(/named\s*\n?#?\s*gap/);
    expect(body).toContain('exit 2');
  });
});

describe('ci-init fix round 1: --branch controls the GitHub push trigger (default main)', () => {
  it('defaults to main', () => {
    const project = makeProject();
    const doc = parseYaml(renderedBody(project, 'github')) as { on: { push: { branches: string[] } } };
    expect(doc.on.push.branches).toEqual(['main']);
  });

  it('--branch overrides it', () => {
    const project = makeProject();
    const r = runCli(['ci-init', 'github', '--project', project, '--branch', 'release']);
    expect(r.status).toBe(0);
    const body = r.stdout.split('\n').slice(2, -2).join('\n');
    const doc = parseYaml(body) as { on: { push: { branches: string[] } } };
    expect(doc.on.push.branches).toEqual(['release']);
  });

  it('refuses a --branch value shaped like a shell/YAML injection attempt', () => {
    const project = makeProject();
    const r = runCli(['ci-init', 'github', '--project', project, '--branch', 'main"; rm -rf /']);
    expect(r.status).toBe(3);
    expect(r.stderr).toMatch(/--branch/);
  });

  it('fix round 2: a numeric-looking branch name stays a YAML string, never a bare number', () => {
    // BRANCH_NAME_SHAPE allows an all-digit branch ("123" is a legal git
    // ref). Rendered unquoted (`branches: [{{BRANCH}}]`), YAML would parse
    // it as the number 123, not the string "123" — GitHub compares it
    // against a ref name, so a numeric branch's push trigger would silently
    // never match. The template quotes the placeholder
    // (`branches: ["{{BRANCH}}"]`) specifically so this stays a string.
    const project = makeProject();
    const r = runCli(['ci-init', 'github', '--project', project, '--branch', '123']);
    expect(r.status).toBe(0);
    const body = r.stdout.split('\n').slice(2, -2).join('\n');
    const doc = parseYaml(body) as { on: { push: { branches: unknown[] } } };
    expect(doc.on.push.branches).toEqual(['123']);
    expect(typeof doc.on.push.branches[0]).toBe('string');
  });
});

describe('ci-init fix round 1: the dev-guardian clone is verified against its resolved commit SHA', () => {
  it.each(['github', 'gitlab', 'bitbucket'] as const)('%s: clones by tag, then verifies git rev-parse HEAD against the resolved SHA', (target) => {
    const project = makeProject();
    const body = renderedBody(project, target);
    const plugin = JSON.parse(readFileSync(resolve(REPO_ROOT, '.claude-plugin', 'plugin.json'), 'utf8')) as {
      version: string;
    };
    expect(body).toMatch(/rev-parse HEAD/);
    // The expected SHA is the pinned test seam's value (deterministic —
    // see PINNED_TEST_SHA), not a placeholder or the tag itself.
    const shaMatch = /expected ([0-9a-f]{40})/.exec(body);
    expect(shaMatch, body).not.toBeNull();
    expect(shaMatch?.[1]).toBe(PINNED_TEST_SHA);
    expect(body).toContain(`clone at v${plugin.version}`);
  });
});

describe('ci-init fix round 2: real tag-to-SHA resolution (no test-seam override)', () => {
  // Deliberately uses `runCliNoPin`: this is the ONE test that must exercise
  // `resolveDevGuardianCommitSha` for real (local-tag lookup, or `git
  // ls-remote` if this checkout lacks the tag) — every other test in this
  // file uses the `GUARDIAN_CI_INIT_PIN_SHA` seam instead, on purpose: this
  // repo bumps `.claude-plugin/plugin.json`'s `version` and tags the
  // release SEPARATELY, so for most of the time a release branch exists,
  // NEITHER this checkout's own tags NOR the network has an answer for the
  // version this exact worktree currently declares — that is an expected,
  // documented state (see resolveDevGuardianCommitSha's own doc comment),
  // not a failure of this test, so it skips rather than fails when hit.
  it('resolves the current release tag to a real commit SHA, or skips cleanly if this checkout is ahead of its own tag and there is no network', (t) => {
    const project = makeProject();
    const r = runCliNoPin(['ci-init', 'github', '--project', project]);
    if (r.status === 3 && /could not resolve/.test(r.stderr)) {
      t.skip(); // expected pre-tag state — see the module doc comment on resolveDevGuardianCommitSha
      return;
    }
    expect(r.status, r.stderr).toBe(0);
    const shaMatch = /expected ([0-9a-f]{40})/.exec(r.stdout);
    expect(shaMatch, r.stdout).not.toBeNull();
    expect(shaMatch?.[1]).not.toBe(PINNED_TEST_SHA); // genuinely resolved, not the test seam's fake value
  });
});

describe('ci-init fix round 1: a symlinked .github escaping the project is refused on write, never followed', () => {
  it('refuses to write through a `.github` that is a symlink pointing outside the project', (t) => {
    const project = makeProject();
    const outside = mkdtempSync(join(tmpdir(), 'guardian-ci-init-outside-'));
    tempDirs.push(outside);
    try {
      symlinkSync(outside, join(project, '.github'), 'dir');
    } catch {
      t.skip(); // no symlink privilege on this host
      return;
    }
    const r = runCli(['ci-init', 'github', '--project', project, '--write']);
    expect(r.status).toBe(3);
    expect(r.stderr).toMatch(/resolves outside the project/);
    expect(existsSync(join(outside, 'workflows'))).toBe(false);
  });
});

describe('ci-init fix round 2: a leaf symlink at the output path is never followed by --force', () => {
  // `firstEscapingAncestor` (tested above) only walks ANCESTORS of outPath;
  // it deliberately does not check outPath itself (see its own doc
  // comment). Without `--force`, `wx` already refuses any existing path at
  // that name, symlink or not. `--force` alone switches to plain `'w'`,
  // which follows a symlink — so these two tests target the leaf itself,
  // using gitlab's flat `.gitlab-ci.yml` output path (no intermediate
  // directory needed, unlike github's `.github/workflows/...`).

  it('refuses to overwrite a leaf symlink that resolves outside the project, even with --force', (t) => {
    const project = makeProject();
    const outside = mkdtempSync(join(tmpdir(), 'guardian-ci-init-outside-'));
    tempDirs.push(outside);
    const outsideTarget = join(outside, 'not-the-pipeline.yml');
    writeFileSync(outsideTarget, 'do not touch\n');
    const outPath = join(project, '.gitlab-ci.yml');
    try {
      symlinkSync(outsideTarget, outPath, 'file');
    } catch {
      t.skip(); // no symlink privilege on this host
      return;
    }

    const r = runCli(['ci-init', 'gitlab', '--project', project, '--write', '--force']);
    expect(r.status).toBe(3);
    expect(r.stderr).toMatch(/refusing to overwrite/);
    expect(r.stderr).toMatch(/resolves outside the project/);
    // Never followed: the file the link points at is untouched, and the
    // link itself is still a link (not replaced, not removed).
    expect(readFileSync(outsideTarget, 'utf8')).toBe('do not touch\n');
    expect(lstatSync(outPath).isSymbolicLink()).toBe(true);
  });

  it('--force overwrites a leaf symlink that resolves inside the project by replacing the link with a plain file', (t) => {
    const project = makeProject();
    const insideTarget = join(project, 'real-target.yml');
    writeFileSync(insideTarget, 'old content\n');
    const outPath = join(project, '.gitlab-ci.yml');
    try {
      symlinkSync(insideTarget, outPath, 'file');
    } catch {
      t.skip(); // no symlink privilege on this host
      return;
    }

    const r = runCli(['ci-init', 'gitlab', '--project', project, '--write', '--force']);
    expect(r.status).toBe(0);
    // The link is gone; outPath is now a plain file holding the rendered
    // pipeline, not written through the old link.
    expect(lstatSync(outPath).isSymbolicLink()).toBe(false);
    expect(readFileSync(outPath, 'utf8')).toMatch(/Generated by `dev-guardian ci-init/);
    // The old link's target is untouched -- proof the write went to a
    // fresh file at outPath, never through the link to insideTarget.
    expect(readFileSync(insideTarget, 'utf8')).toBe('old content\n');
  });

  // Follow-up (Task 21 minor): the two leaf shapes the tests above did not
  // carry — the same refusal, reached by another kind of link.
  it('refuses a leaf symlink to a DIRECTORY outside the project, with or without --force', (t) => {
    const project = makeProject();
    const outside = mkdtempSync(join(tmpdir(), 'guardian-ci-init-outside-'));
    tempDirs.push(outside);
    const outPath = join(project, '.gitlab-ci.yml');
    try {
      symlinkSync(outside, outPath, 'dir');
    } catch {
      t.skip(); // no symlink privilege on this host
      return;
    }

    const forced = runCli(['ci-init', 'gitlab', '--project', project, '--write', '--force']);
    expect(forced.status).toBe(3);
    expect(forced.stderr).toMatch(/resolves outside the project/);
    const plain = runCli(['ci-init', 'gitlab', '--project', project, '--write']);
    expect(plain.status).toBe(1);
    expect(plain.stderr).toMatch(/refusing to overwrite existing pipeline file/);
    // Nothing was written into the directory the link points at, and the
    // link is still a link.
    expect(readdirSync(outside)).toEqual([]);
    expect(lstatSync(outPath).isSymbolicLink()).toBe(true);
  });

  it('refuses a DANGLING leaf symlink, with or without --force — never creates its target', (t) => {
    const project = makeProject();
    const outside = mkdtempSync(join(tmpdir(), 'guardian-ci-init-outside-'));
    tempDirs.push(outside);
    const missingTarget = join(outside, 'not-yet.yml');
    const outPath = join(project, '.gitlab-ci.yml');
    try {
      symlinkSync(missingTarget, outPath, 'file');
    } catch {
      t.skip(); // no symlink privilege on this host
      return;
    }

    const forced = runCli(['ci-init', 'gitlab', '--project', project, '--write', '--force']);
    expect(forced.status).toBe(3);
    expect(forced.stderr).toMatch(/broken symlink/);
    const plain = runCli(['ci-init', 'gitlab', '--project', project, '--write']);
    expect(plain.status).toBe(1);
    expect(existsSync(missingTarget)).toBe(false);
    expect(lstatSync(outPath).isSymbolicLink()).toBe(true);
  });
});

describe('ci-init: --force replaces the file in one step (write to a temp file, then rename)', () => {
  it('--help says what --force still refuses', () => {
    const r = runCli(['--help']);
    expect(r.status).toBe(0);
    const section = r.stdout.slice(r.stdout.indexOf('ci-init <github|gitlab|bitbucket> —'));
    const force = section.slice(section.indexOf('--force'), section.indexOf('Writes:'));
    expect(force).toMatch(/symlink\s+that resolves outside the project, or a broken one/);
  });

  it('never writes through another name for the file — a hard link keeps its content', (t) => {
    // A truncating write goes through the inode every name of the file
    // shares; a rename replaces only the directory entry at outPath.
    const project = makeProject();
    const outside = mkdtempSync(join(tmpdir(), 'guardian-ci-init-outside-'));
    tempDirs.push(outside);
    const other = join(outside, 'keep-me.yml');
    writeFileSync(other, 'do not touch\n');
    const outPath = join(project, '.gitlab-ci.yml');
    try {
      linkSync(other, outPath);
    } catch {
      t.skip(); // no hard links across these directories on this host
      return;
    }

    const r = runCli(['ci-init', 'gitlab', '--project', project, '--write', '--force']);
    expect(r.status).toBe(0);
    expect(readFileSync(outPath, 'utf8')).toMatch(/Generated by `dev-guardian ci-init/);
    expect(readFileSync(other, 'utf8')).toBe('do not touch\n');
    expect(readdirSync(project)).toEqual(['.gitlab-ci.yml']); // no temp file left behind
  });

  it('a plain --write publishes the whole file and leaves no temp file — written or refused', () => {
    // The plain write goes through a temp file too (published with link()),
    // so a success and a refusal must both leave the directory as they found it.
    const project = makeProject();
    const outPath = join(project, '.gitlab-ci.yml');
    const first = runCli(['ci-init', 'gitlab', '--project', project, '--write']);
    expect(first.status).toBe(0);
    const written = readFileSync(outPath, 'utf8');
    expect(written).toMatch(/Generated by `dev-guardian ci-init/);
    expect(readdirSync(project)).toEqual(['.gitlab-ci.yml']);
    expect(lstatSync(outPath).nlink).toBe(1); // the temp name is gone, not a second link

    const second = runCli(['ci-init', 'gitlab', '--project', project, '--write']);
    expect(second.status).toBe(1);
    expect(readdirSync(project)).toEqual(['.gitlab-ci.yml']);
    expect(readFileSync(outPath, 'utf8')).toBe(written);
  });

  it('leaves no temp file behind when the rename fails', () => {
    const project = makeProject();
    const outPath = join(project, '.gitlab-ci.yml');
    mkdirSync(join(outPath, 'occupied'), { recursive: true }); // a non-empty directory at the name

    const r = runCli(['ci-init', 'gitlab', '--project', project, '--write', '--force']);
    expect(r.status).not.toBe(0);
    expect(readdirSync(project)).toEqual(['.gitlab-ci.yml']);
    expect(readdirSync(outPath)).toEqual(['occupied']);
  });
});

// `ci-init github --attest`: the pipeline attests dev-guardian's own scan
// outputs — the JSON report and the SARIF — with GitHub's build-provenance
// attestations. The signing capability (`id-token: write`) sits on a job of
// its own that runs none of the project's code; the scan job, which builds
// the project and runs the scanners on it, keeps exactly the permissions it
// had. argv only, like --start-command; GitHub only.
interface RenderedWorkflow {
  permissions?: Record<string, string>;
  jobs: Record<
    string,
    {
      needs?: string | string[];
      if?: string;
      permissions?: Record<string, string>;
      steps: { name?: string; uses?: string; run?: string; if?: string; with?: Record<string, string> }[];
    }
  >;
}

function pinnedAction(key: string): { repo: string; version: string; sha: string } {
  const pinned = JSON.parse(readFileSync(resolve(REPO_ROOT, 'configs', 'ci', 'pinned.json'), 'utf8')) as {
    actions: Record<string, { repo: string; version: string; sha: string }>;
  };
  const entry = pinned.actions[key];
  if (entry === undefined) throw new Error(`pinned.json has no action ${key}`);
  return entry;
}

function renderGithub(extra: string[] = []): { body: string; doc: RenderedWorkflow } {
  const project = makeProject();
  const r = runCli(['ci-init', 'github', '--project', project, ...extra]);
  expect(r.status, r.stderr).toBe(0);
  const body = r.stdout.split('\n').slice(2, -2).join('\n');
  return { body, doc: parseYaml(body) as RenderedWorkflow };
}

describe('ci-init --attest (GitHub build-provenance attestations of the scan outputs)', () => {
  it('adds an attest job holding ONLY id-token: write and attestations: write, after the scan job, on push only', () => {
    const { doc } = renderGithub(['--attest']);
    const attest = doc.jobs['attest'];
    expect(attest).toBeDefined();
    expect(attest?.permissions).toEqual({ 'id-token': 'write', attestations: 'write' });
    expect(attest?.needs).toBe('scan');
    expect(attest?.if).toMatch(/github\.event_name == 'push'/);
    expect(attest?.if).toMatch(/!cancelled\(\)/);
  });

  it('the scan job — which runs the project and its scanners — gains no permission', () => {
    const plain = renderGithub().doc;
    const attested = renderGithub(['--attest']).doc;
    // With two jobs, nothing is granted at the workflow level (zizmor's
    // excessive-permissions flags a workflow-level write once there is more
    // than one job): each job states what it holds, and the scan job holds
    // exactly what the one-job pipeline gave it.
    expect(attested.permissions).toEqual({});
    expect(attested.jobs['scan']?.permissions).toEqual(plain.permissions);
    expect(plain.permissions).toEqual({ contents: 'read', 'security-events': 'write', actions: 'read' });
  });

  it('attests both outputs with attest-build-provenance, downloaded from the scan job, every action pinned by SHA', () => {
    const { doc } = renderGithub(['--attest']);
    const provenance = pinnedAction('attest_build_provenance');
    const upload = pinnedAction('upload_artifact');
    const download = pinnedAction('download_artifact');
    const steps = doc.jobs['attest']?.steps ?? [];
    expect(steps.map((s) => s.uses ?? 'run')).toEqual([
      `actions/download-artifact@${download.sha}`,
      'run',
      `actions/attest-build-provenance@${provenance.sha}`,
    ]);
    const subjects = (steps[2]?.with?.['subject-path'] ?? '').trim().split('\n');
    expect(subjects).toEqual(['dev-guardian-report.json', 'dev-guardian-results.sarif']);

    const keep = doc.jobs['scan']?.steps.find((s) => s.uses?.startsWith('actions/upload-artifact@'));
    expect(keep?.uses).toBe(`actions/upload-artifact@${upload.sha}`);
    expect(keep?.with?.['name']).toBe(steps[0]?.with?.['name']);
    expect((keep?.with?.['path'] ?? '').trim().split('\n')).toEqual(subjects);
    expect(keep?.with?.['if-no-files-found']).toBe('error');
  });

  it('the scan step writes the JSON report, and its exit code still gates the job (pipefail)', () => {
    const { doc } = renderGithub(['--attest']);
    const scan = doc.jobs['scan']?.steps.find((s) => s.name === 'dev-guardian scan');
    expect(scan?.run).toMatch(/^set -uo pipefail\nset \+e\n/);
    expect(scan?.run).toMatch(/--format json/);
    expect(scan?.run).toMatch(/--sarif dev-guardian-results\.sarif/);
    expect(scan?.run).toMatch(/\| tee dev-guardian-report\.json\nstatus=\$\?\n/);
    expect(scan?.run).toMatch(/exit "\$status"\s*$/);
  });

  // Review of 3.0.0 (S6): the upload ran on `if: always()`, so an incomplete
  // scan's SARIF (exit 2: a scanner did not run) reached code scanning, which
  // closes as "fixed" every alert of a scanner the upload does not contain —
  // `executionSuccessful: false` notwithstanding. Re-review (M-1): an exit 1
  // can be incomplete too — a blocking finding outranks a missing scanner —
  // so the step uploads only exit 0, or exit 1 with coverage full.
  it.each([[[] as string[]], [['--attest']]])('SARIF is uploaded only for a complete run — argv %j', (argv) => {
    const { doc } = renderGithub(argv);
    const steps = (doc.jobs['scan']?.steps ?? []) as Array<{ name?: string; id?: string; run?: string; if?: string }>;
    const scan = steps.find((s) => s.name === 'dev-guardian scan');
    expect(scan?.id).toBe('scan');
    expect(scan?.run).toMatch(
      /echo "exit-code=\$status" >> "\$GITHUB_OUTPUT"\necho "upload-sarif=\$upload" >> "\$GITHUB_OUTPUT"\nexit "\$status"\s*$/,
    );
    const upload = steps.find((s) => s.name === 'Upload SARIF to code scanning');
    expect(upload?.if).toBe("${{ always() && steps.scan.outputs.upload-sarif == 'true' }}");
  });

  it.skipIf(PROBE_BASH === null)(`the scan step keeps the scan's exit code and uploads only a complete run's SARIF${PROBE_BASH === null ? ` (${NO_BASH_REASON})` : ''}`, () => {
    // Run as GitHub runs it (`bash -e`), with a stand-in `node` for the scan
    // (exiting 0 to 3) that hands the step's own SARIF check to the real node,
    // over a SARIF that says the run was, or was not, complete.
    const sarif = (complete: boolean): string =>
      JSON.stringify({ version: '2.1.0', runs: [{ invocations: [{ executionSuccessful: complete }], results: [] }] });
    const cases: Array<[number, boolean, boolean]> = [
      [0, true, true],
      [0, false, true],
      [1, true, true],
      [1, false, false],
      [2, true, false],
      [2, false, false],
      [3, false, false],
    ];
    for (const argv of [[], ['--attest']]) {
      const { doc } = renderGithub(argv);
      const script = doc.jobs['scan']?.steps.find((s) => s.name === 'dev-guardian scan')?.run ?? '';
      for (const [code, complete, uploads] of cases) {
        const dir = makeProject();
        const bin = join(dir, 'bin');
        mkdirSync(bin);
        writeFileSync(
          join(bin, 'node'),
          `#!/bin/sh\nif [ "$1" = "-e" ]; then exec "$REAL_NODE" "$@"; fi\necho scanning\nexit ${code}\n`,
          { mode: 0o755 },
        );
        writeFileSync(join(dir, 'dev-guardian-results.sarif'), sarif(complete));
        writeFileSync(join(dir, 'step.sh'), `export PATH="$PWD/bin:$PATH"\n${script}`);
        const r = spawnSync(PROBE_BASH ?? 'bash', ['-e', 'step.sh'], {
          cwd: dir,
          encoding: 'utf8',
          timeout: 30_000,
          env: { ...process.env, GITHUB_OUTPUT: join(dir, 'out.txt'), DEV_GUARDIAN_HOME: dir, REAL_NODE: process.execPath },
        });
        const label = `${JSON.stringify(argv)} exit ${code}, complete ${complete}`;
        expect(r.status, `${label}: ${r.stderr}`).toBe(code);
        expect(readFileSync(join(dir, 'out.txt'), 'utf8'), label).toBe(`exit-code=${code}\nupload-sarif=${uploads}\n`);
      }
    }
  }, 240_000);

  it('without --attest nothing of it is rendered', () => {
    const { body } = renderGithub();
    expect(body).not.toMatch(/attest|id-token|upload-artifact|download-artifact|dev-guardian-report\.json/);
    expect(body).toMatch(/--format human/);
  });

  it.each(['gitlab', 'bitbucket'] as const)('%s --attest is refused (exit 3) and writes nothing', (target) => {
    const project = makeProject();
    const r = runCli(['ci-init', target, '--project', project, '--attest', '--write']);
    expect(r.status).toBe(3);
    expect(r.stderr).toMatch(/--attest is GitHub-only/);
    expect(readdirSync(project)).toEqual([]);
  });

  it('a repository file declaring "attest" is refused, whatever argv says — command line only', () => {
    for (const argv of [[], ['--attest']]) {
      const project = makeProject();
      mkdirSync(join(project, '.guardian'));
      writeFileSync(join(project, '.guardian', 'ci.json'), JSON.stringify({ attest: true }));
      const r = runCli(['ci-init', 'github', '--project', project, '--write', ...argv]);
      expect(r.status, argv.join(' ')).toBe(3);
      expect(r.stderr).toMatch(/declares "attest"/);
      expect(r.stderr).toMatch(/command line/);
      expect(existsSync(join(project, '.github'))).toBe(false);
    }
  });

  it('--help and the --write message both say how to verify an attestation (gh attestation verify)', () => {
    const help = runCli(['--help']);
    const section = help.stdout.slice(help.stdout.indexOf('ci-init <github|gitlab|bitbucket> —'));
    expect(section).toMatch(/--attest/);
    expect(section).toMatch(/gh attestation verify/);
    const project = makeProject();
    const r = runCli(['ci-init', 'github', '--project', project, '--write', '--attest']);
    expect(r.status).toBe(0);
    expect(r.stdout).toMatch(/gh attestation verify dev-guardian-results\.sarif/);
  });

  // Review M6: --signer-workflow names the workflow FILE, and a copy of it on
  // any branch — edited to run on a push there — signs as that same path.
  it('the verify hint pins the branch the pipeline triggers on (--source-ref), in --help, the write message and the workflow', () => {
    const help = runCli(['--help']);
    const section = help.stdout.slice(help.stdout.indexOf('ci-init <github|gitlab|bitbucket> —'));
    expect(section).toMatch(/--source-ref refs\/heads\/<branch>/);
    for (const [argv, branch] of [[[], 'main'], [['--branch', 'release/2'], 'release/2']] as const) {
      const project = makeProject();
      const r = runCli(['ci-init', 'github', '--project', project, '--write', '--attest', ...argv]);
      expect(r.status).toBe(0);
      expect(r.stdout).toContain(`--source-ref refs/heads/${branch}`);
      const workflow = readFileSync(join(project, '.github', 'workflows', 'dev-guardian.yml'), 'utf8');
      expect(workflow).toContain(`--source-ref refs/heads/${branch}`);
    }
  });

  // Review M5: an attestation proves where a file came from, not that it is
  // a report — and `tee` creates the file even when the scan crashed first.
  it('the attest job refuses an empty or unreadable report before attesting it', () => {
    const { doc } = renderGithub(['--attest']);
    const steps = doc.jobs['attest']?.steps ?? [];
    const check = steps.find((s) => s.uses === undefined);
    expect(steps.indexOf(check ?? {})).toBeLessThan(steps.findIndex((s) => s.uses?.startsWith('actions/attest-build-provenance@')));
    expect(check?.run).toMatch(/^set -euo pipefail\n/);
  });

  it.skipIf(PROBE_BASH === null)(`the report check fails an empty report, broken JSON or a missing SARIF, and passes real ones${PROBE_BASH === null ? ` (${NO_BASH_REASON})` : ''}`, () => {
    const { doc } = renderGithub(['--attest']);
    const script = doc.jobs['attest']?.steps.find((s) => s.uses === undefined)?.run ?? '';
    const REPORT = JSON.stringify({ exit_code: 1, coverage: 'full', coverage_gaps: [], new_findings: [] });
    const SARIF = JSON.stringify({ version: '2.1.0', $schema: 'https://json.schemastore.org/sarif-2.1.0.json', runs: [] });
    const cases: Array<[string, Record<string, string>, boolean]> = [
      ['both real', { 'dev-guardian-report.json': REPORT, 'dev-guardian-results.sarif': SARIF }, true],
      ['an empty report (the scan crashed; tee created the file)', { 'dev-guardian-report.json': '', 'dev-guardian-results.sarif': SARIF }, false],
      ['broken JSON', { 'dev-guardian-report.json': '{"exit_code": 1,', 'dev-guardian-results.sarif': SARIF }, false],
      ['JSON that is not a report', { 'dev-guardian-report.json': '[]', 'dev-guardian-results.sarif': SARIF }, false],
      ['no SARIF', { 'dev-guardian-report.json': REPORT }, false],
      ['a SARIF that is not SARIF 2.1.0', { 'dev-guardian-report.json': REPORT, 'dev-guardian-results.sarif': '{"runs": []}' }, false],
    ];
    for (const [name, files, pass] of cases) {
      const dir = makeProject();
      for (const [file, content] of Object.entries(files)) writeFileSync(join(dir, file), content);
      writeFileSync(join(dir, 'check.sh'), script);
      const r = spawnSync(PROBE_BASH ?? 'bash', ['check.sh'], { cwd: dir, encoding: 'utf8', timeout: 30_000 });
      expect(r.status === 0, `${name}: exit ${r.status}\n${r.stderr}`).toBe(pass);
    }
  }, 120_000); // six bash + node spawns: seconds each on a loaded Windows machine

  it('--help, the write message and the workflow say the attestation runs whatever the gate said, and what a public repository exposes', () => {
    const help = runCli(['--help']);
    const section = help.stdout.slice(help.stdout.indexOf('ci-init <github|gitlab|bitbucket> —'));
    expect(section).toMatch(/even when the gate failed/);
    expect(section).toMatch(/public repository/);
    const project = makeProject();
    const r = runCli(['ci-init', 'github', '--project', project, '--write', '--attest']);
    expect(r.stdout).toMatch(/proves where the reports came from, not that the gate passed/);
    expect(r.stdout).toMatch(/public repository/);
    const workflow = readFileSync(join(project, '.github', 'workflows', 'dev-guardian.yml'), 'utf8');
    expect(workflow).toMatch(/even when the gate failed/);
    expect(workflow).toMatch(/printed to the job log/);
  });

  it('renders exactly as expected (snapshot)', () => {
    const project = makeProject();
    const r = runCli(['ci-init', 'github', '--project', project, '--attest']);
    expect(r.status).toBe(0);
    expect(r.stdout.split('\n').slice(2).join('\n')).toMatchSnapshot();
  });

  it.skipIf(!ACTIONLINT_INSTALLED)('actionlint accepts the --attest workflow with zero errors', () => {
    const project = makeProject();
    const r = runCli(['ci-init', 'github', '--project', project, '--write', '--attest']);
    expect(r.status).toBe(0);
    const result = spawnSync('actionlint', [join(project, '.github', 'workflows', 'dev-guardian.yml')], { encoding: 'utf8' });
    expect(result.status, `actionlint stdout:\n${result.stdout}\nstderr:\n${result.stderr}`).toBe(0);
  });

  // Part E review, round 2: a release-like --branch made zizmor raise a
  // cache-poisoning error on actions/setup-node (its automatic npm cache),
  // with or without --attest — the linter matrix now holds those renderings.
  const MATRIX: readonly (readonly string[])[] = [
    ['--branch', 'release/v2'],
    ['--branch', 'release/v2', '--attest'],
    ['--branch', 'releases/2026.09'],
  ];

  describe.skipIf(!ZIZMOR_INSTALLED)('zizmor on the release-branch renderings', () => {
    it.each(MATRIX.map((flags) => [flags.join(' '), flags] as const))('zero findings with %s', (_label, flags) => {
      const project = makeProject();
      const r = runCli(['ci-init', 'github', '--project', project, '--write', ...flags]);
      expect(r.status).toBe(0);
      const result = spawnSync('zizmor', ['--format=json', join(project, '.github', 'workflows', 'dev-guardian.yml')], { encoding: 'utf8' });
      const findings: unknown = JSON.parse(result.stdout.trim().length > 0 ? result.stdout : '[]');
      expect(findings, `zizmor findings:\n${JSON.stringify(findings, null, 2)}`).toEqual([]);
    });
  });

  describe.skipIf(!ACTIONLINT_INSTALLED)('actionlint on the release-branch renderings', () => {
    it.each(MATRIX.map((flags) => [flags.join(' '), flags] as const))('zero errors with %s', (_label, flags) => {
      const project = makeProject();
      const r = runCli(['ci-init', 'github', '--project', project, '--write', ...flags]);
      expect(r.status).toBe(0);
      const result = spawnSync('actionlint', [join(project, '.github', 'workflows', 'dev-guardian.yml')], { encoding: 'utf8' });
      expect(result.status, `actionlint stdout:\n${result.stdout}\nstderr:\n${result.stderr}`).toBe(0);
    });
  });

  it('no rendering lets setup-node cache dependencies (a poisoned cache would reach a release branch)', () => {
    for (const flags of [[], ['--attest'], ...MATRIX]) {
      const { doc } = renderGithub([...flags]);
      const setup = doc.jobs['scan']?.steps.find((s) => s.uses?.startsWith('actions/setup-node@'));
      expect(setup?.with?.['package-manager-cache'], flags.join(' ')).toBe(false);
      expect(setup?.with?.['cache'], flags.join(' ')).toBeUndefined();
    }
  });

  it.skipIf(!ZIZMOR_INSTALLED)('zizmor accepts the --attest workflow with zero findings', () => {
    const project = makeProject();
    const r = runCli(['ci-init', 'github', '--project', project, '--write', '--attest']);
    expect(r.status).toBe(0);
    const result = spawnSync('zizmor', ['--format=json', join(project, '.github', 'workflows', 'dev-guardian.yml')], {
      encoding: 'utf8',
    });
    const findings: unknown = JSON.parse(result.stdout.trim().length > 0 ? result.stdout : '[]');
    expect(findings, `zizmor findings:\n${JSON.stringify(findings, null, 2)}`).toEqual([]);
  });
});
