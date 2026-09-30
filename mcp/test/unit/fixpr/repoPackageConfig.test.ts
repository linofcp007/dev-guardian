/**
 * `fixpr/repoPackageConfig.ts` — the repository's package-manager
 * configuration is set aside in create_fix_pr's checkouts, a Composer
 * repository refuses Composer's part, and a requirements file that chooses a
 * pip index refuses the install (review of 3.0.0, round 2, item 1).
 */
import { existsSync, mkdirSync, readdirSync, readFileSync, symlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, describe, expect, it, vi } from 'vitest';
import {
  composerChoosesRepository,
  installRefusal,
  setAsidePackageConfig,
} from '../../../src/fixpr/repoPackageConfig.js';
import { packageManagerEnv, userConfigReferences } from '../../../src/fixpr/testCommandEnv.js';
import { applyGroup } from '../../../src/fixpr/apply.js';
import { prepareTestEnvironment } from '../../../src/fixpr/testEnv.js';
import type { FixGroup } from '../../../src/fixpr/types.js';
import type { runProcess } from '../../../src/runners/processRunner.js';
import { CAN_SYMLINK } from '../../helpers/fsCapabilities.js';
import { cleanupTempDirs, makeTempDir } from '../../helpers/tempDir.js';

afterAll(cleanupTempDirs);

function tree(files: Record<string, string>): string {
  const root = makeTempDir('repo-pm-');
  for (const [rel, body] of Object.entries(files)) {
    mkdirSync(join(root, rel, '..'), { recursive: true });
    writeFileSync(join(root, rel), body);
  }
  return root;
}

describe('setAsidePackageConfig', () => {
  it('moves every package-manager configuration out of the project and every directory up to the root, and restores it', () => {
    const root = tree({
      '.npmrc': 'registry=https://attacker.example/\n',
      '.yarnrc.yml': 'npmRegistryServer: https://attacker.example\n',
      'pip.conf': '[global]\nindex-url = https://attacker.example/simple\n',
      '.cargo/config.toml': '[source.crates-io]\nreplace-with = "evil"\n',
      '.cargo/other.toml': 'kept',
      'app/.npmrc': '@acme:registry=https://attacker.example/\n',
      'app/.pnpmrc': 'x',
      'app/.yarnrc': 'x',
      'app/pip.ini': 'x',
      'app/.pip/pip.conf': 'x',
      'app/NuGet.Config': '<configuration/>',
      'app/.bundle/config': 'BUNDLE_MIRROR__HTTPS://RUBYGEMS__ORG/: https://attacker.example\n',
      'app/package.json': '{}',
      'app/src/.npmrc': 'below the project: not read by npm there, left alone',
    });
    const project = join(root, 'app');
    const aside = setAsidePackageConfig(root, project);

    expect(aside.moved.sort()).toEqual(
      [
        '.cargo/config.toml',
        '.npmrc',
        '.yarnrc.yml',
        'pip.conf',
        'app/.bundle/config',
        'app/.npmrc',
        'app/.pip',
        'app/.pnpmrc',
        'app/.yarnrc',
        'app/NuGet.Config',
        'app/pip.ini',
      ].sort(),
    );
    for (const p of aside.moved) expect(existsSync(join(root, p)), p).toBe(false);
    expect(readFileSync(join(root, '.cargo', 'other.toml'), 'utf8')).toBe('kept');
    expect(existsSync(join(root, 'app', 'src', '.npmrc'))).toBe(true);
    expect(existsSync(join(project, 'package.json'))).toBe(true);

    aside.restore();
    aside.restore();
    expect(readFileSync(join(root, '.npmrc'), 'utf8')).toBe('registry=https://attacker.example/\n');
    expect(readFileSync(join(root, 'app', '.pip', 'pip.conf'), 'utf8')).toBe('x');
    aside.dispose();
  });

  it('with nothing to move, moves nothing and creates nothing', () => {
    const root = tree({ 'package.json': '{}' });
    const aside = setAsidePackageConfig(root, root);
    expect(aside.moved).toEqual([]);
    aside.dispose();
  });

  it.skipIf(!CAN_SYMLINK)('moves a link as a link, never following it', () => {
    const outside = makeTempDir('repo-pm-outside-');
    writeFileSync(join(outside, 'npmrc'), 'the user file');
    const root = tree({ 'package.json': '{}' });
    symlinkSync(join(outside, 'npmrc'), join(root, '.npmrc'), 'file');
    const aside = setAsidePackageConfig(root, root);
    expect(aside.moved).toEqual(['.npmrc']);
    expect(readFileSync(join(outside, 'npmrc'), 'utf8')).toBe('the user file');
    expect(readdirSync(outside)).toEqual(['npmrc']);
    aside.restore();
    aside.dispose();
  });
});

describe('composerChoosesRepository', () => {
  it('refuses a composer.json that declares repositories, and passes one that does not', () => {
    expect(composerChoosesRepository(tree({ 'composer.json': '{"repositories":[{"type":"composer","url":"https://x"}]}' }))).toMatch(
      /repositories/,
    );
    expect(composerChoosesRepository(tree({ 'composer.json': '{"repositories":{"x":{"type":"vcs","url":"u"}}}' }))).not.toBeNull();
    expect(composerChoosesRepository(tree({ 'composer.json': '{"require":{}}' }))).toBeNull();
    expect(composerChoosesRepository(tree({ 'composer.json': '{"repositories":[]}' }))).toBeNull();
  });
});

describe('installRefusal', () => {
  const pipIndex = tree({ 'requirements.txt': 'django==3.2.0\n--index-url https://attacker.example/simple\n' });

  it('refuses a pip step where the requirements choose an index, naming the file, the line and the option', () => {
    expect(
      installRefusal({ projectDir: pipIndex, stepEcosystems: ['pip'], stepFiles: ['requirements.txt'], rescanTools: ['scan_deps'] }),
    ).toBe(
      "the project's Python requirements name where pip installs from, or could not be checked " +
        '(requirements.txt:2: index option (--index-url, https://attacker.example)); ' +
        'dev-guardian installs only plain requirements it has read — a name, extras, versions and markers',
    );
  });

  it("refuses any group deps_audit re-scans there: its pip-audit installs every requirements file", () => {
    expect(installRefusal({ projectDir: pipIndex, stepEcosystems: ['npm'], stepFiles: [], rescanTools: ['deps_audit'] })).toMatch(
      /index option/,
    );
  });

  it('lets an npm group re-scanned by scan_deps through, and a clean project', () => {
    expect(installRefusal({ projectDir: pipIndex, stepEcosystems: ['npm'], stepFiles: [], rescanTools: ['scan_deps'] })).toBeNull();
    const clean = tree({ 'requirements.txt': 'django==3.2.0\n' });
    expect(installRefusal({ projectDir: clean, stepEcosystems: ['pip'], stepFiles: ['requirements.txt'], rescanTools: ['deps_audit'] })).toBeNull();
  });

  it('refuses a Composer step where composer.json declares repositories', () => {
    const dir = tree({ 'composer.json': '{"repositories":[{"type":"composer","url":"https://attacker.example"}]}' });
    expect(installRefusal({ projectDir: dir, stepEcosystems: ['composer'], stepFiles: [], rescanTools: [] })).toMatch(/repositories/);
  });

  it('refuses an npm install where a dependency points at a network path, naming it by host', () => {
    const dir = tree({ 'package.json': JSON.stringify({ dependencies: { a: '1.0.0', b: 'file:\\\\evil.invalid\\share\\b' } }) });
    expect(installRefusal({ projectDir: dir, stepEcosystems: ['npm'], stepFiles: [], rescanTools: [] })).toBe(
      "the project's npm dependencies point at a network path (package.json: dependencies.b (\\\\evil.invalid)); " +
        "dev-guardian doesn't install from a network path",
    );
    // No npm install in this checkout: nothing to refuse.
    expect(installRefusal({ projectDir: dir, stepEcosystems: ['pip'], stepFiles: [], rescanTools: [] })).toBeNull();
    expect(installRefusal({ projectDir: dir, stepEcosystems: [], stepFiles: [], rescanTools: [], npmInstalls: true })).toMatch(/network path/);
  });
});


describe('packageManagerEnv', () => {
  it("keeps the allowlist, the package managers' own configuration, and what the user's ~/.npmrc references — nothing else", () => {
    const home = makeTempDir('repo-pm-home-');
    writeFileSync(join(home, '.npmrc'), '//npm.internal.example/:_authToken=${NPM_TOKEN}\nemail=${NPM_EMAIL:-x}\n');
    const env = packageManagerEnv(
      {
        PATH: '/usr/bin',
        HOME: home,
        NPM_TOKEN: 'user-token',
        NPM_EMAIL: 'me@example.com',
        GITHUB_TOKEN: 'ghp_x',
        AWS_SECRET_ACCESS_KEY: 's',
        GUARDIAN_DATA_DIR: '/g',
        NPM_CONFIG_REGISTRY: 'https://npm.internal.example/',
        PIP_INDEX_URL: 'https://pypi.internal.example/simple',
        CARGO_REGISTRIES_INTERNAL_TOKEN: 't',
        GOPROXY: 'https://proxy.internal.example',
        HTTPS_PROXY: 'http://proxy:3128',
      },
      home,
    );
    expect(env).toEqual({
      PATH: '/usr/bin',
      HOME: home,
      NPM_TOKEN: 'user-token',
      NPM_EMAIL: 'me@example.com',
      NPM_CONFIG_REGISTRY: 'https://npm.internal.example/',
      PIP_INDEX_URL: 'https://pypi.internal.example/simple',
      CARGO_REGISTRIES_INTERNAL_TOKEN: 't',
      GOPROXY: 'https://proxy.internal.example',
      HTTPS_PROXY: 'http://proxy:3128',
    });
  });

  it('reads the file NPM_CONFIG_USERCONFIG names instead of ~/.npmrc', () => {
    const home = makeTempDir('repo-pm-home-');
    const cfg = join(home, 'custom-npmrc');
    writeFileSync(cfg, '//r/:_authToken=${MY_TOKEN}\n');
    expect(userConfigReferences([cfg])).toEqual(['MY_TOKEN']);
    const env = packageManagerEnv({ MY_TOKEN: 'm', NPM_CONFIG_USERCONFIG: cfg, OTHER_TOKEN: 'o' }, home);
    expect(env).toEqual({ MY_TOKEN: 'm', NPM_CONFIG_USERCONFIG: cfg });
  });
});

describe('the package-manager processes create_fix_pr runs directly', () => {
  it('applyGroup runs an npm step with extendEnv: false and no token the user did not configure', async () => {
    vi.stubEnv('GITHUB_TOKEN', 'ghp_never');
    try {
      const seen: Array<Parameters<typeof runProcess>[0]> = [];
      const run = (async (o: Parameters<typeof runProcess>[0]) => {
        seen.push(o);
        return { outcome: 'completed', exitCode: 0, stdout: '', stderr: '', truncated: false };
      }) as unknown as typeof runProcess;
      const group = {
        source: 'deps',
        key: 'npm',
        hash: 'h',
        severity: 'high',
        candidates: [
          {
            label: 'x',
            fingerprints: ['f'],
            steps: [{ ecosystem: 'npm', package_name: 'x', installed_version: '1', latest_version: '2', upgrade_command: 'npm install x@2' }],
          },
        ],
      } as unknown as FixGroup;
      const r = await applyGroup({ group, worktreePath: makeTempDir('repo-pm-wt-'), lockfileOnly: false, run });
      expect(r.applied).toBe(true);
      expect(seen[0]?.extendEnv).toBe(false);
      expect(seen[0]?.env).toBeDefined();
      expect(seen[0]?.env?.['GITHUB_TOKEN']).toBeUndefined();
    } finally {
      vi.unstubAllEnvs();
    }
  });

  it('prepareTestEnvironment runs npm ci with extendEnv: false', async () => {
    const dir = tree({ 'package.json': '{}', 'package-lock.json': '{}' });
    const seen: Array<Parameters<typeof runProcess>[0]> = [];
    const run = (async (o: Parameters<typeof runProcess>[0]) => {
      seen.push(o);
      return { outcome: 'completed', exitCode: 0, stdout: '', stderr: '', truncated: false };
    }) as unknown as typeof runProcess;
    await prepareTestEnvironment({ treePath: dir, derived: { command: 'npm', args: ['test'], origin: 'x' }, run });
    const ci = seen.find((o) => o.command === 'npm');
    expect(ci?.extendEnv).toBe(false);
    expect(ci?.env).toBeDefined();
  });
});
