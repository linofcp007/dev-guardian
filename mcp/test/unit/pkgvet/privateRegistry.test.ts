import { spawn, spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { customRegistryFor } from '../../../src/pkgvet/privateRegistry.js';
import { MCP_ROOT, TSX_NODE_ARGS } from '../../helpers/tsxNode.js';

let project: string;
let home: string;

beforeEach(() => {
  project = mkdtempSync(join(tmpdir(), 'pkgvet-project-'));
  home = mkdtempSync(join(tmpdir(), 'pkgvet-home-'));
});

afterEach(() => {
  rmSync(project, { recursive: true, force: true });
  rmSync(home, { recursive: true, force: true });
});

// Hermetic: /etc and the node prefix point into the temp home, never at this machine's.
const ctx = (env: Record<string, string> = {}) => ({
  projectDir: project,
  homeDir: home,
  env,
  etcDir: join(home, 'no-etc'),
  nodeExecPath: join(home, 'no-node', 'bin', 'node'),
  systemLibraryDir: join(home, 'no-library'),
});

describe('customRegistryFor — npm', () => {
  it('nothing configured: public', () => {
    expect(customRegistryFor('npm', 'lodash', ctx())).toBeNull();
  });

  it('a project .npmrc registry= makes every name private-capable', () => {
    writeFileSync(join(project, '.npmrc'), 'registry=https://npm.acme.local/\n');
    expect(customRegistryFor('npm', 'lodash', ctx())).toMatchObject({ url: 'https://npm.acme.local/' });
  });

  it('a registry= that IS the public registry is not custom', () => {
    writeFileSync(join(project, '.npmrc'), 'registry=https://registry.npmjs.org/\n');
    expect(customRegistryFor('npm', 'lodash', ctx())).toBeNull();
  });

  it('@scope:registry= applies to that scope only', () => {
    writeFileSync(join(project, '.npmrc'), '@acme:registry=https://npm.acme.local/\n');
    expect(customRegistryFor('npm', '@acme/tools', ctx())).toMatchObject({ url: 'https://npm.acme.local/' });
    expect(customRegistryFor('npm', '@other/tools', ctx())).toBeNull();
    expect(customRegistryFor('npm', 'lodash', ctx())).toBeNull();
  });

  it('the user-level ~/.npmrc counts', () => {
    writeFileSync(join(home, '.npmrc'), 'registry=https://artifactory.acme.local/api/npm/npm/\n');
    expect(customRegistryFor('npm', 'lodash', ctx())).not.toBeNull();
  });

  it('an .npmrc in a parent directory of the project counts', () => {
    const nested = join(project, 'packages', 'web');
    mkdirSync(nested, { recursive: true });
    writeFileSync(join(project, '.npmrc'), 'registry=https://npm.acme.local/\n');
    expect(customRegistryFor('npm', 'lodash', { projectDir: nested, homeDir: home, env: {} })).not.toBeNull();
  });

  it('NPM_CONFIG_REGISTRY counts', () => {
    expect(customRegistryFor('npm', 'lodash', ctx({ NPM_CONFIG_REGISTRY: 'https://npm.acme.local' }))).toMatchObject({
      source: 'NPM_CONFIG_REGISTRY',
    });
    expect(customRegistryFor('npm', 'lodash', ctx({ npm_config_registry: 'https://npm.acme.local' }))).not.toBeNull();
  });

  it('yarn berry .yarnrc.yml: global and per-scope servers', () => {
    writeFileSync(
      join(project, '.yarnrc.yml'),
      'npmScopes:\n  acme:\n    npmRegistryServer: "https://npm.acme.local"\n',
    );
    expect(customRegistryFor('npm', '@acme/x', ctx())).not.toBeNull();
    expect(customRegistryFor('npm', 'lodash', ctx())).toBeNull();
    writeFileSync(join(project, '.yarnrc.yml'), 'npmRegistryServer: "https://npm.acme.local"\n');
    expect(customRegistryFor('npm', 'lodash', ctx())).not.toBeNull();
  });
});

describe('customRegistryFor — PyPI', () => {
  it('nothing configured: public', () => {
    expect(customRegistryFor('pypi', 'requests', ctx())).toBeNull();
  });

  it.each(['PIP_INDEX_URL', 'PIP_EXTRA_INDEX_URL', 'UV_INDEX_URL', 'UV_EXTRA_INDEX_URL'])('%s counts', (name) => {
    expect(customRegistryFor('pypi', 'requests', ctx({ [name]: 'https://pypi.acme.local/simple' }))).toMatchObject({
      source: name,
    });
  });

  it('an index URL that is PyPI itself is not custom', () => {
    expect(customRegistryFor('pypi', 'requests', ctx({ PIP_INDEX_URL: 'https://pypi.org/simple' }))).toBeNull();
  });

  it('pip.conf / pip.ini in the user config locations count', () => {
    mkdirSync(join(home, '.config', 'pip'), { recursive: true });
    writeFileSync(join(home, '.config', 'pip', 'pip.conf'), '[global]\nextra-index-url = https://pypi.acme.local/simple\n');
    expect(customRegistryFor('pypi', 'requests', ctx())).not.toBeNull();
  });

  it('PIP_CONFIG_FILE is honoured', () => {
    const conf = join(home, 'custom-pip.ini');
    writeFileSync(conf, '[global]\nindex-url = https://pypi.acme.local/simple\n');
    expect(customRegistryFor('pypi', 'requests', ctx({ PIP_CONFIG_FILE: conf }))).not.toBeNull();
  });

  it('[[tool.uv.index]] and [[tool.poetry.source]] in pyproject.toml count', () => {
    writeFileSync(join(project, 'pyproject.toml'), '[project]\nname = "x"\n\n[[tool.uv.index]]\nname = "acme"\nurl = "https://pypi.acme.local/simple"\n');
    expect(customRegistryFor('pypi', 'requests', ctx())).not.toBeNull();
    writeFileSync(join(project, 'pyproject.toml'), '[tool.poetry]\nname = "x"\n\n[[tool.poetry.source]]\nname = "acme"\nurl = "https://pypi.acme.local/simple"\n');
    expect(customRegistryFor('pypi', 'requests', ctx())).not.toBeNull();
  });

  it('a pyproject.toml without index configuration is public', () => {
    writeFileSync(join(project, 'pyproject.toml'), '[project]\nname = "x"\ndependencies = ["requests"]\n');
    expect(customRegistryFor('pypi', 'requests', ctx())).toBeNull();
  });
});

describe('customRegistryFor — Composer', () => {
  it('no repositories: public', () => {
    writeFileSync(join(project, 'composer.json'), JSON.stringify({ require: { 'monolog/monolog': '^3' } }));
    expect(customRegistryFor('packagist', 'acme/internal', ctx())).toBeNull();
  });

  it('a repositories entry in composer.json counts', () => {
    writeFileSync(
      join(project, 'composer.json'),
      JSON.stringify({ repositories: [{ type: 'composer', url: 'https://repo.acme.local' }] }),
    );
    expect(customRegistryFor('packagist', 'acme/internal', ctx())).not.toBeNull();
  });
});

describe('fix round 1 — I1: the config locations that were missing', () => {
  let etc: string;
  beforeEach(() => {
    etc = join(home, 'etc');
    mkdirSync(etc, { recursive: true });
  });
  const withEtc = (env: Record<string, string> = {}) => ({ projectDir: project, homeDir: home, env, etcDir: etc });

  it('global pip: /etc/pip.conf', () => {
    writeFileSync(join(etc, 'pip.conf'), '[global]\nindex-url = https://pypi.acme.local/simple\n');
    expect(customRegistryFor('pypi', 'requests', withEtc())).toMatchObject({ kind: 'registry' });
  });

  it('global pip: /etc/xdg/pip/pip.conf', () => {
    mkdirSync(join(etc, 'xdg', 'pip'), { recursive: true });
    writeFileSync(join(etc, 'xdg', 'pip', 'pip.conf'), '[global]\nextra-index-url = https://pypi.acme.local/simple\n');
    expect(customRegistryFor('pypi', 'requests', withEtc())).not.toBeNull();
  });

  it('global pip: %ProgramData%\\pip\\pip.ini', () => {
    const programData = join(home, 'ProgramData');
    mkdirSync(join(programData, 'pip'), { recursive: true });
    writeFileSync(join(programData, 'pip', 'pip.ini'), '[global]\nindex-url = https://pypi.acme.local/simple\n');
    expect(customRegistryFor('pypi', 'requests', withEtc({ ProgramData: programData }))).not.toBeNull();
  });

  it('user uv: ~/.config/uv/uv.toml and %APPDATA%\\uv\\uv.toml', () => {
    mkdirSync(join(home, '.config', 'uv'), { recursive: true });
    writeFileSync(join(home, '.config', 'uv', 'uv.toml'), '[[index]]\nurl = "https://pypi.acme.local/simple"\n');
    expect(customRegistryFor('pypi', 'requests', withEtc())).not.toBeNull();
    rmSync(join(home, '.config'), { recursive: true, force: true });
    const appdata = join(home, 'Roaming');
    mkdirSync(join(appdata, 'uv'), { recursive: true });
    writeFileSync(join(appdata, 'uv', 'uv.toml'), 'index-url = "https://pypi.acme.local/simple"\n');
    expect(customRegistryFor('pypi', 'requests', withEtc({ APPDATA: appdata }))).not.toBeNull();
  });

  it('user yarn: ~/.yarnrc.yml', () => {
    writeFileSync(join(home, '.yarnrc.yml'), 'npmRegistryServer: "https://npm.acme.local"\n');
    expect(customRegistryFor('npm', 'lodash', withEtc())).not.toBeNull();
  });

  it('npm global npmrc via npm_config_globalconfig', () => {
    const globalrc = join(home, 'global-npmrc');
    writeFileSync(globalrc, 'registry=https://npm.acme.local/\n');
    expect(customRegistryFor('npm', 'lodash', withEtc({ npm_config_globalconfig: globalrc }))).not.toBeNull();
    expect(customRegistryFor('npm', 'lodash', withEtc())).toBeNull();
  });

  it('pnpm rc: ~/.config/pnpm/rc and %LOCALAPPDATA%\\pnpm\\config\\rc', () => {
    mkdirSync(join(home, '.config', 'pnpm'), { recursive: true });
    writeFileSync(join(home, '.config', 'pnpm', 'rc'), 'registry=https://npm.acme.local/\n');
    expect(customRegistryFor('npm', 'lodash', withEtc())).not.toBeNull();
    rmSync(join(home, '.config'), { recursive: true, force: true });
    const local = join(home, 'Local');
    mkdirSync(join(local, 'pnpm', 'config'), { recursive: true });
    writeFileSync(join(local, 'pnpm', 'config', 'rc'), 'registry=https://npm.acme.local/\n');
    expect(customRegistryFor('npm', 'lodash', withEtc({ LOCALAPPDATA: local }))).not.toBeNull();
  });
});

describe('fix round 1 — ruling (e): an npmjs auth token means a scoped 404 may be private', () => {
  it.each(['//registry.npmjs.org/:_authToken=${NPM_TOKEN}', '_auth=dXNlcjpwYXNz', '//registry.npmjs.org/:_auth=dXNlcjpwYXNz'])(
    'scoped name + %s → auth',
    (line) => {
      writeFileSync(join(project, '.npmrc'), `${line}\n`);
      expect(customRegistryFor('npm', '@acme/private', ctx())).toMatchObject({ kind: 'auth' });
    },
  );

  it('the token in the user ~/.npmrc counts too', () => {
    writeFileSync(join(home, '.npmrc'), '//registry.npmjs.org/:_authToken=abc\n');
    expect(customRegistryFor('npm', '@acme/private', ctx())).toMatchObject({ kind: 'auth' });
  });

  it('an unscoped name is unaffected by a token (npm has no private unscoped packages)', () => {
    writeFileSync(join(project, '.npmrc'), '//registry.npmjs.org/:_authToken=abc\n');
    expect(customRegistryFor('npm', 'lodash', ctx())).toBeNull();
  });

  it('no token: a scoped name is public', () => {
    expect(customRegistryFor('npm', '@acme/private', ctx())).toBeNull();
  });
});

describe('fix round 1 — ruling (f): a local workspace package is not a missing package', () => {
  it('package.json workspaces', () => {
    writeFileSync(join(project, 'package.json'), JSON.stringify({ name: 'root', workspaces: ['packages/*'] }));
    mkdirSync(join(project, 'packages', 'ui'), { recursive: true });
    writeFileSync(join(project, 'packages', 'ui', 'package.json'), JSON.stringify({ name: '@acme/ui' }));
    expect(customRegistryFor('npm', '@acme/ui', ctx())).toMatchObject({ kind: 'workspace' });
    expect(customRegistryFor('npm', '@acme/other', ctx())).toBeNull();
  });

  it('package.json workspaces in the { packages } form, from inside a member', () => {
    writeFileSync(join(project, 'package.json'), JSON.stringify({ workspaces: { packages: ['apps/*'] } }));
    mkdirSync(join(project, 'apps', 'web'), { recursive: true });
    mkdirSync(join(project, 'apps', 'api'), { recursive: true });
    writeFileSync(join(project, 'apps', 'web', 'package.json'), JSON.stringify({ name: 'web' }));
    writeFileSync(join(project, 'apps', 'api', 'package.json'), JSON.stringify({ name: 'acme-api' }));
    const inMember = { projectDir: join(project, 'apps', 'web'), homeDir: home, env: {} };
    expect(customRegistryFor('npm', 'acme-api', inMember)).toMatchObject({ kind: 'workspace' });
  });

  it('pnpm-workspace.yaml', () => {
    writeFileSync(join(project, 'pnpm-workspace.yaml'), "packages:\n  - 'libs/**'\n");
    mkdirSync(join(project, 'libs', 'core', 'utils'), { recursive: true });
    writeFileSync(join(project, 'libs', 'core', 'utils', 'package.json'), JSON.stringify({ name: 'acme-utils' }));
    expect(customRegistryFor('npm', 'acme-utils', ctx())).toMatchObject({ kind: 'workspace' });
  });

  it('never looks inside node_modules', () => {
    writeFileSync(join(project, 'package.json'), JSON.stringify({ workspaces: ['packages/*'] }));
    mkdirSync(join(project, 'node_modules', 'lodahs'), { recursive: true });
    writeFileSync(join(project, 'node_modules', 'lodahs', 'package.json'), JSON.stringify({ name: 'lodahs' }));
    expect(customRegistryFor('npm', 'lodahs', ctx())).toBeNull();
  });

  it('uv workspace members', () => {
    writeFileSync(join(project, 'pyproject.toml'), '[project]\nname = "root"\n\n[tool.uv.workspace]\nmembers = ["packages/*"]\n');
    mkdirSync(join(project, 'packages', 'core'), { recursive: true });
    writeFileSync(join(project, 'packages', 'core', 'pyproject.toml'), '[project]\nname = "acme-core"\n');
    expect(customRegistryFor('pypi', 'acme_core', ctx())).toMatchObject({ kind: 'workspace' });
    expect(customRegistryFor('pypi', 'requests', ctx())).toBeNull();
  });

  it('composer path repositories (already a custom repository)', () => {
    writeFileSync(join(project, 'composer.json'), JSON.stringify({ repositories: [{ type: 'path', url: 'packages/*' }] }));
    expect(customRegistryFor('packagist', 'acme/local', ctx())).not.toBeNull();
  });
});

describe('fix round 2 — registry context the hook could still miss', () => {
  it('npm default global npmrc on Windows: %APPDATA%\\npm\\etc\\npmrc', () => {
    const appdata = join(home, 'Roaming');
    mkdirSync(join(appdata, 'npm', 'etc'), { recursive: true });
    writeFileSync(join(appdata, 'npm', 'etc', 'npmrc'), 'registry=https://npm.corp.local/\n');
    const c = { projectDir: project, homeDir: home, env: { APPDATA: appdata }, platform: 'win32' as const };
    expect(customRegistryFor('npm', 'lodash', c)).toMatchObject({ kind: 'registry' });
  });

  it('npm default global npmrc on POSIX: <node prefix>/etc/npmrc from the node executable', () => {
    const prefix = join(home, 'usr-local');
    mkdirSync(join(prefix, 'etc'), { recursive: true });
    writeFileSync(join(prefix, 'etc', 'npmrc'), 'registry=https://npm.corp.local/\n');
    const c = { projectDir: project, homeDir: home, env: {}, platform: 'linux' as const, nodeExecPath: join(prefix, 'bin', 'node') };
    expect(customRegistryFor('npm', 'lodash', c)).toMatchObject({ kind: 'registry' });
  });

  it('macOS pip: ~/Library/Application Support/pip/pip.conf', () => {
    const dir = join(home, 'Library', 'Application Support', 'pip');
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, 'pip.conf'), '[global]\nindex-url = https://pypi.corp.local/simple\n');
    expect(customRegistryFor('pypi', 'requests', ctx())).not.toBeNull();
  });

  it('NuGet config is read ABOVE the repository root too, as NuGet does', () => {
    const repo = join(project, 'repo');
    mkdirSync(join(repo, '.git'), { recursive: true });
    writeFileSync(
      join(project, 'NuGet.Config'),
      '<configuration><packageSources><add key="corp" value="https://nuget.corp.local/v3/index.json" /></packageSources></configuration>',
    );
    expect(customRegistryFor('nuget', 'Corp.Lib', { projectDir: repo, homeDir: home, env: {} })).not.toBeNull();
  });

  it.each([
    ['YARN_NPM_REGISTRY_SERVER', 'https://npm.corp.local'],
    ['yarn_npm_registry_server', 'https://npm.corp.local'],
    ['YARN_REGISTRY', 'https://npm.corp.local'],
    ['BUN_CONFIG_REGISTRY', 'https://npm.corp.local'],
    ['npm_config_@corp:registry', 'https://npm.corp.local'],
    ['NPM_CONFIG_REGISTRY', 'https://npm.corp.local'],
  ])('npm: the hook env var %s counts', (name, value) => {
    expect(customRegistryFor('npm', '@corp/x', ctx({ [name]: value }))).toMatchObject({ kind: 'registry', source: name });
  });

  it('npm: an env var pointing at the PUBLIC registry does not (npm test exports npm_config_registry)', () => {
    expect(customRegistryFor('npm', 'lodash', ctx({ npm_config_registry: 'https://registry.npmjs.org/' }))).toBeNull();
  });

  it.each([
    ['pip_index_url', 'https://pypi.corp.local/simple'],
    ['PIP_EXTRA_INDEX_URL', 'https://pypi.corp.local/simple'],
    ['UV_INDEX', 'corp=https://pypi.corp.local/simple'],
    ['UV_INDEX_STRATEGY', 'unsafe-best-match'],
    ['PIP_NO_INDEX', '1'],
  ])('pypi: the hook env var %s counts', (name, value) => {
    expect(customRegistryFor('pypi', 'requests', ctx({ [name]: value }))).toMatchObject({ source: name });
  });

  it('pypi: PIP_NO_INDEX=0 does not', () => {
    expect(customRegistryFor('pypi', 'requests', ctx({ PIP_NO_INDEX: '0' }))).toBeNull();
  });

  // Follow-up Part Y: only a NUGET_* variable that names a source, a feed or a
  // config file counts; NUGET_PACKAGES is the package cache.
  it.each([
    ['NUGET_SOURCE', 'https://nuget.corp.local/v3/index.json'],
    ['nuget_feed_url', 'https://nuget.corp.local/v3/index.json'],
    ['NUGET_RESTORE_CONFIG_FILE', '/ci/nuget.config'],
    ['NuGetPackageSourceCredentials_corp', 'Username=ci;Password=x'],
  ])('nuget: %s counts', (name, value) => {
    expect(customRegistryFor('nuget', 'Corp.Lib', ctx({ [name]: value }))).toMatchObject({ source: name });
  });

  it.each([
    ['NUGET_PACKAGES', '/opt/nuget'],
    ['NUGET_XMLDOC_MODE', 'skip'],
    ['NUGET_HTTP_CACHE_PATH', '/tmp/nuget-http'],
    ['NUGET_CERT_REVOCATION_MODE', 'offline'],
  ])('nuget: %s does not', (name, value) => {
    expect(customRegistryFor('nuget', 'Corp.Lib', ctx({ [name]: value }))).toBeNull();
  });
});

// Follow-up Part Y (item 5): configuration the package managers read that
// this did not — each one a false DENY of a private name waiting to happen.
describe('customRegistryFor — the configuration locations that were still missing (Part Y)', () => {
  const NUGET_CORP =
    '<configuration><packageSources><add key="corp" value="https://nuget.corp.local/v3/index.json" /></packageSources></configuration>';

  it('Yarn Berry reads .yarnrc.yml in every ancestor up to the root — above the repository root too', () => {
    const repo = join(project, 'repo');
    mkdirSync(join(repo, '.git'), { recursive: true });
    writeFileSync(join(project, '.yarnrc.yml'), 'npmRegistryServer: "https://npm.corp.local"\n');
    expect(customRegistryFor('npm', 'corp-lib', { ...ctx(), projectDir: repo })).toMatchObject({
      url: 'https://npm.corp.local',
    });
    // …which is Yarn's rule, not npm's: a parent .npmrc above the repository root still is not read.
    rmSync(join(project, '.yarnrc.yml'));
    writeFileSync(join(project, '.npmrc'), 'registry=https://npm.corp.local/\n');
    expect(customRegistryFor('npm', 'corp-lib', { ...ctx(), projectDir: repo })).toBeNull();
  });

  it('NuGet machine-wide configs: %ProgramFiles(x86)%\\NuGet\\Config\\*.config', () => {
    const pf = join(home, 'pf86');
    mkdirSync(join(pf, 'NuGet', 'Config'), { recursive: true });
    writeFileSync(join(pf, 'NuGet', 'Config', 'Corp.Offline.config'), NUGET_CORP);
    expect(customRegistryFor('nuget', 'Corp.Lib', ctx({ 'ProgramFiles(x86)': pf }))).toMatchObject({
      url: 'https://nuget.corp.local/v3/index.json',
    });
  });

  it('NuGet machine-wide configs: /etc/opt/NuGet/Config/*.config', () => {
    const dir = join(home, 'no-etc', 'opt', 'NuGet', 'Config');
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, 'corp.config'), NUGET_CORP);
    expect(customRegistryFor('nuget', 'Corp.Lib', ctx())).not.toBeNull();
  });

  it('NuGet machine-wide configs: /Library/Application Support/NuGet/Config/*.config (macOS)', () => {
    const lib = join(home, 'Library-system');
    mkdirSync(join(lib, 'Application Support', 'NuGet', 'Config'), { recursive: true });
    writeFileSync(join(lib, 'Application Support', 'NuGet', 'Config', 'corp.config'), NUGET_CORP);
    expect(customRegistryFor('nuget', 'Corp.Lib', { ...ctx(), systemLibraryDir: lib })).not.toBeNull();
  });

  it('NuGet extra user configs: %APPDATA%\\NuGet\\config\\*.config, ~/.nuget/config/*.config', () => {
    const appdata = join(home, 'Roaming');
    mkdirSync(join(appdata, 'NuGet', 'config'), { recursive: true });
    writeFileSync(join(appdata, 'NuGet', 'config', 'corp.config'), NUGET_CORP);
    expect(customRegistryFor('nuget', 'Corp.Lib', ctx({ APPDATA: appdata }))).not.toBeNull();
    rmSync(appdata, { recursive: true, force: true });
    mkdirSync(join(home, '.nuget', 'config'), { recursive: true });
    writeFileSync(join(home, '.nuget', 'config', 'corp.config'), NUGET_CORP);
    expect(customRegistryFor('nuget', 'Corp.Lib', ctx())).not.toBeNull();
  });

  it('a *.config there that names only nuget.org is not custom, and a file not named *.config is not read', () => {
    const dir = join(home, 'no-etc', 'opt', 'NuGet', 'Config');
    mkdirSync(dir, { recursive: true });
    writeFileSync(
      join(dir, 'public.config'),
      '<configuration><packageSources><add key="nuget.org" value="https://api.nuget.org/v3/index.json" /></packageSources></configuration>',
    );
    writeFileSync(join(dir, 'notes.txt'), NUGET_CORP);
    expect(customRegistryFor('nuget', 'Corp.Lib', ctx())).toBeNull();
  });

  it('pip: $CONDA_PREFIX/pip.conf (a conda environment is pip\'s site)', () => {
    const conda = join(home, 'miniconda', 'envs', 'app');
    mkdirSync(conda, { recursive: true });
    writeFileSync(join(conda, 'pip.conf'), '[global]\nindex-url = https://pypi.corp.local/simple\n');
    expect(customRegistryFor('pypi', 'corp-lib', ctx({ CONDA_PREFIX: conda }))).not.toBeNull();
  });

  it('pip: /Library/Application Support/pip/pip.conf (macOS system-wide)', () => {
    const lib = join(home, 'Library-system');
    mkdirSync(join(lib, 'Application Support', 'pip'), { recursive: true });
    writeFileSync(join(lib, 'Application Support', 'pip', 'pip.conf'), '[global]\nindex-url = https://pypi.corp.local/simple\n');
    expect(customRegistryFor('pypi', 'corp-lib', { ...ctx(), systemLibraryDir: lib })).not.toBeNull();
  });
});

describe('customRegistryFor — NuGet', () => {
  it('no nuget.config: public', () => {
    expect(customRegistryFor('nuget', 'Acme.Internal', ctx())).toBeNull();
  });

  it('a nuget.config with only nuget.org is public', () => {
    writeFileSync(
      join(project, 'nuget.config'),
      '<configuration><packageSources><clear /><add key="nuget.org" value="https://api.nuget.org/v3/index.json" /></packageSources></configuration>',
    );
    expect(customRegistryFor('nuget', 'Acme.Internal', ctx())).toBeNull();
  });

  it('a NuGet.Config (any casing) with a non-nuget.org source counts', () => {
    writeFileSync(
      join(project, 'NuGet.Config'),
      '<configuration><packageSources><add key="acme" value="https://nuget.acme.local/v3/index.json" /></packageSources></configuration>',
    );
    expect(customRegistryFor('nuget', 'Acme.Internal', ctx())).toMatchObject({
      url: 'https://nuget.acme.local/v3/index.json',
    });
  });
});

// Task 23 fix round 2, N1: the install hook reads these files synchronously
// inside a 15 s hook budget. A FIFO or a device where a config file belongs
// must never be opened, and an absurdly large one never read.
describe('customRegistryFor — files that are not small regular files are not read', () => {
  it('a directory named .npmrc is ignored, not thrown on', () => {
    mkdirSync(join(project, '.npmrc'));
    expect(customRegistryFor('npm', 'lodash', ctx())).toBeNull();
  });

  it('an .npmrc over the 1 MiB cap is not read', () => {
    writeFileSync(join(project, '.npmrc'), `registry=https://npm.acme.local/\n${'#'.repeat(1024 * 1024)}\n`);
    expect(customRegistryFor('npm', 'lodash', ctx())).toBeNull();
  });

  it.skipIf(process.platform === 'win32')('a FIFO .npmrc is not opened (POSIX only: Windows has no FIFOs)', () => {
    expect(spawnSync('mkfifo', [join(project, '.npmrc')]).status).toBe(0);
    const t0 = Date.now();
    expect(customRegistryFor('npm', 'lodash', ctx())).toBeNull();
    expect(Date.now() - t0).toBeLessThan(1000);
  });
});

/** Whether this account may create symlinks (Windows needs admin or Developer Mode). */
const CAN_SYMLINK = ((): boolean => {
  const probe = mkdtempSync(join(tmpdir(), 'pkgvet-symlink-probe-'));
  try {
    writeFileSync(join(probe, 't'), 'x');
    symlinkSync(join(probe, 't'), join(probe, 'l'));
    return true;
  } catch {
    return false;
  } finally {
    rmSync(probe, { recursive: true, force: true });
  }
})();

// Follow-up Part Y (item 4): these reads had the descriptor checks only. A
// `.npmrc` linked to `\\<unreachable host>\…` held the install hook on its
// open past the 15 s timeout (~136 s was measured for the hook config), and
// the install then ran unvetted. Every read now walks the path's links first,
// as the hook config reader does, and a file reached through a network or
// device link is not read: it is not evidence.
describe('customRegistryFor — a file reached through a network or device link is not opened (Part Y)', () => {
  const WIN = process.platform === 'win32';
  /**
   * On POSIX a link target spelled `//tmp/…` is refused by the walk (a UNC
   * spelling) yet names a LOCAL file — so a reader that follows the link finds
   * the registry in it, and one that walks first does not. Windows has no such
   * spelling to test with: Node stores a `\\?\C:\…` link target as the plain
   * path. There, the unreachable-share test below is the check.
   */
  const POSIX_LINKS = CAN_SYMLINK && !WIN;
  const deviceSpelling = (p: string): string => `/${p}`;
  const corpNpmrc = (): string => {
    const real = join(home, 'real-npmrc');
    writeFileSync(real, 'registry=https://npm.corp.local/\n');
    return real;
  };

  it.skipIf(!POSIX_LINKS)('a project .npmrc linked through a //-spelled target is not read (POSIX with symlinks; skipped otherwise)', () => {
    symlinkSync(deviceSpelling(corpNpmrc()), join(project, '.npmrc'), 'file');
    expect(customRegistryFor('npm', 'lodash', ctx())).toBeNull();
  });

  it.skipIf(!POSIX_LINKS)('a user ~/.npmrc linked that way is not read either (POSIX with symlinks; skipped otherwise)', () => {
    symlinkSync(deviceSpelling(corpNpmrc()), join(home, '.npmrc'), 'file');
    expect(customRegistryFor('npm', 'lodash', ctx())).toBeNull();
  });

  it.skipIf(!POSIX_LINKS)('nor an .npmrc in a parent directory of the project (POSIX with symlinks; skipped otherwise)', () => {
    const nested = join(project, 'packages', 'web');
    mkdirSync(nested, { recursive: true });
    symlinkSync(deviceSpelling(corpNpmrc()), join(project, '.npmrc'), 'file');
    expect(customRegistryFor('npm', 'lodash', { ...ctx(), projectDir: nested })).toBeNull();
  });

  it.skipIf(!POSIX_LINKS)('a user pip directory linked that way is not walked into (POSIX with symlinks; skipped otherwise)', () => {
    const real = join(home, 'real-pip');
    mkdirSync(real);
    writeFileSync(join(real, 'pip.conf'), '[global]\nindex-url = https://pypi.corp.local/simple\n');
    mkdirSync(join(home, '.config'), { recursive: true });
    symlinkSync(deviceSpelling(real), join(home, '.config', 'pip'), 'dir');
    expect(customRegistryFor('pypi', 'requests', ctx())).toBeNull();
  });

  it.skipIf(!POSIX_LINKS)('a user NuGet directory linked that way is not listed (POSIX with symlinks; skipped otherwise)', () => {
    const real = join(home, 'real-nuget');
    mkdirSync(real);
    writeFileSync(
      join(real, 'NuGet.Config'),
      '<configuration><packageSources><add key="corp" value="https://nuget.corp.local/v3/index.json" /></packageSources></configuration>',
    );
    mkdirSync(join(home, '.nuget'), { recursive: true });
    symlinkSync(deviceSpelling(real), join(home, '.nuget', 'NuGet'), 'dir');
    expect(customRegistryFor('nuget', 'Corp.Lib', ctx())).toBeNull();
  });

  it.skipIf(!CAN_SYMLINK)('a local link — absolute or relative — is still followed and read (needs symlink rights; skipped without them)', () => {
    symlinkSync(corpNpmrc(), join(project, '.npmrc'), 'file');
    expect(customRegistryFor('npm', 'lodash', ctx())).toMatchObject({ url: 'https://npm.corp.local/' });
    rmSync(join(project, '.npmrc'));
    mkdirSync(join(project, 'cfg'));
    writeFileSync(join(project, 'cfg', 'npmrc'), 'registry=https://npm.rel.local/\n');
    symlinkSync(join('cfg', 'npmrc'), join(project, '.npmrc'), 'file');
    expect(customRegistryFor('npm', 'lodash', ctx())).toMatchObject({ url: 'https://npm.rel.local/' });
  });

  // The real failure: a link to a share that never answers. Run in a child
  // with a kill, because a blocked synchronous open cannot be interrupted from
  // inside the process. TEST-NET-1 (192.0.2.1) is never routed. On POSIX
  // `//192.0.2.1/…` is a local path, so this can only fail on Windows.
  it.skipIf(!CAN_SYMLINK)(
    'links to an unreachable share — project, parent and user .npmrc, .git, user pip and NuGet directories — cost no wait (needs symlink rights; skipped without them)',
    async () => {
      const UNC = WIN ? '\\\\192.0.2.1\\share' : '//192.0.2.1/share';
      const sep = WIN ? '\\' : '/';
      const app = join(project, 'app');
      mkdirSync(app);
      symlinkSync(`${UNC}${sep}npmrc`, join(app, '.npmrc'), 'file');
      symlinkSync(`${UNC}${sep}parent-npmrc`, join(project, '.npmrc'), 'file');
      symlinkSync(`${UNC}${sep}git`, join(project, '.git'), 'dir');
      symlinkSync(`${UNC}${sep}user-npmrc`, join(home, '.npmrc'), 'file');
      mkdirSync(join(home, '.config'), { recursive: true });
      symlinkSync(`${UNC}${sep}pip`, join(home, '.config', 'pip'), 'dir');
      mkdirSync(join(home, '.nuget'), { recursive: true });
      symlinkSync(`${UNC}${sep}nuget`, join(home, '.nuget', 'NuGet'), 'dir');
      const script = join(home, 'probe.mjs');
      const moduleUrl = pathToFileURL(resolve(MCP_ROOT, 'src', 'pkgvet', 'privateRegistry.ts')).href;
      writeFileSync(
        script,
        `import { customRegistryFor } from ${JSON.stringify(moduleUrl)};\n` +
          'const [projectDir, homeDir] = process.argv.slice(2);\n' +
          "const c = { projectDir, homeDir, env: {}, etcDir: homeDir + '/no-etc', nodeExecPath: homeDir + '/no-node/bin/node' };\n" +
          'const t0 = Date.now();\n' +
          "const r = [customRegistryFor('npm', 'lodash', c), customRegistryFor('pypi', 'requests', c), customRegistryFor('nuget', 'Corp.Lib', c)];\n" +
          'process.stdout.write(JSON.stringify({ r, ms: Date.now() - t0 }));\n',
      );
      const out = await new Promise<{ timedOut: boolean; stdout: string }>((done) => {
        const child = spawn(process.execPath, [...TSX_NODE_ARGS, script, app, home], { stdio: ['ignore', 'pipe', 'pipe'] });
        let stdout = '';
        child.stdout.on('data', (d: Buffer) => {
          stdout += d.toString('utf8');
        });
        const timer = setTimeout(() => {
          child.kill('SIGKILL');
          done({ timedOut: true, stdout });
        }, 45_000);
        child.on('exit', () => {
          clearTimeout(timer);
          done({ timedOut: false, stdout });
        });
      });
      expect(out.timedOut).toBe(false);
      const parsed = JSON.parse(out.stdout) as { r: unknown[]; ms: number };
      expect(parsed.r).toEqual([null, null, null]);
      expect(parsed.ms).toBeLessThan(5000);
    },
    60_000,
  );
});
