import { spawn, spawnSync } from 'node:child_process';
import { chmodSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { customRegistryFor, isPublicRegistryUrl, npmScopeRegistry, type RegistryContext } from '../../../src/pkgvet/privateRegistry.js';
import { MCP_ROOT, TSX_NODE_ARGS } from '../../helpers/tsxNode.js';
import { hangBound } from '../../helpers/timing.js';

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
    // Fix round 1 (M3): fallback folders are package sources too.
    ['NUGET_FALLBACK_PACKAGES', '/opt/nuget-fallback'],
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

  // Fix round 1 (M2): Visual Studio installs a machine-wide
  // Microsoft.VisualStudio.Offline.config whose one source is a LOCAL folder
  // of the packages VS ships. It explains a 404 only for a package that folder
  // actually holds — otherwise it turned the missing-name deny off on every
  // machine with Visual Studio.
  describe('a local-folder source in a machine-wide config (the Visual Studio offline feed)', () => {
    const offlineFeed = (): string => {
      const pf = join(home, 'pf86');
      const feed = join(pf, 'Microsoft SDKs', 'NuGetPackages');
      mkdirSync(feed, { recursive: true });
      mkdirSync(join(pf, 'NuGet', 'Config'), { recursive: true });
      writeFileSync(
        join(pf, 'NuGet', 'Config', 'Microsoft.VisualStudio.Offline.config'),
        `<?xml version="1.0" encoding="utf-8"?><configuration><packageSources><add key="Microsoft Visual Studio Offline Packages" value="${feed}\\" /></packageSources></configuration>`,
      );
      return feed;
    };
    const vsCtx = () => ctx({ 'ProgramFiles(x86)': join(home, 'pf86') });

    it('does not explain a package the folder does not hold', () => {
      offlineFeed();
      expect(customRegistryFor('nuget', 'Acme.Totally.Missing.Pkg', vsCtx())).toBeNull();
    });

    it('explains one it holds — flat `<id>.<version>.nupkg` or hierarchical `<id>/`, any casing', () => {
      const feed = offlineFeed();
      writeFileSync(join(feed, 'Microsoft.VisualStudio.Shipped.1.2.3.nupkg'), '');
      expect(customRegistryFor('nuget', 'microsoft.visualstudio.shipped', vsCtx())).toMatchObject({ kind: 'registry' });
      mkdirSync(join(feed, 'corp.offline.lib'));
      expect(customRegistryFor('nuget', 'Corp.Offline.Lib', vsCtx())).toMatchObject({ kind: 'registry' });
    });

    // Fix round 2: the id ends where the version begins — at the first
    // dot-separated segment from which the rest parses as a NuGet version.
    it.each([
      ['Foo', 'Foo.2FA.1.0.0.nupkg', false],
      ['Foo.2FA', 'Foo.2FA.1.0.0.nupkg', true],
      ['Foo', 'Foo.1.0.0-beta.1.nupkg', true],
      ['Foo', 'Foo.2.1.0.0.nupkg', true],
      ['Foo', 'Foo.1.0.0+build.5.nupkg', true],
      ['Foo', 'Foo.Bar.1.0.0.nupkg', false],
      ['Foo', 'Foo.nupkg', false],
      // Fix round 3: every split where `id.` is followed by a version counts —
      // `foo.2.1.0.0` is `foo` 2.1.0.0 AND `foo.2` 1.0.0.
      ['foo.2', 'foo.2.1.0.0.nupkg', true],
      ['foo.2.1', 'foo.2.1.0.0.nupkg', true],
    ] as const)('%s held by %s: %s', (id, file, held) => {
      const feed = offlineFeed();
      writeFileSync(join(feed, file), '');
      const r = customRegistryFor('nuget', id, vsCtx());
      if (held) expect(r).toMatchObject({ kind: 'registry' });
      else expect(r).toBeNull();
    });

    it('a package whose name only starts the same does not count', () => {
      const feed = offlineFeed();
      writeFileSync(join(feed, 'Corp.Lib.Extra.1.0.0.nupkg'), '');
      expect(customRegistryFor('nuget', 'Corp.Lib', vsCtx())).toBeNull();
    });

    it('a URL source in the same machine-wide directory still counts for every name', () => {
      offlineFeed();
      writeFileSync(
        join(home, 'pf86', 'NuGet', 'Config', 'Corp.config'),
        '<configuration><packageSources><add key="corp" value="https://nuget.corp.local/v3/index.json" /></packageSources></configuration>',
      );
      expect(customRegistryFor('nuget', 'Acme.Totally.Missing.Pkg', vsCtx())).toMatchObject({ url: 'https://nuget.corp.local/v3/index.json' });
    });

    it('a local folder in a PROJECT nuget.config still counts for every name, as before', () => {
      writeFileSync(
        join(project, 'nuget.config'),
        '<configuration><packageSources><add key="local" value="./packages" /></packageSources></configuration>',
      );
      expect(customRegistryFor('nuget', 'Acme.Totally.Missing.Pkg', ctx())).toMatchObject({ kind: 'registry' });
    });
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
//
// Part Y fix round 1 (controller ruling): a registry configuration that is
// there but was not read is UNKNOWN, never absent — it may well name a private
// registry. It is reported as `unreadable`, which turns a missing-name deny
// into a warning, exactly as a readable private registry does.
describe('customRegistryFor — files that are not small regular files are not read, and are unknown', () => {
  const unreadable = (path: string): unknown => ({ kind: 'unreadable', source: path, what: 'configuration' });

  it('a directory named .npmrc is not read, and is not "no registry"', () => {
    mkdirSync(join(project, '.npmrc'));
    expect(customRegistryFor('npm', 'lodash', ctx())).toEqual(unreadable(join(project, '.npmrc')));
  });

  it('an .npmrc over the 1 MiB cap is not read, and is not "no registry"', () => {
    writeFileSync(join(project, '.npmrc'), `registry=https://npm.acme.local/\n${'#'.repeat(1024 * 1024)}\n`);
    expect(customRegistryFor('npm', 'lodash', ctx())).toEqual(unreadable(join(project, '.npmrc')));
  });

  it.skipIf(process.platform === 'win32')('a FIFO .npmrc is not opened, and is not "no registry" (POSIX only: Windows has no FIFOs)', () => {
    expect(spawnSync('mkfifo', [join(project, '.npmrc')]).status).toBe(0);
    const t0 = Date.now();
    expect(customRegistryFor('npm', 'lodash', ctx())).toEqual(unreadable(join(project, '.npmrc')));
    expect(Date.now() - t0).toBeLessThan(hangBound(1000));
  });

  it('a registry found elsewhere still wins over an unreadable file', () => {
    mkdirSync(join(project, '.npmrc'));
    writeFileSync(join(home, '.npmrc'), 'registry=https://npm.corp.local/\n');
    expect(customRegistryFor('npm', 'lodash', ctx())).toMatchObject({ kind: 'registry', url: 'https://npm.corp.local/' });
  });

  it('every ecosystem: pip.conf, composer.json, nuget.config', () => {
    mkdirSync(join(home, '.config', 'pip', 'pip.conf'), { recursive: true });
    expect(customRegistryFor('pypi', 'corp-lib', ctx())).toEqual(unreadable(join(home, '.config', 'pip', 'pip.conf')));
    mkdirSync(join(project, 'composer.json'));
    expect(customRegistryFor('packagist', 'corp/lib', ctx())).toEqual(unreadable(join(project, 'composer.json')));
    mkdirSync(join(project, 'nuget.config'));
    expect(customRegistryFor('nuget', 'Corp.Lib', ctx())).toEqual(unreadable(join(project, 'nuget.config')));
  });

  // Fix round 2: the message names what was refused, not always "registry configuration".
  it('an unreadable WORKSPACE MANIFEST is named as one', () => {
    writeFileSync(join(project, 'package.json'), JSON.stringify({ name: 'root', workspaces: ['packages/*'] }));
    mkdirSync(join(project, 'packages', 'a', 'package.json'), { recursive: true });
    expect(customRegistryFor('npm', 'corp-lib', ctx())).toEqual({
      kind: 'unreadable',
      source: join(project, 'packages', 'a', 'package.json'),
      what: 'workspace manifest',
    });
  });

  it.skipIf(process.platform === 'win32' || (typeof process.getuid === 'function' && process.getuid() === 0))(
    'an ancestor directory that cannot be listed is named as a directory (POSIX, not root)',
    () => {
      const sub = join(project, 'sub');
      mkdirSync(sub);
      chmodSync(project, 0o300);
      try {
        expect(customRegistryFor('nuget', 'Corp.Lib', { ...ctx(), projectDir: sub })).toEqual({
          kind: 'unreadable',
          source: project,
          what: 'directory',
        });
      } finally {
        chmodSync(project, 0o700);
      }
    },
  );

  it('an absent file is absent: nothing configured is still public', () => {
    expect(customRegistryFor('npm', 'lodash', ctx())).toBeNull();
    expect(customRegistryFor('pypi', 'requests', ctx())).toBeNull();
    expect(customRegistryFor('nuget', 'Corp.Lib', ctx())).toBeNull();
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
// device link is not read. It is UNKNOWN, not absent (fix round 1): it may
// name a private registry, so a missing name there warns instead of denying.
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
    expect(customRegistryFor('npm', 'lodash', ctx())).toEqual({ kind: 'unreadable', source: join(project, '.npmrc'), what: 'configuration' });
  });

  it.skipIf(!POSIX_LINKS)('a user ~/.npmrc linked that way is not read either (POSIX with symlinks; skipped otherwise)', () => {
    symlinkSync(deviceSpelling(corpNpmrc()), join(home, '.npmrc'), 'file');
    expect(customRegistryFor('npm', 'lodash', ctx())).toEqual({ kind: 'unreadable', source: join(home, '.npmrc'), what: 'configuration' });
  });

  it.skipIf(!POSIX_LINKS)('nor an .npmrc in a parent directory of the project (POSIX with symlinks; skipped otherwise)', () => {
    const nested = join(project, 'packages', 'web');
    mkdirSync(nested, { recursive: true });
    symlinkSync(deviceSpelling(corpNpmrc()), join(project, '.npmrc'), 'file');
    expect(customRegistryFor('npm', 'lodash', { ...ctx(), projectDir: nested })).toEqual({
      kind: 'unreadable',
      source: join(project, '.npmrc'),
      what: 'configuration',
    });
  });

  it.skipIf(!POSIX_LINKS)('a user pip directory linked that way is not walked into (POSIX with symlinks; skipped otherwise)', () => {
    const real = join(home, 'real-pip');
    mkdirSync(real);
    writeFileSync(join(real, 'pip.conf'), '[global]\nindex-url = https://pypi.corp.local/simple\n');
    mkdirSync(join(home, '.config'), { recursive: true });
    symlinkSync(deviceSpelling(real), join(home, '.config', 'pip'), 'dir');
    expect(customRegistryFor('pypi', 'requests', ctx())).toEqual({
      kind: 'unreadable',
      source: join(home, '.config', 'pip', 'pip.conf'),
      what: 'configuration',
    });
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
    expect(customRegistryFor('nuget', 'Corp.Lib', ctx())).toEqual({ kind: 'unreadable', source: join(home, '.nuget', 'NuGet'), what: 'directory' });
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
      expect(parsed.r).toEqual([
        { kind: 'unreadable', source: join(app, '.npmrc'), what: 'configuration' },
        { kind: 'unreadable', source: join(home, '.config', 'pip', 'pip.conf'), what: 'configuration' },
        { kind: 'unreadable', source: join(home, '.nuget', 'NuGet'), what: 'directory' },
      ]);
      expect(parsed.ms).toBeLessThan(hangBound(5000));
    },
    60_000,
  );
});

// T-18: the registries the USER's npm configuration names. A lockfile package
// fetched from one of them is the user's own choice, and the hook says nothing
// of it; a registry a file of the PROJECT names never counts — the project is
// what is being vetted.
describe('install-vet-lockfile-pins', () => {
  type UserRegistries = (ctx?: RegistryContext) => string[];

  /** `npmUserRegistries`, reached at run time: the export is new, and a static import of it would stop every test of this file. */
  async function userRegistries(): Promise<UserRegistries> {
    const mod: Record<string, unknown> = await import('../../../src/pkgvet/privateRegistry.js');
    const fn = mod['npmUserRegistries'];
    if (typeof fn !== 'function') throw new Error('src/pkgvet/privateRegistry.ts does not export `npmUserRegistries` yet');
    return fn as UserRegistries;
  }

  /** The URLs listed, sorted and once each: neither their order nor a URL named in two places is the contract. */
  const listed = async (c: RegistryContext): Promise<string[]> => [...new Set((await userRegistries())(c))].sort();

  it('T-18 `registry=` and `@scope:registry=` of the user npmrc, each with a trailing slash — and never the credential beside them', async () => {
    writeFileSync(
      join(home, '.npmrc'),
      [
        '; the default registry, and a scope with one of its own',
        'registry=https://npm.acme.example/team',
        '@corp:registry=https://npm.corp.example/api/npm/',
        '//npm.acme.example/team/:_authToken=invented-token-0000',
        '',
      ].join('\n'),
    );
    expect(await listed(ctx())).toEqual(['https://npm.acme.example/team/', 'https://npm.corp.example/api/npm/']);
  });

  it('T-18 the user npmrc is the file NPM_CONFIG_USERCONFIG names, when it names one', async () => {
    const named = join(home, 'ci-npmrc');
    writeFileSync(named, 'registry=https://ci.acme.example/npm\n');
    expect(await listed(ctx({ NPM_CONFIG_USERCONFIG: named }))).toEqual(['https://ci.acme.example/npm/']);
  });

  it('T-18 the global npmrc: the file npm_config_globalconfig names, and npm’s default one on Windows and on POSIX', async () => {
    const named = join(home, 'global-npmrc');
    writeFileSync(named, 'registry=https://global.acme.example\n@corp:registry=https://global.corp.example/npm\n');
    expect(await listed(ctx({ npm_config_globalconfig: named }))).toEqual(['https://global.acme.example/', 'https://global.corp.example/npm/']);

    const appdata = join(home, 'Roaming');
    mkdirSync(join(appdata, 'npm', 'etc'), { recursive: true });
    writeFileSync(join(appdata, 'npm', 'etc', 'npmrc'), 'registry=https://windows.acme.example/\n');
    expect(await listed({ ...ctx({ APPDATA: appdata }), platform: 'win32' })).toEqual(['https://windows.acme.example/']);

    const prefix = join(home, 'usr-local');
    mkdirSync(join(prefix, 'etc'), { recursive: true });
    writeFileSync(join(prefix, 'etc', 'npmrc'), 'registry=https://posix.acme.example/\n');
    expect(await listed({ ...ctx(), platform: 'linux', nodeExecPath: join(prefix, 'bin', 'node') })).toEqual(['https://posix.acme.example/']);
  });

  it.each([
    ['npm_config_registry', 'https://env.acme.example/npm', 'https://env.acme.example/npm/'],
    ['NPM_CONFIG_REGISTRY', 'https://env.acme.example/npm/', 'https://env.acme.example/npm/'],
    ['npm_config_@corp:registry', 'https://env.corp.example', 'https://env.corp.example/'],
    ['YARN_NPM_REGISTRY_SERVER', 'https://yarn.acme.example', 'https://yarn.acme.example/'],
    ['YARN_REGISTRY', 'https://classic.acme.example/', 'https://classic.acme.example/'],
    ['BUN_CONFIG_REGISTRY', 'https://bun.acme.example/npm', 'https://bun.acme.example/npm/'],
  ])('T-18 the environment variable %s names one', async (name, value, url) => {
    expect(await listed(ctx({ [name]: value }))).toEqual([url]);
  });

  it('T-18 ~/.yarnrc.yml (`npmRegistryServer`, `npmScopes`) and ~/.bunfig.toml (`[install] registry`, `[install.scopes]`)', async () => {
    writeFileSync(
      join(home, '.yarnrc.yml'),
      'npmRegistryServer: "https://yarn.acme.example"\nnpmScopes:\n  corp:\n    npmRegistryServer: "https://yarn.corp.example/npm"\n',
    );
    expect(await listed(ctx())).toEqual(['https://yarn.acme.example/', 'https://yarn.corp.example/npm/']);

    rmSync(join(home, '.yarnrc.yml'));
    writeFileSync(
      join(home, '.bunfig.toml'),
      '[install]\nregistry = "https://bun.acme.example/"\n\n[install.scopes]\n"@corp" = { url = "https://bun.corp.example/npm", token = "$BUN_TOKEN" }\n',
    );
    expect(await listed(ctx())).toEqual(['https://bun.acme.example/', 'https://bun.corp.example/npm/']);
  });

  it('T-18 never a file of the project: an .npmrc, .yarnrc.yml, .yarnrc or bunfig.toml in the command’s directory or above it, up to the repository root, names none', async () => {
    const repo = join(project, 'repo');
    const member = join(repo, 'packages', 'web');
    mkdirSync(join(repo, '.git'), { recursive: true });
    mkdirSync(member, { recursive: true });
    writeFileSync(join(repo, '.npmrc'), 'registry=https://evil.example/npm/\n@corp:registry=https://evil.example/corp/\n');
    writeFileSync(join(member, '.npmrc'), 'registry=https://evil.example/member/\n');
    writeFileSync(
      join(member, '.yarnrc.yml'),
      'npmRegistryServer: "https://evil.example/yarn"\nnpmScopes:\n  corp:\n    npmRegistryServer: "https://evil.example/yarn-corp"\n',
    );
    writeFileSync(join(member, '.yarnrc'), 'registry "https://evil.example/classic"\n');
    writeFileSync(join(member, 'bunfig.toml'), '[install]\nregistry = "https://evil.example/bun/"\n\n[install.scopes]\n"@corp" = "https://evil.example/bun-corp/"\n');
    expect(await listed({ ...ctx(), projectDir: member })).toEqual([]);
    expect(await listed({ ...ctx(), projectDir: repo })).toEqual([]);

    // The user's own is listed beside them — and it alone.
    writeFileSync(join(home, '.npmrc'), 'registry=https://npm.acme.example/\n');
    expect(await listed({ ...ctx(), projectDir: member })).toEqual(['https://npm.acme.example/']);
  });

  it('T-18 the public registry is not one — named in a file or in the environment', async () => {
    writeFileSync(join(home, '.npmrc'), 'registry=https://registry.npmjs.org/\n@corp:registry=https://registry.npmjs.org\n');
    writeFileSync(join(home, '.yarnrc.yml'), 'npmRegistryServer: "https://registry.yarnpkg.com"\n');
    expect(await listed(ctx({ npm_config_registry: 'https://registry.npmjs.org/' }))).toEqual([]);
  });

  it('T-18 a configuration that cannot be read names none, and nothing is thrown: a directory where the user npmrc belongs, a file over the size cap', async () => {
    mkdirSync(join(home, '.npmrc'));
    expect(await listed(ctx())).toEqual([]);

    rmSync(join(home, '.npmrc'), { recursive: true });
    writeFileSync(join(home, '.npmrc'), `registry=https://npm.acme.example/\n${'#'.repeat(1024 * 1024)}\n`);
    expect(await listed(ctx())).toEqual([]);
  });

  it('T-18 a value that is not an http(s) URL is not listed: a variable left unexpanded, a setting that merely has "registry" in its name', async () => {
    writeFileSync(join(home, '.npmrc'), 'registry=${NPM_REGISTRY_URL}\n');
    expect(await listed(ctx({ npm_config_replace_registry_host: 'never' }))).toEqual([]);
  });
  it('T-24 (US-1.AC-12, US-1.AC-22) the prepared scope lookup answers as `npmScopeRegistry` does, and reads the configuration once however many scopes it is asked', async () => {
    const mod = await import('../../../src/pkgvet/privateRegistry.js');
    const { npmScopeRegistry, npmScopeRegistryOf, registryCache } = mod;
    writeFileSync(join(home, '.npmrc'), '@mine:registry=https://npm.user.example/\n@npmjs:registry=https://registry.npmjs.org/\nregistry=https://npm.default.example/\n');
    writeFileSync(join(project, '.npmrc'), '@team:registry=https://npm.team.example/\n');
    const names = ['@mine/a', '@team/b', '@plain/c', 'unscoped', '@npmjs/d', '@mine/other', '@env/e'];
    const withEnv = ctx({ 'npm_config_@env:registry': 'https://npm.env.example/' });
    const expected = names.map((n) => npmScopeRegistry(n, withEnv));
    expect(expected.map((r) => r?.from ?? null)).toEqual(['user', 'project', null, null, null, 'user', 'user']);

    // Reads of a configuration file, counted at the cache the lookups share.
    let gets = 0;
    const cache = registryCache();
    const reads = cache.reads;
    cache.reads = new Proxy(reads, {
      get(target, prop) {
        if (prop === 'get') {
          return (key: string) => {
            gets += 1;
            return target.get(key);
          };
        }
        const value: unknown = Reflect.get(target, prop, target);
        return typeof value === 'function' ? (value as (...a: unknown[]) => unknown).bind(target) : value;
      },
    });
    const lookup = npmScopeRegistryOf({ ...withEnv, cache });
    expect(lookup('unscoped')).toBeNull();
    expect(gets).toBe(0);
    expect(lookup('@mine/a')).toEqual(expected[0]);
    const afterOne = gets;
    expect(afterOne).toBeGreaterThan(0);
    expect(names.map((n) => lookup(n))).toEqual(expected);
    expect(names.map((n) => lookup(n))).toEqual(expected);
    expect(gets).toBe(afterOne);
  });

});

// ───────────────── pkgvet-public-registry-url-parse — a URL is the public registry by its HOST, not by its first characters

describe('pkgvet-public-registry-url-parse', () => {
  const PUBLIC_HOSTS = {
    npm: ['registry.npmjs.org', 'registry.npmjs.com', 'registry.yarnpkg.com'],
    pypi: ['pypi.org', 'pypi.python.org', 'files.pythonhosted.org'],
    packagist: ['packagist.org', 'repo.packagist.org'],
    nuget: ['api.nuget.org', 'www.nuget.org', 'nuget.org'],
  } as const;
  const ECOSYSTEMS = Object.keys(PUBLIC_HOSTS) as Array<keyof typeof PUBLIC_HOSTS>;
  const SCHEMES = ['https://', 'http://', '//'];

  /** The ecosystems and public hosts for which the answer on `urlOf(scheme, host)` is not `expected`, one line each. */
  const wrongAnswers = (urlOf: (scheme: string, host: string) => string, expected: boolean, schemes: string[] = SCHEMES): string[] => {
    const wrong: string[] = [];
    for (const eco of ECOSYSTEMS) {
      for (const host of PUBLIC_HOSTS[eco]) {
        for (const scheme of schemes) {
          const url = urlOf(scheme, host);
          if (isPublicRegistryUrl(eco, url) !== expected) wrong.push(`${eco}: ${JSON.stringify(url)}`);
        }
      }
    }
    return wrong;
  };

  // Built from pieces: no literal `scheme://user:password@host` stands in the test source.
  const withUser = (scheme: string, host: string, user: string, tail = '/'): string => [scheme, host, user, '@', 'evil.example', tail].join('');

  it('T-01 a URL whose authority carries credentials is another registry, in all four ecosystems and for every public host', () => {
    for (const user of [':x', ':', ':443']) {
      expect(wrongAnswers((scheme, host) => withUser(scheme, host, user), false), `credentials "${user}" before the @`).toEqual([]);
    }
  });

  it('T-02 the plain forms of a public host stay public; another host, a suffix, a trailing dot, a user@ and a value that is not a URL stay another registry', () => {
    // Public, as today: any scheme, with or without the slash or a path, the scheme's own port, upper case, quotes, white space at the ends.
    expect(wrongAnswers((scheme, host) => `${scheme}${host}/`, true), 'the host and a slash').toEqual([]);
    expect(wrongAnswers((scheme, host) => `${scheme}${host}`, true), 'the host alone').toEqual([]);
    expect(wrongAnswers((scheme, host) => `${scheme}${host}/simple/`, true), 'a path').toEqual([]);
    expect(wrongAnswers((_scheme, host) => `https://${host}:443/`, true), 'https and 443').toEqual([]);
    expect(wrongAnswers((_scheme, host) => `//${host}:443/`, true), 'no scheme and 443').toEqual([]);
    expect(wrongAnswers((_scheme, host) => `http://${host}:80/`, true), 'http and 80').toEqual([]);
    expect(wrongAnswers((scheme, host) => `${scheme.toUpperCase()}${host.toUpperCase()}/`, true), 'upper case').toEqual([]);
    expect(wrongAnswers((scheme, host) => `"${scheme}${host}/"`, true), 'double quotes').toEqual([]);
    expect(wrongAnswers((scheme, host) => `'${scheme}${host}/'`, true), 'single quotes').toEqual([]);
    expect(wrongAnswers((scheme, host) => `  ${scheme}${host}/ \t`, true), 'white space at the ends').toEqual([]);

    // Another registry, as today.
    expect(wrongAnswers((scheme) => `${scheme}evil.example/`, false), 'another host').toEqual([]);
    expect(wrongAnswers((scheme, host) => `${scheme}${host}.evil.example/`, false), 'a suffix').toEqual([]);
    expect(wrongAnswers((scheme, host) => `${scheme}${host}./`, false), 'a trailing dot').toEqual([]);
    expect(wrongAnswers((scheme, host) => `${scheme}evil.example/${host}/`, false), 'the public host in the path of another one').toEqual([]);
    expect(wrongAnswers((_scheme, host) => ['dguser', '@', host, '/'].join(''), false), 'a user@ and no scheme').toEqual([]);
    expect(wrongAnswers((scheme, host) => ['dguser', '@', scheme, host, '/'].join(''), false), 'a user@ before the scheme').toEqual([]);
    for (const eco of ECOSYSTEMS) {
      for (const notUrl of ['no-index', '(configured)', 'C:\\feed', '']) {
        expect(isPublicRegistryUrl(eco, notUrl), `${eco}: ${JSON.stringify(notUrl)}`).toBe(false);
      }
    }
  });

  it("T-03 a port that is not the scheme's, a backslash, a space or a control character in the text is another registry", () => {
    expect(wrongAnswers((_scheme, host) => `https://${host}:8443/`, false), 'https on 8443').toEqual([]);
    expect(wrongAnswers((_scheme, host) => `//${host}:8443/`, false), 'no scheme on 8443').toEqual([]);
    expect(wrongAnswers((_scheme, host) => `http://${host}:443/`, false), 'http on 443').toEqual([]);
    expect(wrongAnswers((_scheme, host) => `https://${host}:80/`, false), 'https on 80').toEqual([]);
    expect(wrongAnswers((scheme, host) => withUser(scheme, host, '/\\'), false, ['https://']), 'a backslash after the slash').toEqual([]);
    expect(wrongAnswers((_scheme, host) => ['https://', host, ':443\\@', 'evil.example', '/'].join(''), false), 'a backslash after the port').toEqual([]);
    expect(wrongAnswers((_scheme, host) => ['https://', host, '\\@', 'evil.example', '/'].join(''), false), 'a backslash right after the host').toEqual([]);
    expect(wrongAnswers((scheme, host) => `${scheme}${host}/a b`, false), 'a space inside').toEqual([]);
    expect(wrongAnswers((scheme, host) => `${scheme}${host}/ @evil.example/`, false), 'a space before an @').toEqual([]);
    expect(wrongAnswers((scheme, host) => `${scheme}${host}/a\tb`, false), 'a tab inside').toEqual([]);
    expect(wrongAnswers((scheme, host) => `${scheme}${host}/a\u0001b`, false), 'a control character inside').toEqual([]);
    expect(wrongAnswers((scheme, host) => `${scheme}${host}/a\nb`, false), 'a line break inside').toEqual([]);
  });

  describe('T-03 through the configuration readers', () => {
    const NPM_URL = withUser('https://', 'registry.npmjs.org', ':x');
    const PYPI_URL = withUser('https://', 'pypi.org', ':x', '/simple');
    const NUGET_URL = withUser('https://', 'api.nuget.org', ':x', '/v3/index.json');
    const put = (file: string, text: string): void => {
      mkdirSync(join(file, '..'), { recursive: true });
      writeFileSync(file, text);
    };

    it('T-03 a project .npmrc registry= with credentials before the host is a registry', () => {
      put(join(project, '.npmrc'), `registry=${NPM_URL}\n`);
      expect(customRegistryFor('npm', 'lodash', ctx())).toMatchObject({ kind: 'registry', url: NPM_URL });
    });

    it('T-03 a project .npmrc @scope:registry= with credentials before the host is the registry of that scope', () => {
      put(join(project, '.npmrc'), `@s:registry=${NPM_URL}\n`);
      expect(customRegistryFor('npm', '@s/pkg', ctx())).toMatchObject({ kind: 'registry', url: NPM_URL });
      expect(npmScopeRegistry('@s/pkg', ctx())).toMatchObject({ scope: 's', url: NPM_URL, from: 'project' });
    });

    it('T-03 the environment: NPM_CONFIG_REGISTRY, and npm_config_@scope:registry for the scope', () => {
      expect(customRegistryFor('npm', 'lodash', ctx({ NPM_CONFIG_REGISTRY: NPM_URL }))).toMatchObject({ kind: 'registry', source: 'NPM_CONFIG_REGISTRY' });
      expect(npmScopeRegistry('@s/pkg', ctx({ 'npm_config_@s:registry': NPM_URL }))).toMatchObject({ scope: 's', url: NPM_URL, from: 'user' });
    });

    it('T-03 pip.conf index-url with credentials before the host is a registry', () => {
      put(join(home, '.config', 'pip', 'pip.conf'), `[global]\nindex-url = ${PYPI_URL}\n`);
      expect(customRegistryFor('pypi', 'requests', ctx())).toMatchObject({ kind: 'registry', url: PYPI_URL });
    });

    it('T-03 pyproject.toml [tool.uv] index-url with credentials before the host is a registry', () => {
      put(join(project, 'pyproject.toml'), `[project]\nname = "app"\nversion = "0.1.0"\n\n[tool.uv]\nindex-url = "${PYPI_URL}"\n`);
      expect(customRegistryFor('pypi', 'requests', ctx())).toMatchObject({ kind: 'registry', url: PYPI_URL });
    });

    it('T-03 nuget.config package source with credentials before the host is a registry', () => {
      put(join(project, 'nuget.config'), `<configuration><packageSources><add key="corp" value="${NUGET_URL}" /></packageSources></configuration>\n`);
      expect(customRegistryFor('nuget', 'Newtonsoft.Json', ctx())).toMatchObject({ kind: 'registry', url: NUGET_URL });
    });

    it('T-03 an environment variable with several URLs, and with the name=URL form', () => {
      expect(customRegistryFor('pypi', 'requests', ctx({ PIP_EXTRA_INDEX_URL: `https://pypi.org/simple ${PYPI_URL}` }))).toMatchObject({
        kind: 'registry',
        source: 'PIP_EXTRA_INDEX_URL',
      });
      expect(customRegistryFor('pypi', 'requests', ctx({ PIP_INDEX_URL: `corp=${PYPI_URL}` }))).toMatchObject({ kind: 'registry', source: 'PIP_INDEX_URL' });
      expect(customRegistryFor('nuget', 'Newtonsoft.Json', ctx({ NUGET_SOURCE: `https://api.nuget.org/v3/index.json ${NUGET_URL}` }))).toMatchObject({
        kind: 'registry',
        source: 'NUGET_SOURCE',
      });
    });
  });

  // Fix round 1: the readers hand over the value as the package manager reads it — the comment after it is dropped.
  describe('T-02 / T-03 the value as the manager reads it, and the authority that ends at ? or #', () => {
    const PUBLIC = 'https://registry.npmjs.org/';
    const OTHER = 'https://npm.acme.local/';
    const DISGUISED = withUser('https://', 'registry.npmjs.org', ':x');
    const put = (file: string, text: string): void => {
      mkdirSync(join(file, '..'), { recursive: true });
      writeFileSync(file, text);
    };
    /** Every spelling npm, pnpm, Yarn 1 and bun read as the URL alone (measured, see the spec's measurements). */
    const npmrcValues = (url: string): string[] => [`${url} ; a note`, `${url} # a note`, `${url}; a note`, `${url}#a-note`, `"${url}"`, `"${url}" ; a note`];
    const yarnValues = (url: string): string[] => [`${url} # a note`, `"${url}" # a note`, `"${url}"`, url];

    it('T-02 a public URL followed by a comment, or quoted, in an .npmrc is not a custom registry (as in 3.12.0)', () => {
      const wrong: string[] = [];
      for (const value of npmrcValues(PUBLIC)) {
        put(join(project, '.npmrc'), `registry=${value}\n`);
        if (customRegistryFor('npm', 'lodash', ctx()) !== null) wrong.push(`registry=${value}`);
        put(join(project, '.npmrc'), `@s:registry=${value}\n`);
        if (npmScopeRegistry('@s/pkg', ctx()) !== null) wrong.push(`@s:registry=${value}`);
        if (customRegistryFor('npm', '@s/pkg', ctx()) !== null) wrong.push(`customRegistryFor @s:registry=${value}`);
      }
      put(join(project, '.npmrc'), `registry = "${PUBLIC}"\n`);
      if (customRegistryFor('npm', 'lodash', ctx()) !== null) wrong.push('registry = "<url>"');
      expect(wrong).toEqual([]);
    });

    it('T-02 a public URL followed by a comment, quoted or not, in a .yarnrc.yml is not a custom registry', () => {
      const wrong: string[] = [];
      for (const value of yarnValues(PUBLIC)) {
        put(join(project, '.yarnrc.yml'), `npmRegistryServer: ${value}\n`);
        if (customRegistryFor('npm', 'lodash', ctx()) !== null) wrong.push(`npmRegistryServer: ${value}`);
        put(join(project, '.yarnrc.yml'), `npmScopes:\n  s:\n    npmRegistryServer: ${value}\n`);
        if (npmScopeRegistry('@s/pkg', ctx()) !== null) wrong.push(`npmScopes.s.npmRegistryServer: ${value}`);
      }
      expect(wrong).toEqual([]);
    });

    it('T-02 an empty port is the default one: public', () => {
      for (const eco of ECOSYSTEMS) {
        for (const host of PUBLIC_HOSTS[eco]) {
          for (const tail of ['/simple', '/', '?x=1', '#frag', '']) {
            for (const scheme of SCHEMES) expect(isPublicRegistryUrl(eco, `${scheme}${host}:${tail}`), `${eco}: ${scheme}${host}:${tail}`).toBe(true);
          }
        }
      }
    });

    it('T-02 the authority ends at ? or #: a user@ after them is part of the query, fragment or path, and the host is the public one', () => {
      expect(wrongAnswers((scheme, host) => `${scheme}${host}?@evil.example/`, true), 'after a ?').toEqual([]);
      expect(wrongAnswers((scheme, host) => `${scheme}${host}#@evil.example`, true), 'after a #').toEqual([]);
      expect(wrongAnswers((scheme, host) => `${scheme}${host}/@evil.example`, true), 'after a /').toEqual([]);
    });

    it('T-03 another registry followed by a comment is still a custom registry, and the url has no comment text', () => {
      const wrong: string[] = [];
      for (const value of npmrcValues(OTHER)) {
        put(join(project, '.npmrc'), `registry=${value}\n`);
        const found = customRegistryFor('npm', 'lodash', ctx());
        if (found?.kind !== 'registry' || found.url !== OTHER) wrong.push(`registry=${value} -> ${JSON.stringify(found)}`);
      }
      rmSync(join(project, '.npmrc'), { force: true });
      for (const value of yarnValues(OTHER)) {
        put(join(project, '.yarnrc.yml'), `npmRegistryServer: ${value}\n`);
        const found = customRegistryFor('npm', 'lodash', ctx());
        if (found?.kind !== 'registry' || found.url !== OTHER) wrong.push(`npmRegistryServer: ${value} -> ${JSON.stringify(found)}`);
      }
      expect(wrong).toEqual([]);
    });

    it('T-03 a disguised URL followed by a comment is still a registry; a backslash in the value stops the cut and reads as another registry', () => {
      for (const value of npmrcValues(DISGUISED)) {
        put(join(project, '.npmrc'), `registry=${value}\n`);
        expect(customRegistryFor('npm', 'lodash', ctx()), `registry=${value}`).toMatchObject({ kind: 'registry' });
      }
      put(join(project, '.npmrc'), 'registry=https://registry.npmjs.org/a\\;b\n');
      expect(customRegistryFor('npm', 'lodash', ctx()), 'a backslash').toMatchObject({ kind: 'registry' });
    });
  });

  // Fix round 2: Yarn reads these `.yarnrc.yml` values as ANOTHER host (measured with Yarn 4.18.1); the reader must not read the public URL out of them.
  describe('T-02 / T-03 a .yarnrc.yml npmRegistryServer that is not a plain single-line scalar', () => {
    const PUB = ['https://', 'registry.npmjs.org'].join('');
    const put = (text: string): void => writeFileSync(join(project, '.yarnrc.yml'), text);
    /** The scalar value written after `npmRegistryServer:` — the continuation, if any, on the lines after it. */
    const FORMS: Array<[string, string]> = [
      ['a doubled quote in a single-quoted scalar', `'${PUB}'':x@evil.example/'`],
      ['a plain scalar continued on a more indented line', `${PUB}\n@CONT:x@evil.example/`],
      ['a double-quoted scalar continued on an indented line', `"${PUB}\n@CONT:x@evil.example/"`],
      ['a double-quoted scalar with an escape', `"${PUB}:x\\x40evil.example/"`],
    ];
    /** `@CONT` stands for the indent of a continuation line: deeper than the key at `indent` spaces. */
    const asKey = (value: string, indent: number): string => `${value.replace(/@CONT/g, ' '.repeat(indent + 2))}\n`;
    const defaultFile = (value: string): string => `npmRegistryServer: ${asKey(value, 0)}`;
    const scopeFile = (value: string): string => `npmScopes:\n  s:\n    npmRegistryServer: ${asKey(value, 4)}`;

    it.each(FORMS)('T-03 as the default registry, %s is another registry', (_label, value) => {
      put(defaultFile(value));
      expect(customRegistryFor('npm', 'lodash', ctx())).toMatchObject({ kind: 'registry' });
    });

    it.each(FORMS)('T-03 as the registry of a scope, %s is a registry of its own', (_label, value) => {
      put(scopeFile(value));
      expect(npmScopeRegistry('@s/pkg', ctx())).not.toBeNull();
      expect(customRegistryFor('npm', '@s/pkg', ctx())).toMatchObject({ kind: 'registry' });
    });

    it('T-03 the value that is not plain is not named: the reader gives a placeholder, never part of the text', () => {
      put(defaultFile(FORMS[1]?.[1] ?? ''));
      expect(JSON.stringify(customRegistryFor('npm', 'lodash', ctx())).includes('evil.example')).toBe(false);
    });

    it('T-03 an .npmrc has no continuation line and no doubled-quote escape: its quote tricks still read as another registry', () => {
      const tricks = [`'${PUB}'':x@evil.example/'`, `"${PUB}":x@evil.example/`, `"${PUB}\\":x@evil.example/"`, `'${PUB}':x@evil.example/`];
      const wrong: string[] = [];
      for (const value of tricks) {
        writeFileSync(join(project, '.npmrc'), `registry=${value}\n`);
        if (customRegistryFor('npm', 'lodash', ctx())?.kind !== 'registry') wrong.push(value);
      }
      expect(wrong).toEqual([]);
    });

    const PLAIN = [PUB + '/', `"${PUB}/"`, `'${PUB}/'`, `${PUB}/ # a note`, `"${PUB}/" # a note`, `'${PUB}/' # a note`];
    const FOLLOWERS: Array<[string, string]> = [
      ['another top-level key', 'enableTelemetry: false\n'],
      ['a comment and another top-level key', '# a note\n\nenableTelemetry: false\n'],
      ['a nested mapping of another key', 'npmScopes:\n  other:\n    npmAlwaysAuth: true\n'],
    ];

    it.each(PLAIN)('T-02 the plain single-line value %s, followed by each kind of next line, is the public registry', (value) => {
      const wrong: string[] = [];
      for (const [label, next] of FOLLOWERS) {
        put(`npmRegistryServer: ${value}\n${next}`);
        if (customRegistryFor('npm', 'lodash', ctx()) !== null) wrong.push(`default, then ${label}`);
        put(`npmScopes:\n  s:\n    npmRegistryServer: ${value}\n    npmAlwaysAuth: true\n  t:\n    npmRegistryServer: ${value}\n${next.startsWith('npmScopes') ? '' : next}`);
        if (npmScopeRegistry('@s/pkg', ctx()) !== null) wrong.push(`scope s, then ${label}`);
        if (npmScopeRegistry('@t/pkg', ctx()) !== null) wrong.push(`scope t, then ${label}`);
      }
      expect(wrong).toEqual([]);
    });
  });
});
