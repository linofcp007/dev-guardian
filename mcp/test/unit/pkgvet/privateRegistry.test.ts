import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { customRegistryFor } from '../../../src/pkgvet/privateRegistry.js';

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

const ctx = (env: Record<string, string> = {}) => ({ projectDir: project, homeDir: home, env });

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
