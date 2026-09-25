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
