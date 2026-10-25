/**
 * Review 3.6.1, finding 1: the WordPress tools ran the audited site's code.
 *
 * Every WP-CLI call (`wp_audit`, `wp_cron_audit`, `wp_plugin_check`,
 * `wp_vuln_check`'s URL look-up) ran with the install as its working
 * directory, this server's whole environment and nothing skipped: a
 * backdoored plugin or theme of a site copied off a server ran on the user's
 * machine with every token the server held, and WP-CLI loaded the `require:`
 * list of the site's `wp-cli.yml`. Now each call skips the site's plugins and
 * theme, runs from a temporary directory of its own holding an empty
 * `wp-cli.yml` (WP-CLI stops at the first one it finds walking up), names
 * the site by `--path`, and gets an allowlisted environment
 * (`wordpress/wpCli.ts`). WP-CLI is mocked here; `test/e2e/wpCliIsolation.test.ts`
 * runs the real one.
 */

import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { isAbsolute, join, relative, resolve } from 'node:path';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../src/runners/processRunner.js', () => ({ runProcess: vi.fn() }));
vi.mock('../../src/tools/scanHelpers.js', async () => {
  const actual = await vi.importActual<typeof import('../../src/tools/scanHelpers.js')>('../../src/tools/scanHelpers.js');
  return { ...actual, scannerAvailable: vi.fn() };
});

import { runProcess, type ProcessRunOptions, type ProcessRunResult } from '../../src/runners/processRunner.js';
import { scannerAvailable } from '../../src/tools/scanHelpers.js';
import type { PluginContext } from '../../src/context.js';
import { resolveProjectPath } from '../../src/platform/projectPath.js';
import { GuardianDatabase as Database } from '../../src/storage/db.js';
import { runMigrations } from '../../src/storage/migrations/runner.js';
import { Storage } from '../../src/storage/index.js';
import { TOOLS } from '../../src/tools/index.js';
import { wpCliEnv } from '../../src/wordpress/wpCli.js';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';

afterAll(cleanupTempDirs);
beforeAll(async () => {
  await import('../../src/tools/wpAudit.js');
  await import('../../src/tools/wpCronAudit.js');
  await import('../../src/tools/wpPluginCheck.js');
  await import('../../src/tools/wpVulnCheck.js');
});

/** What each WP-CLI call was handed, and what its working directory held while it ran. */
interface Seen {
  args: string[];
  cwd: string;
  env: NodeJS.ProcessEnv | undefined;
  extendEnv: boolean | undefined;
  gitRepos: readonly string[] | undefined;
  config: string | null;
}
let seen: Seen[] = [];

const ok = (stdout: string): ProcessRunResult => ({ outcome: 'completed', exitCode: 0, stdout, stderr: '', truncated: false });

/** WP-CLI's answers, by the subcommand's first words; wpscan says it has no token. */
function fakeWp(opts: ProcessRunOptions): ProcessRunResult {
  const a = opts.args ?? [];
  if (opts.command === 'wpscan') return { ...ok(''), outcome: 'failed', exitCode: 1 };
  const cfg = join(opts.cwd, 'wp-cli.yml');
  seen.push({
    args: a,
    cwd: opts.cwd,
    env: opts.env,
    extendEnv: opts.extendEnv,
    gitRepos: opts.gitRepos,
    config: existsSync(cfg) ? readFileSync(cfg, 'utf8') : null,
  });
  const is = (...w: string[]): boolean => w.every((x, i) => a[i] === x);
  if (is('core', 'version')) return ok('6.6.2\n');
  if (is('cron', 'event', 'list')) return ok('[{"hook":"wp_version_check","next_run_relative":"1 hour","schedule":"twicedaily"}]');
  if (is('plugin', 'list')) return ok('[{"name":"akismet","status":"active","version":"5.3","auto_update":"off"}]');
  if (is('user', 'list')) return ok('[]');
  if (is('option', 'get', 'home')) return ok('https://site.example\n');
  return ok('');
}

beforeEach(() => {
  seen = [];
  vi.mocked(runProcess).mockReset();
  vi.mocked(runProcess).mockImplementation(async (o) => fakeWp(o));
  vi.mocked(scannerAvailable).mockReset();
  vi.mocked(scannerAvailable).mockResolvedValue('/fake/bin/wp');
  // Credentials the server holds: none may reach the site's PHP.
  vi.stubEnv('GH_TOKEN', 'ghp_never_handed_to_the_site');
  vi.stubEnv('WPSCAN_API_TOKEN', 'wpscantokenneverhanded');
  vi.stubEnv('AWS_SECRET_ACCESS_KEY', 'never-handed');
  vi.stubEnv('GUARDIAN_DATA_DIR', join(makeTempDir('wpcli-iso-data-'), 'd'));
  vi.stubEnv('WP_CLI_CACHE_DIR', '/user/own/wp-cli-cache');
});
afterEach(() => {
  vi.unstubAllEnvs();
});

function plugin(): PluginContext {
  const db = new Database(':memory:');
  runMigrations(db);
  return { storage: new Storage(db), shell: null, scriptsDir: process.cwd(), progressNotifier: { send: () => {} } };
}

/** A WordPress install whose own wp-cli.yml would load a PHP file. */
function site(): string {
  const dir = resolveProjectPath(makeTempDir('wpcli-iso-site-')).path;
  writeFileSync(join(dir, 'wp-config.php'), '<?php\n');
  writeFileSync(join(dir, 'wp-cli.yml'), 'require:\n  - evil.php\n');
  return dir;
}

async function call(name: string, input: Record<string, unknown>): Promise<void> {
  const tool = TOOLS.find((t) => t.name === name);
  if (!tool) throw new Error(`${name} is not registered`);
  await tool.handler(input, plugin());
}

const inside = (dir: string, p: string): boolean => {
  const rel = relative(resolve(dir), resolve(p));
  return rel === '' || (!rel.startsWith('..') && !isAbsolute(rel));
};

describe.each([
  ['wp_audit', (dir: string) => ({ wp_install_path: dir })],
  ['wp_cron_audit', (dir: string) => ({ wp_install_path: dir })],
  ['wp_plugin_check', (dir: string) => ({ slug: 'akismet', wp_install_path: dir })],
  ['wp_vuln_check', (dir: string) => ({ wp_install_path: dir })],
])('%s runs WP-CLI without the site’s plugins, theme, wp-cli.yml or the server’s credentials', (name, input) => {
  it('every call skips plugins and themes, and names the site by --path', async () => {
    const dir = site();
    await call(name, input(dir));
    expect(seen.length).toBeGreaterThan(0);
    for (const s of seen) {
      expect(s.args, s.args.join(' ')).toEqual(expect.arrayContaining(['--skip-plugins', '--skip-themes', `--path=${dir}`]));
    }
  });

  it('runs from a directory of its own, outside the site, whose empty wp-cli.yml stops the search — removed afterwards', async () => {
    const dir = site();
    await call(name, input(dir));
    for (const s of seen) {
      expect(inside(dir, s.cwd), `${s.cwd} is inside ${dir}`).toBe(false);
      expect(s.config, `no wp-cli.yml in ${s.cwd}`).not.toBeNull();
      expect(s.config ?? '').not.toMatch(/^\s*[a-z_-]+\s*:/im);
      expect(existsSync(s.cwd), `${s.cwd} was left behind`).toBe(false);
    }
  });

  it('hands WP-CLI an allowlisted environment: PATH and the user’s WP-CLI settings, no credential, no GUARDIAN_*', async () => {
    const dir = site();
    await call(name, input(dir));
    for (const s of seen) {
      expect(s.extendEnv).toBe(false);
      const env = s.env ?? {};
      const names = Object.keys(env).map((k) => k.toUpperCase());
      expect(names).toContain('PATH');
      expect(env['WP_CLI_CACHE_DIR']).toBe('/user/own/wp-cli-cache');
      for (const banned of ['GH_TOKEN', 'WPSCAN_API_TOKEN', 'AWS_SECRET_ACCESS_KEY', 'GUARDIAN_DATA_DIR']) {
        expect(names, banned).not.toContain(banned);
      }
      // Git hardening still reads the install's own repository.
      expect(s.gitRepos).toEqual([dir]);
    }
  });
});

describe('wpCliEnv', () => {
  it('keeps the WP-CLI and PHP settings and the proxies, drops credentials even in those families', () => {
    const env = wpCliEnv({
      PATH: '/bin',
      WP_CLI_PHP: '/opt/php',
      WP_CLI_CONFIG_PATH: '/home/u/.wp-cli/config.yml',
      PHPRC: '/etc/php',
      HTTPS_PROXY: 'http://proxy:3128',
      WP_CLI_GITHUB_TOKEN: 'x',
      WP_CONFIG_PATH: '/elsewhere/wp-config.php',
      DB_PASSWORD: 'x',
      GUARDIAN_OFFLINE: '1',
    });
    expect(env).toEqual({
      PATH: '/bin',
      WP_CLI_PHP: '/opt/php',
      WP_CLI_CONFIG_PATH: '/home/u/.wp-cli/config.yml',
      PHPRC: '/etc/php',
      HTTPS_PROXY: 'http://proxy:3128',
    });
  });
});
