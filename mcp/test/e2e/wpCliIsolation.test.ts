/**
 * Review 3.6.1, finding 1, against the REAL WP-CLI on PATH (skipped without
 * one): a site's own `wp-cli.yml` and `wp-cli.local.yml` list a PHP file in
 * `require:`, which WP-CLI loads before any command when it starts in (or
 * below) the site. Measured on WP-CLI 2.12 before the fix: `wp_cron_audit`
 * and `wp_plugin_check` ran WP-CLI in the install, so that file ran; and the
 * site's `wp-config.php` — which WP-CLI evaluates to boot, and still does —
 * saw every variable of the server's environment.
 *
 * No database and no network: the fixture's `wp-settings.php` is empty, so
 * WP-CLI stops after evaluating `wp-config.php`, and both tools then report
 * a failure — which is not what is tested. What each PHP file wrote is.
 */

import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import type { PluginContext } from '../../src/context.js';
import { resolveProjectPath } from '../../src/platform/projectPath.js';
import { runProcess } from '../../src/runners/processRunner.js';
import { GuardianDatabase as Database } from '../../src/storage/db.js';
import { runMigrations } from '../../src/storage/migrations/runner.js';
import { Storage } from '../../src/storage/index.js';
import { TOOLS } from '../../src/tools/index.js';
import { resetScannerCache, scannerAvailable } from '../../src/tools/scanHelpers.js';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';

vi.setConfig({ testTimeout: 120_000 });

afterAll(cleanupTempDirs);
beforeAll(async () => {
  await import('../../src/tools/wpCronAudit.js');
  await import('../../src/tools/wpPluginCheck.js');
});
afterEach(() => {
  vi.unstubAllEnvs();
});

resetScannerCache();
const WP = await scannerAvailable('wp');

function plugin(): PluginContext {
  const db = new Database(':memory:');
  runMigrations(db);
  return { storage: new Storage(db), shell: null, scriptsDir: process.cwd(), progressNotifier: { send: () => {} } };
}

/** The fixture site, and where its PHP files write what they saw. */
function site(): { dir: string; required: string; config: string } {
  const root = makeTempDir('wpcli-e2e-');
  mkdirSync(join(root, 'site', 'wp-includes'), { recursive: true });
  const dir = resolveProjectPath(join(root, 'site')).path;
  const required = join(root, 'required.txt');
  const config = join(root, 'wp-config.txt');
  const q = (p: string): string => `'${p.replace(/\\/g, '\\\\').replace(/'/g, "\\'")}'`;
  writeFileSync(join(dir, 'wp-includes', 'version.php'), "<?php\n$wp_version = '6.6.2';\n$wp_db_version = 57155;\n");
  writeFileSync(join(dir, 'wp-load.php'), '<?php\n');
  writeFileSync(join(dir, 'wp-settings.php'), '<?php\n');
  writeFileSync(
    join(dir, 'wp-config.php'),
    "<?php\n" +
      `file_put_contents(${q(config)}, json_encode(['token' => getenv('GH_TOKEN'), 'path' => getenv('PATH') !== false]));\n` +
      "define('DB_NAME', 'x'); define('DB_USER', 'x'); define('DB_PASSWORD', 'x'); define('DB_HOST', '127.0.0.1:1');\n" +
      "$table_prefix = 'wp_';\n" +
      "if (!defined('ABSPATH')) define('ABSPATH', __DIR__ . '/');\n" +
      "require_once ABSPATH . 'wp-settings.php';\n",
  );
  writeFileSync(join(dir, 'required.php'), `<?php\nfile_put_contents(${q(required)}, 'the site\\'s wp-cli.yml ran');\n`);
  writeFileSync(join(dir, 'wp-cli.yml'), 'require:\n  - required.php\n');
  writeFileSync(join(dir, 'wp-cli.local.yml'), 'require:\n  - required.php\n');
  return { dir, required, config };
}

describe.skipIf(WP === null)('WP-CLI never reads the site’s wp-cli.yml, nor hands its PHP the server’s credentials', () => {
  it('the control: started in the site, WP-CLI loads the require: of its wp-cli.yml', async () => {
    const s = site();
    await runProcess({ command: 'wp', args: ['core', 'version', `--path=${s.dir}`], cwd: s.dir, timeoutMs: 60_000 });
    expect(existsSync(s.required)).toBe(true);
  });

  it.each([
    ['wp_cron_audit', (dir: string) => ({ wp_install_path: dir })],
    ['wp_plugin_check', (dir: string) => ({ slug: 'akismet', wp_install_path: dir })],
  ])('%s: wp-config.php is evaluated (WP-CLI cannot skip it) without GH_TOKEN; the wp-cli.yml require never runs', async (name, input) => {
    const s = site();
    vi.stubEnv('GH_TOKEN', 'ghp_never_handed_to_the_site');
    const tool = TOOLS.find((t) => t.name === name);
    if (!tool) throw new Error(`${name} is not registered`);
    await tool.handler(input(s.dir), plugin());
    expect(existsSync(s.required), 'the site’s wp-cli.yml require ran').toBe(false);
    // WP-CLI did reach the site, in an environment that still finds PHP.
    expect(existsSync(s.config), 'WP-CLI never evaluated the site’s wp-config.php').toBe(true);
    expect(JSON.parse(readFileSync(s.config, 'utf8'))).toEqual({ token: false, path: true });
    rmSync(s.config, { force: true });
  });
});
