/**
 * How every WP-CLI call dev-guardian makes is run (review 3.6.1, finding 1):
 * `wp_audit`, `wp_cron_audit`, `wp_plugin_check` and `wp_vuln_check`'s URL
 * look-up.
 *
 * WP-CLI is not a reader of the install: to answer anything from the
 * database it BOOTS the site — the site's own PHP. The audits ran it with the
 * install as the working directory, this server's whole environment and
 * nothing skipped, so on a site copied off a compromised server (the case
 * these tools exist for) a backdoored plugin or theme ran on the user's
 * machine, with every token the server was started with in its environment;
 * and WP-CLI reads a `wp-cli.yml` / `wp-cli.local.yml` from its working
 * directory upward, whose `require:` list it loads as PHP before any command
 * (measured on WP-CLI 2.12: a site's `wp-cli.yml` requiring `evil.php` ran
 * on `wp core version --path=…` started in the site). Now:
 *
 *   - **`--skip-plugins --skip-themes`** on every call: no plugin of the site
 *     and no theme's `functions.php` is loaded. Nothing the tools read needs
 *     them — checksums and plugin headers are read from the files, users,
 *     cron events and options from the database, and `wp plugin list` still
 *     reports each plugin's real status (WP-CLI filters `active_plugins` only
 *     until `plugins_loaded`; measured on a 25-plugin site: the same
 *     active / inactive states). It also makes the answers truer: a plugin
 *     that hides its own administrator (`pre_user_query`), its cron event or
 *     itself (`all_plugins`) is not running to hide them.
 *   - **A working directory of its own**: a fresh temporary directory holding
 *     an empty `wp-cli.yml`, which WP-CLI finds first and so stops looking
 *     above it — the site's `wp-cli.yml` (its `require:`, `path:`, `url:`,
 *     `ssh:`) is never read, nor one in any directory above the temporary
 *     one (measured: the same `evil.php` did not run, even from a directory
 *     inside the site). The site is named by `--path`. `WP_CLI_CONFIG_PATH`
 *     would not do this: it moves only the USER's global configuration
 *     (`Runner::get_global_config_path`), which is kept, as is the user's
 *     `WP_CLI_*` environment.
 *   - **An allowlisted environment** (`extendEnv: false`): the project test
 *     command's (`fixpr/testCommandEnv.ts` — PATH, home, temp, locale, what
 *     Windows needs; no name that looks like a credential, no `GUARDIAN_*`),
 *     plus WP-CLI's and PHP's own settings and the proxy variables. A
 *     `GH_TOKEN`, `WPSCAN_API_TOKEN` or cloud credential the server holds no
 *     longer reaches the site's PHP. Git hardening still applies, for the
 *     install's repository too (`gitRepos`).
 *
 * **What still runs, and cannot be skipped.** WP-CLI has no switch for the
 * rest of the boot: the site's `wp-config.php` (also evaluated by `wp config
 * get`), its WordPress core files, its must-use plugins (`wp-content/mu-plugins`
 * — WP-CLI documents that `--skip-plugins` leaves them loaded) and its
 * drop-ins (`wp-content/db.php`, `object-cache.php`, `advanced-cache.php`).
 * `wp core version` and `wp core verify-checksums` load none of it (WP-CLI
 * runs them before WordPress loads). Those are the site's files, not a
 * plugin's — and on a compromised copy they may be altered too: run the WP-CLI
 * audits only on a site you would let boot, or read its code first
 * (`scan_wordpress`, `wp_audit`'s checksums).
 */

import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { testCommandEnv } from '../fixpr/testCommandEnv.js';
import { runProcess, type ProcessRunResult } from '../runners/processRunner.js';

/** Appended to every WP-CLI call: the site's plugins and theme are not loaded. */
const WP_CLI_SKIP_ARGS = ['--skip-plugins', '--skip-themes'] as const;

/** WP-CLI's and PHP's own settings — the user's, never the site's. */
const WP_CLI_ENV_PREFIXES = ['WP_CLI_'];
const WP_CLI_ENV_EXACT = new Set(['PHPRC', 'PHP_INI_SCAN_DIR', 'HTTP_PROXY', 'HTTPS_PROXY', 'NO_PROXY', 'ALL_PROXY']);

/** Never handed over, whatever family the name is in (the test command's rule). */
const CREDENTIAL = /TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|AUTH|API_?KEY|PRIVATE_?KEY|SESSION|COOKIE/i;

/**
 * The environment WP-CLI runs in, from `source` (this process's by default),
 * to be passed with `extendEnv: false` — see the module comment.
 */
export function wpCliEnv(source: NodeJS.ProcessEnv = process.env): NodeJS.ProcessEnv {
  const out = testCommandEnv(source);
  for (const [name, value] of Object.entries(source)) {
    if (value === undefined) continue;
    const upper = name.toUpperCase();
    if (CREDENTIAL.test(upper)) continue;
    if (WP_CLI_ENV_EXACT.has(upper) || WP_CLI_ENV_PREFIXES.some((p) => upper.startsWith(p))) out[name] = value;
  }
  return out;
}

/** What `wp-cli.yml` in WP-CLI's own directory says: nothing (see the module comment). */
const NEUTRAL_CONFIG = '# dev-guardian: an empty project configuration, so WP-CLI reads no wp-cli.yml of the site\n';

/** One WP-CLI call against the install: `args` without `--path` or the skip flags, which are added. */
export type WpCli = (args: readonly string[], timeoutMs: number) => Promise<ProcessRunResult>;

/**
 * Runs `fn` with a {@link WpCli} pointed at `installPath`, from a temporary
 * directory removed afterwards. A directory that cannot be made is every
 * call's failure, named — never a call made from somewhere else.
 */
export async function withWpCli<T>(installPath: string, fn: (wp: WpCli) => Promise<T>): Promise<T> {
  let dir: string | null = null;
  let problem = '';
  try {
    dir = mkdtempSync(join(tmpdir(), 'dg-wpcli-'));
    writeFileSync(join(dir, 'wp-cli.yml'), NEUTRAL_CONFIG, { flag: 'wx' });
  } catch (e) {
    problem = `dev-guardian did not run WP-CLI: its working directory could not be prepared (${(e as Error).message})`;
  }
  const cwd = problem === '' ? dir : null;
  const env = wpCliEnv();
  const notRun: ProcessRunResult = {
    outcome: 'failed',
    exitCode: null,
    stdout: '',
    stderr: `${problem}\n`,
    truncated: false,
    notRun: { code: 'wp_cli_dir', message: problem },
  };
  const wp: WpCli = async (args, timeoutMs) =>
    cwd === null
      ? notRun
      : runProcess({
          command: 'wp',
          args: [...args, `--path=${installPath}`, ...WP_CLI_SKIP_ARGS],
          cwd,
          env,
          extendEnv: false,
          gitRepos: [installPath],
          timeoutMs,
        });
  try {
    return await fn(wp);
  } finally {
    if (dir !== null) {
      try {
        rmSync(dir, { recursive: true, force: true, maxRetries: 3, retryDelay: 50 });
      } catch {
        /* a temporary directory left behind holds an empty file */
      }
    }
  }
}
