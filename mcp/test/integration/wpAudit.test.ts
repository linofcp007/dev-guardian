/**
 * `wp_audit`'s checksum verification against canned WP-CLI output (review
 * I5) — WP-CLI is not installed here, so the shapes are taken from its
 * source, wp-cli/checksum-command (main, retrieved 2026-09-29):
 *
 *   - `src/Checksum_Core_Command.php`, end of `__invoke`: when there are
 *     errors and `--format` is not plain, `new Formatter( $assoc_args,
 *     array( 'file', 'message' ) )` → `display_items( $this->errors )` on
 *     STDOUT, then `WP_CLI::error( "WordPress installation doesn't verify
 *     against checksums." )` — "Error: …" on STDERR, exit 1. The messages:
 *     "File doesn't verify against checksum", "File doesn't exist", "File
 *     should not exist".
 *   - `src/Checksum_Plugin_Command.php`: rows `plugin_name`, `file`,
 *     `message` ("Checksum does not match", "File was added"), displayed the
 *     same way; a plugin whose checksums cannot be had is a WARNING and a
 *     skip — "Could not retrieve the checksums for version {$version} of
 *     plugin {$plugin->name}, skipping.", "Could not retrieve the version for
 *     plugin {$plugin->name}, skipping." — and the result goes through
 *     wp-cli's `Utils\report_batch_operation_results( 'plugin', 'verify', … )`
 *     (`php/utils.php`): any failure is `WP_CLI::error( "Only verified
 *     {$successes} of {$total} plugins ({$failures} failed, {$skips}
 *     skipped)." )`, exit 1; skips alone are a success.
 *   - `checksum-command.php` registers `core verify-checksums` and `plugin
 *     verify-checksums` only: there is no `theme verify-checksums`.
 */

import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
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
import type { ToolResult, ToolRun } from '../../src/types.js';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';

afterAll(cleanupTempDirs);
beforeAll(async () => {
  await import('../../src/tools/wpAudit.js');
});
beforeEach(() => {
  vi.mocked(runProcess).mockReset();
  vi.mocked(scannerAvailable).mockReset();
  vi.mocked(scannerAvailable).mockResolvedValue('/fake/bin/wp');
  // The retry backoff (1 s, 3 s, 9 s) on a fake clock: a call that fails every
  // attempt no longer costs 13 s of real time, and "no retry" is read from the
  // call count, never from a stopwatch (review 3.0, R7).
  vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
});
afterEach(() => {
  vi.useRealTimers();
});

function install(): string {
  const dir = resolveProjectPath(makeTempDir('wp-audit-')).path;
  writeFileSync(join(dir, 'wp-config.php'), '<?php\n');
  return dir;
}

function plugin(): PluginContext {
  const db = new Database(':memory:');
  runMigrations(db);
  return { storage: new Storage(db), shell: null, scriptsDir: process.cwd(), progressNotifier: { send: () => {} } };
}

const run = (exitCode: number, stdout: string, stderr = ''): ProcessRunResult => ({
  outcome: exitCode === 0 ? 'completed' : 'failed',
  exitCode,
  stdout,
  stderr,
  truncated: false,
});

const CORE_ROWS = [
  { file: 'wp-includes/version.php', message: "File doesn't verify against checksum" },
  { file: 'wp-admin/about.php', message: "File doesn't exist" },
  { file: 'wp-content/x.php', message: 'File should not exist' },
];
const PLUGIN_ROWS = [
  { plugin_name: 'akismet', file: 'akismet.php', message: 'Checksum does not match' },
  { plugin_name: 'akismet', file: 'evil.php', message: 'File was added' },
];

interface Scenario {
  core?: ProcessRunResult;
  plugins?: ProcessRunResult;
}

function wpCli(s: Scenario = {}): (opts: ProcessRunOptions) => ProcessRunResult {
  return (opts) => {
    const a = opts.args ?? [];
    const has = (...words: string[]): boolean => words.every((w, i) => a[i] === w);
    if (has('core', 'version')) return run(0, '6.4.1\n');
    if (has('core', 'verify-checksums')) {
      return (
        s.core ??
        run(1, JSON.stringify(CORE_ROWS), "Error: WordPress installation doesn't verify against checksums.\n")
      );
    }
    if (has('plugin', 'verify-checksums')) {
      return (
        s.plugins ??
        run(
          1,
          JSON.stringify(PLUGIN_ROWS),
          'Warning: Could not retrieve the checksums for version 3.1 of plugin premium-forms, skipping.\n' +
            'Warning: Could not retrieve the version for plugin local-hacks, skipping.\n' +
            'Error: Only verified 1 of 4 plugins (1 failed, 2 skipped).\n',
        )
      );
    }
    if (has('theme', 'verify-checksums')) return run(1, '', "Error: 'verify-checksums' is not a registered subcommand of 'theme'.\n");
    if (has('user', 'list')) return run(0, '[{"user_login":"admin","user_email":"a@x"}]');
    if (has('plugin', 'list')) return run(0, '[{"name":"akismet","auto_update":"on"}]');
    if (has('config', 'get')) return run(0, 'true\n');
    return run(1, '', `unexpected ${a.join(' ')}`);
  };
}

interface Out {
  ok: true;
  scan_id: string;
  coverage: string;
  tools_run: ToolRun[];
  missing_tools: string[];
  checksum_mismatches: { core: Array<{ file: string; status: string }>; plugins: Record<string, Array<{ file: string; status: string }>> };
  checksums_not_checked: { themes: string; plugins: Array<{ plugin: string; reason: string }> };
  warnings: string[];
  wp_version: string | null;
  config_flags: Record<string, boolean | null>;
  admins: Array<{ user_login: string; user_email: string; risky: boolean }>;
  plugins_with_auto_update: string[];
}

/** The raw tool result — the retry timers advanced on the fake clock while it runs. */
async function callTool(input: Record<string, unknown>, ctx: PluginContext = plugin()): Promise<ToolResult<Record<string, unknown>>> {
  const tool = TOOLS.find((t) => t.name === 'wp_audit');
  if (!tool) throw new Error('wp_audit not registered');
  const pending = tool.handler(input, ctx);
  await vi.runAllTimersAsync();
  return pending;
}

async function audit(dir: string, input: Record<string, unknown> = {}, ctx?: PluginContext): Promise<Out> {
  const r = await callTool({ wp_install_path: dir, ...input }, ctx);
  if (!r.ok) throw new Error(JSON.stringify(r.error));
  return r as unknown as Out;
}

const callsOf = (...words: string[]): number =>
  vi.mocked(runProcess).mock.calls.filter((c) => words.every((w, i) => (c[0].args ?? [])[i] === w)).length;

describe('wp_audit reads WP-CLI’s checksum report on exit 1 (review I5)', () => {
  it('a tampered core and plugin: every mismatch reported, no retry, no warning that the check failed', async () => {
    vi.mocked(runProcess).mockImplementation(async (o) => wpCli()(o));
    const out = await audit(install());
    expect(out.checksum_mismatches.core).toEqual([
      { file: 'wp-includes/version.php', status: 'modified' },
      { file: 'wp-admin/about.php', status: 'missing' },
      { file: 'wp-content/x.php', status: 'added' },
    ]);
    expect(out.checksum_mismatches.plugins).toEqual({
      akismet: [
        { file: 'akismet.php', status: 'modified' },
        { file: 'evil.php', status: 'added' },
      ],
    });
    // Exit 1 WITH its rows is the answer, not a failure: asked once each.
    expect(callsOf('core', 'verify-checksums')).toBe(1);
    expect(callsOf('plugin', 'verify-checksums')).toBe(1);
    expect(out.warnings.join(' ')).not.toMatch(/verify-checksums: exit/);
  });

  it('never asks for theme checksums, and says themes were not checked', async () => {
    vi.mocked(runProcess).mockImplementation(async (o) => wpCli()(o));
    const out = await audit(install());
    expect(callsOf('theme', 'verify-checksums')).toBe(0);
    expect(out.checksums_not_checked.themes).toMatch(/not checked \(WP-CLI has no theme checksums\)/);
    expect('themes' in out.checksum_mismatches).toBe(false);
  });

  it('plugins WP-CLI skipped are named as not checked, and the audit is partial', async () => {
    vi.mocked(runProcess).mockImplementation(async (o) => wpCli()(o));
    const out = await audit(install());
    expect(out.checksums_not_checked.plugins).toEqual([
      { plugin: 'local-hacks', reason: expect.stringMatching(/version/) },
      { plugin: 'premium-forms', reason: expect.stringMatching(/checksums for version 3\.1/) },
    ]);
    expect(out.missing_tools).toEqual(['wp-cli']);
    expect(out.coverage).toBe('partial');
  });

  it('a clean install: exit 0, nothing printed, nothing missing — full', async () => {
    vi.mocked(runProcess).mockImplementation(async (o) =>
      wpCli({
        core: run(0, '', 'Success: WordPress installation verifies against checksums.\n'),
        plugins: run(0, '', 'Success: Verified 3 of 3 plugins.\n'),
      })(o),
    );
    const out = await audit(install());
    expect(out.checksum_mismatches.core).toEqual([]);
    expect(out.checksum_mismatches.plugins).toEqual({});
    expect(out.checksums_not_checked.plugins).toEqual([]);
    expect(out.tools_run).toEqual([{ name: 'wp-cli', status: 'ok' }]);
    expect(out.coverage).toBe('full');
  });

  it(
    'exit 1 with no rows (checksums unavailable) is a failed check, retried, and a named gap — never "no mismatches"',
    async () => {
      vi.mocked(runProcess).mockImplementation(async (o) =>
        wpCli({ core: run(1, '', "Error: Couldn't get checksums from WordPress.org.\n") })(o),
      );
      const out = await audit(install());
      expect(callsOf('core', 'verify-checksums')).toBe(4);
      expect(out.warnings.join(' ')).toMatch(/core verify-checksums: exit 1/);
      expect(out.missing_tools).toEqual(['wp-cli']);
      expect(out.coverage).toBe('partial');
      expect(out.tools_run[0]?.reason).toMatch(/core checksums not verified/);
    },
    30_000,
  );
});

// ---------------------------------------------------------------------------
// Review 3.0, R7-I4: the rest of wp_audit — its refusals, its options and its
// partial answers had no test. Every subsection that did not answer is a
// named gap, never a silent `ok`.
// ---------------------------------------------------------------------------

/** `wpCli()` on a clean install, with the answers named by their first words replaced (e.g. 'user list'). */
function wpCliWith(answers: Record<string, ProcessRunResult>): (opts: ProcessRunOptions) => ProcessRunResult {
  const base = wpCli({
    core: run(0, '', 'Success: WordPress installation verifies against checksums.\n'),
    plugins: run(0, '', 'Success: Verified 3 of 3 plugins.\n'),
  });
  return (opts) => {
    const a = opts.args ?? [];
    for (const [key, answer] of Object.entries(answers)) {
      if (key.split(' ').every((w, i) => a[i] === w)) return answer;
    }
    return base(opts);
  };
}

describe('wp_audit refuses what it cannot audit', () => {
  it('a directory with no wp-config.php is not a WordPress install, and WP-CLI is never started', async () => {
    const dir = resolveProjectPath(makeTempDir('wp-audit-empty-')).path;
    const r = await callTool({ wp_install_path: dir });
    expect(r).toMatchObject({ ok: false, error: { code: 'not_a_wordpress_install' } });
    expect(vi.mocked(runProcess)).not.toHaveBeenCalled();
  });

  it('a path that does not resolve is not a WordPress install either', async () => {
    const r = await callTool({ wp_install_path: join(makeTempDir('wp-audit-gone-'), 'no', 'such', 'dir') });
    expect(r).toMatchObject({ ok: false, error: { code: 'not_a_wordpress_install' } });
  });

  it('WP-CLI not on PATH: missing_scanner, naming the install_toolchain call', async () => {
    vi.mocked(scannerAvailable).mockResolvedValue(null);
    const r = await callTool({ wp_install_path: install() });
    expect(r).toMatchObject({ ok: false, error: { code: 'missing_scanner' } });
    if (!r.ok) expect(r.error.message).toContain('install_toolchain');
    expect(vi.mocked(runProcess)).not.toHaveBeenCalled();
  });
});

describe('wp_audit — what it reads, and the options that turn it off', () => {
  it('reads the version, the admins (flagging risky logins), auto-updating plugins and the config flags', async () => {
    vi.mocked(runProcess).mockImplementation(async (o) =>
      wpCliWith({
        'user list': run(
          0,
          JSON.stringify([
            { user_login: 'Admin', user_email: 'a@x.test' },
            { user_login: 'maria', user_email: 'm@x.test' },
          ]),
        ),
        'plugin list': run(
          0,
          JSON.stringify([
            { name: 'akismet', auto_update: 'on' },
            { name: 'hello', auto_update: 'off' },
            { name: 'jetpack', auto_update: 'ON' },
          ]),
        ),
        'config get DISALLOW_FILE_EDIT': run(0, '1\n'),
        'config get WP_DEBUG': run(0, 'false\n'),
        'config get WP_DEBUG_LOG': run(0, '0\n'),
        'config get FORCE_SSL_ADMIN': run(0, 'TRUE\n'),
      })(o),
    );
    const out = await audit(install());
    expect(out.wp_version).toBe('6.4.1');
    expect(out.admins).toEqual([
      { user_login: 'Admin', user_email: 'a@x.test', risky: true },
      { user_login: 'maria', user_email: 'm@x.test', risky: false },
    ]);
    expect(out.plugins_with_auto_update).toEqual(['akismet', 'jetpack']);
    expect(out.config_flags).toEqual({ DISALLOW_FILE_EDIT: true, WP_DEBUG: false, WP_DEBUG_LOG: false, FORCE_SSL_ADMIN: true });
    expect(out.coverage).toBe('full');
  });

  it('risky_login_names replaces the default list, compared case-insensitively', async () => {
    vi.mocked(runProcess).mockImplementation(async (o) =>
      wpCliWith({
        'user list': run(
          0,
          JSON.stringify([
            { user_login: 'admin', user_email: 'a@x.test' },
            { user_login: 'OPS', user_email: 'o@x.test' },
          ]),
        ),
      })(o),
    );
    const out = await audit(install(), { risky_login_names: ['ops'] });
    expect(out.admins.map((a) => [a.user_login, a.risky])).toEqual([
      ['admin', false],
      ['OPS', true],
    ]);
  });

  it('include_users: false never lists users; include_options: false never reads a config flag', async () => {
    vi.mocked(runProcess).mockImplementation(async (o) => wpCliWith({})(o));
    const out = await audit(install(), { include_users: false, include_options: false });
    expect(callsOf('user', 'list')).toBe(0);
    expect(callsOf('config', 'get')).toBe(0);
    expect(out.admins).toEqual([]);
    expect(out.config_flags).toEqual({ DISALLOW_FILE_EDIT: null, WP_DEBUG: null, WP_DEBUG_LOG: null, FORCE_SSL_ADMIN: null });
    expect(out.coverage).toBe('full');
  });

  it('persists a wp_audit scan whose meta is the structured audit', async () => {
    vi.mocked(runProcess).mockImplementation(async (o) => wpCliWith({})(o));
    const ctx = plugin();
    const out = await audit(install(), {}, ctx);
    const scan = ctx.storage.scans.getById(out.scan_id);
    expect(scan).toMatchObject({ scan_type: 'wp_audit', status: 'completed' });
    expect(scan?.meta).toMatchObject({ wp_version: '6.4.1', checksum_mismatches: { core: [], plugins: {} } });
  });
});

describe('wp_audit — a subsection that did not answer is a named gap, never a silent ok', () => {
  it.each([
    ['the version', 'core version', 'core version not read', /core version: exit 1/],
    ['the admin list', 'user list', 'admin users not read', /user list: exit 1/],
    ['the plugin list', 'plugin list', 'plugin list not read', /plugin list: exit 1/],
    ['plugin checksums', 'plugin verify-checksums', 'plugin checksums not verified', /plugin verify-checksums: exit 1/],
    ['a config flag', 'config get WP_DEBUG', 'config WP_DEBUG not read', /config get WP_DEBUG: exit 1/],
  ])('%s failing every attempt: retried, warned about, and partial', async (_label, key, gap, warning) => {
    vi.mocked(runProcess).mockImplementation(async (o) =>
      wpCliWith({ [key]: run(1, '', 'Error: Error establishing a database connection.\n') })(o),
    );
    const out = await audit(install());
    expect(callsOf(...key.split(' '))).toBe(4);
    expect(out.warnings.join('\n')).toMatch(warning);
    expect(out.missing_tools).toEqual(['wp-cli']);
    expect(out.coverage).toBe('partial');
    expect(out.tools_run).toEqual([{ name: 'wp-cli', status: 'ok', reason: gap }]);
  });

  it.each([
    ['the admin list', 'user list', 'user list: stdout not JSON', 'admin users not read'],
    ['the plugin list', 'plugin list', 'plugin list: stdout not JSON', 'plugin list not read'],
  ])('%s answering something that is not JSON: warned about, and partial', async (_label, key, warning, gap) => {
    vi.mocked(runProcess).mockImplementation(async (o) => wpCliWith({ [key]: run(0, 'PHP Notice: something\n[{') })(o));
    const out = await audit(install());
    expect(out.warnings).toContain(warning);
    expect(out.tools_run[0]?.reason).toBe(gap);
    expect(out.coverage).toBe('partial');
  });

  it('a version that recovers on the second attempt is read, and nothing is missing', async () => {
    let versionCalls = 0;
    vi.mocked(runProcess).mockImplementation(async (o) => {
      const a = o.args ?? [];
      if (a[0] === 'core' && a[1] === 'version') {
        versionCalls += 1;
        return versionCalls === 1 ? run(1, '', 'Error: busy\n') : run(0, '6.5.0\n');
      }
      return wpCliWith({})(o);
    });
    const out = await audit(install());
    expect(versionCalls).toBe(2);
    expect(out.wp_version).toBe('6.5.0');
    expect(out.coverage).toBe('full');
  });

  it('nothing answering at all: the scan is failed, not a clean audit', async () => {
    vi.mocked(runProcess).mockImplementation(async () =>
      run(1, '', 'Error: This does not seem to be a WordPress installation.\n'),
    );
    const ctx = plugin();
    const out = await audit(install(), {}, ctx);
    expect(out.tools_run[0]?.status).toBe('failed');
    expect(out.coverage).not.toBe('full');
    expect(ctx.storage.scans.getById(out.scan_id)?.status).toBe('failed');
  });
});

describe('wp_audit — checksum rows it cannot classify, and must-use plugins', () => {
  it('a row whose message names no known state is "unknown", never dropped', async () => {
    vi.mocked(runProcess).mockImplementation(async (o) =>
      wpCliWith({
        'core verify-checksums': run(
          1,
          JSON.stringify([
            { file: 'wp-includes/x.php', message: 'Something new WP-CLI says' },
            { file: 'wp-admin/y.php', status: 'changed' },
          ]),
          'Error: nope\n',
        ),
      })(o),
    );
    const out = await audit(install());
    expect(out.checksum_mismatches.core).toEqual([
      { file: 'wp-includes/x.php', status: 'unknown' },
      { file: 'wp-admin/y.php', status: 'modified' },
    ]);
  });

  it('exit 1 with rows that are not checksum rows is a failed check, not a report', async () => {
    vi.mocked(runProcess).mockImplementation(async (o) =>
      wpCliWith({ 'core verify-checksums': run(1, JSON.stringify([{ name: 'not a checksum row' }]), 'Error: x\n') })(o),
    );
    const out = await audit(install());
    expect(callsOf('core', 'verify-checksums')).toBe(4);
    expect(out.checksum_mismatches.core).toEqual([]);
    expect(out.tools_run[0]?.reason).toMatch(/core checksums not verified/);
  });

  it('a must-use plugin WP-CLI cannot verify, and a must-use plugin it skipped, are both named', async () => {
    vi.mocked(runProcess).mockImplementation(async (o) =>
      wpCliWith({
        'plugin verify-checksums': run(
          0,
          '',
          "Warning: Must-use plugin 'loader.php' appears to be a custom file or loader plugin and cannot be verified.\n" +
            'Warning: Could not retrieve the checksums for version 1.2 of must-use plugin mu-tools, skipping.\n' +
            'Success: Verified 1 of 1 plugins (2 skipped).\n',
        ),
      })(o),
    );
    const out = await audit(install());
    expect(out.checksums_not_checked.plugins).toEqual([
      { plugin: 'loader.php', reason: 'a custom must-use file WP-CLI cannot verify' },
      { plugin: 'mu-tools', reason: 'WP-CLI could not retrieve the checksums for version 1.2 of must-use plugin' },
    ]);
    expect(out.tools_run[0]?.reason).toBe('2 plugin(s) not verified: loader.php, mu-tools');
  });
});
