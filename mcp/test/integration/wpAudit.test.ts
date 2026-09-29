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
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

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
import type { ToolRun } from '../../src/types.js';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';

afterAll(cleanupTempDirs);
beforeAll(async () => {
  await import('../../src/tools/wpAudit.js');
});
beforeEach(() => {
  vi.mocked(runProcess).mockReset();
  vi.mocked(scannerAvailable).mockReset();
  vi.mocked(scannerAvailable).mockResolvedValue('/fake/bin/wp');
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
}

async function audit(dir: string): Promise<Out> {
  const tool = TOOLS.find((t) => t.name === 'wp_audit');
  if (!tool) throw new Error('wp_audit not registered');
  const r = await tool.handler({ wp_install_path: dir }, plugin());
  if (!r.ok) throw new Error(JSON.stringify(r.error));
  return r as unknown as Out;
}

const callsOf = (...words: string[]): number =>
  vi.mocked(runProcess).mock.calls.filter((c) => words.every((w, i) => (c[0].args ?? [])[i] === w)).length;

describe('wp_audit reads WP-CLI’s checksum report on exit 1 (review I5)', () => {
  it('a tampered core and plugin: every mismatch reported, no retry, no warning that the check failed', async () => {
    vi.mocked(runProcess).mockImplementation(async (o) => wpCli()(o));
    const started = Date.now();
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
    expect(Date.now() - started).toBeLessThan(900);
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
