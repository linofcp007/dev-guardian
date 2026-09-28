/**
 * `wp_vuln_check_source`'s wiring of `wordpress/wpOrgHealth.ts#checkWpOrgPlugins`'s
 * `notChecked` result into `missing_tools` / `warnings` / `coverage` (fix
 * round 1, item 2).
 *
 * The tool's own overall deadline is 60s (`WP_ORG_OVERALL_TIMEOUT_MS`), far
 * too slow to actually exceed in a unit test — and `checkWpOrgPlugins`'s
 * OWN concurrency/deadline behaviour is already covered, with a real mocked
 * slow fetch, in `test/unit/wordpress/wpOrgHealth.test.ts`. This file mocks
 * `checkWpOrgPlugins` itself to return a canned `notChecked` set, isolating
 * exactly the question those tests do not answer: does the TOOL react to
 * `notChecked` correctly?
 */

import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';

vi.mock('../../src/wordpress/wpOrgHealth.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../src/wordpress/wpOrgHealth.js')>();
  return { ...actual, checkWpOrgPlugins: vi.fn() };
});

import { checkWpOrgPlugins } from '../../src/wordpress/wpOrgHealth.js';
import type { PluginContext } from '../../src/context.js';
import { runMigrations } from '../../src/storage/migrations/runner.js';
import { Storage } from '../../src/storage/index.js';
import { GuardianDatabase as Database } from '../../src/storage/db.js';
import { TOOLS } from '../../src/tools/index.js';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';

beforeAll(async () => {
  await import('../../src/tools/wpVulnCheckSource.js');
});

afterAll(cleanupTempDirs);
afterEach(() => {
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
  vi.mocked(checkWpOrgPlugins).mockReset();
});

function getTool(name: string) {
  const t = TOOLS.find((x) => x.name === name);
  if (!t) throw new Error(`Tool '${name}' not registered`);
  return t;
}

function makePlugin(): PluginContext {
  const db = new Database(':memory:');
  runMigrations(db);
  return { storage: new Storage(db), shell: null, scriptsDir: process.cwd(), progressNotifier: { send: () => {} } };
}

function writeFile(path: string, content: string): void {
  mkdirSync(join(path, '..'), { recursive: true });
  writeFileSync(path, content, 'utf8');
}

function buildWpInstallWithPlugins(slugs: string[]): string {
  const root = makeTempDir('wpvcs-deadline-');
  writeFile(join(root, 'wp-includes', 'version.php'), "<?php\n$wp_version = '6.4.0';\n");
  for (const slug of slugs) {
    writeFile(
      join(root, 'wp-content', 'plugins', slug, `${slug}.php`),
      ['<?php', '/*', `Plugin Name: ${slug}`, 'Version: 1.0', '*/'].join('\n'),
    );
  }
  return root;
}

describe('wp_vuln_check_source: wp.org deadline wiring (fix round 1, item 2)', () => {
  it('records a named gap and a warning when some plugins are not checked before the deadline', async () => {
    const root = buildWpInstallWithPlugins(['a', 'b', 'c']);
    vi.stubEnv('GUARDIAN_OFFLINE', '1'); // wordfence-feed side is irrelevant here
    vi.mocked(checkWpOrgPlugins).mockResolvedValue({
      results: [{ slug: 'a', status: 'ok', plugin_status: 'found', fetched_at: new Date().toISOString() }],
      notChecked: ['b', 'c'],
    });

    const tool = getTool('wp_vuln_check_source');
    const r = (await tool.handler({ project_path: root }, makePlugin())) as {
      ok: true;
      coverage: string;
      missing_tools: string[];
      tools_run: { name: string; status: string }[];
      warnings_extra?: string[];
      wp_org: { checked: number; not_checked: number };
    };

    expect(r.ok).toBe(true);
    expect(r.tools_run.find((t) => t.name === 'wp-plugin-api')?.status).toBe('ok');
    expect(r.missing_tools).toContain('wp-plugin-api:deadline');
    expect(r.coverage).toBe('partial');
    expect(r.wp_org).toMatchObject({ checked: 1, not_checked: 2 });
    expect(
      r.warnings_extra?.some((w) => w.includes('did not finish within its overall time budget') && w.includes('b')),
    ).toBe(true);
  });

  it('marks wp-plugin-api FAILED when the deadline is exceeded before any plugin could be checked', async () => {
    const root = buildWpInstallWithPlugins(['a', 'b']);
    // Deliberately online here: an offline-caused "nothing checked" reads
    // 'skipped' (see the previous describe's offline test); this test is
    // specifically the ONLINE "the deadline itself ran out" case, which
    // must read 'failed' instead.
    vi.stubEnv('GUARDIAN_OFFLINE', '0');
    vi.stubEnv('WORDFENCE_API_KEY', ''); // keep the wordfence-feed side out of this test's way
    vi.stubEnv('GUARDIAN_CACHE_DIR', makeTempDir('wpvcs-deadline-cache-')); // never touch the real user cache dir
    vi.mocked(checkWpOrgPlugins).mockResolvedValue({ results: [], notChecked: ['a', 'b'] });

    const tool = getTool('wp_vuln_check_source');
    const r = (await tool.handler({ project_path: root }, makePlugin())) as {
      ok: true;
      tools_run: { name: string; status: string; reason?: string }[];
      missing_tools: string[];
    };

    expect(r.ok).toBe(true);
    const run = r.tools_run.find((t) => t.name === 'wp-plugin-api');
    expect(run?.status).toBe('failed');
    expect(run?.reason).toMatch(/time budget/);
    // Not offline-caused, so this is 'failed' rather than 'skipped' and does
    // NOT also get the (offline-only) missing_tools push.
    expect(r.missing_tools).not.toContain('wp-plugin-api');
  });
});
