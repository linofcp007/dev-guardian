/**
 * Review C1, against the REAL WPScan on PATH, with a fake home so it has no
 * database (`~/.wpscan/db` / `~/.cache/wpscan/db` absent). Reproduced on
 * WPScan 4.1.0 before the fix: WPScan wrote `{"scan_aborted":"Update
 * required, you can not run a scan if a database file is missing."}` and
 * exited 4; wp_vuln_check answered `{ ok: true, findings_count: 0,
 * cves_count: 0, warnings: ["No WPSCAN_API_TOKEN — public-no-token rate
 * limit applies."] }` with no status, tools_run or coverage — and wrote its
 * report into the server's working directory.
 *
 * The suite runs with GUARDIAN_OFFLINE=1 (vitest.config.ts), so the fix must
 * refuse to download the database and say how to get it: nothing here
 * touches the network (the target is a closed loopback port, and WPScan
 * aborts on the missing database before it contacts the target).
 */

import { mkdirSync } from 'node:fs';
import { join, resolve, sep } from 'node:path';
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import type { PluginContext } from '../../src/context.js';
import { GuardianDatabase as Database } from '../../src/storage/db.js';
import { runMigrations } from '../../src/storage/migrations/runner.js';
import { Storage } from '../../src/storage/index.js';
import { TOOLS } from '../../src/tools/index.js';
import { resetScannerCache } from '../../src/tools/scanHelpers.js';
import type { ToolRun } from '../../src/types.js';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';
import { isInstalled } from '../helpers/toolchain.js';

vi.setConfig({ testTimeout: 180_000 });

afterAll(cleanupTempDirs);
beforeAll(async () => {
  await import('../../src/tools/wpVulnCheck.js');
  resetScannerCache();
});
afterEach(() => {
  vi.unstubAllEnvs();
});

const WPSCAN_INSTALLED = await isInstalled('wpscan');
const REQUIRE_TOOLCHAIN = process.env['GUARDIAN_REQUIRE_SEMGREP'] === '1';

describe('wp_vuln_check with a real WPScan and no database', () => {
  it.runIf(REQUIRE_TOOLCHAIN)('GUARDIAN_REQUIRE_SEMGREP=1 — WPScan must be on PATH', () => {
    expect(WPSCAN_INSTALLED).toBe(true);
  });

  it.skipIf(!WPSCAN_INSTALLED)('is a failed scan naming `wpscan --update`, never ok with 0 findings', async () => {
    const home = makeTempDir('wpscan-fake-home-');
    mkdirSync(join(home, '.cache'), { recursive: true });
    const cache = makeTempDir('wpscan-guardian-cache-');
    vi.stubEnv('HOME', home);
    vi.stubEnv('USERPROFILE', home);
    vi.stubEnv('XDG_CACHE_HOME', join(home, '.cache'));
    vi.stubEnv('GUARDIAN_CACHE_DIR', cache);
    vi.stubEnv('GUARDIAN_OFFLINE', '1');
    vi.stubEnv('WPSCAN_API_TOKEN', '');

    const db = new Database(':memory:');
    runMigrations(db);
    const p: PluginContext = { storage: new Storage(db), shell: null, scriptsDir: process.cwd(), progressNotifier: { send: () => {} } };
    const tool = TOOLS.find((t) => t.name === 'wp_vuln_check');
    if (!tool) throw new Error('wp_vuln_check not registered');
    const r = await tool.handler({ target_url: 'http://127.0.0.1:9/' }, p);
    if (!r.ok) throw new Error(JSON.stringify(r.error));
    const out = r as unknown as {
      status: string;
      coverage: string;
      tools_run: ToolRun[];
      missing_tools: string[];
      report_path: string;
      scan_id: string;
    };
    expect(out.status).toBe('failed');
    expect(out.coverage).toBe('none');
    expect(out.tools_run[0]?.name).toBe('wpscan');
    expect(out.tools_run[0]?.status).toBe('failed');
    expect(out.tools_run[0]?.reason).toMatch(/no local database.*wpscan --update/i);
    expect(p.storage.scans.getById(out.scan_id)?.status).toBe('failed');
    expect(resolve(out.report_path).startsWith(resolve(cache) + sep)).toBe(true);
  });
});
