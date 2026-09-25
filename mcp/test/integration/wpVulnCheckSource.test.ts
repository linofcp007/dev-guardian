/**
 * Integration test for `wp_vuln_check_source`: wires the two network passes
 * (Wordfence Intelligence v3, wp.org plugin API) through a mocked global
 * `fetch`, mirroring `test/integration/securityTools.test.ts`'s pattern for
 * the process-spawning scan tools. No real network — `GUARDIAN_OFFLINE=1`
 * is the suite default (`vitest.config.ts`); tests exercising the online
 * path clear it with `vi.stubEnv('GUARDIAN_OFFLINE', '0')`.
 */

import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
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
});

function getTool(name: string) {
  const t = TOOLS.find((x) => x.name === name);
  if (!t) throw new Error(`Tool '${name}' not registered`);
  return t;
}

function makePlugin(): PluginContext {
  const db = new Database(':memory:');
  runMigrations(db);
  const storage = new Storage(db);
  return {
    storage,
    shell: null,
    scriptsDir: process.cwd(),
    progressNotifier: { send: () => {} },
  };
}

function writeFile(path: string, content: string): void {
  mkdirSync(join(path, '..'), { recursive: true });
  writeFileSync(path, content, 'utf8');
}

/** A WP install: core 6.4.0, three plugins (one Wordfence-vulnerable, one
 *  closed on wp.org, one stale on wp.org), one Wordfence-vulnerable theme. */
function buildWpInstall(): string {
  const root = makeTempDir('wpvcs-');
  writeFile(join(root, 'wp-includes', 'version.php'), "<?php\n$wp_version = '6.4.0';\n");
  writeFile(
    join(root, 'wp-content', 'plugins', 'sample-plugin', 'sample-plugin.php'),
    ['<?php', '/*', 'Plugin Name: Sample Plugin', 'Version: 0.9', '*/'].join('\n'),
  );
  writeFile(
    join(root, 'wp-content', 'plugins', 'closed-plugin', 'closed-plugin.php'),
    ['<?php', '/*', 'Plugin Name: Closed Plugin', 'Version: 1.0', '*/'].join('\n'),
  );
  writeFile(
    join(root, 'wp-content', 'plugins', 'stale-plugin', 'stale-plugin.php'),
    ['<?php', '/*', 'Plugin Name: Stale Plugin', 'Version: 2.0', '*/'].join('\n'),
  );
  writeFile(
    join(root, 'wp-content', 'themes', 'sample-theme', 'style.css'),
    ['/*', 'Theme Name: Sample Theme', 'Version: 1.5', '*/'].join('\n'),
  );
  return root;
}

const WORDFENCE_FEED = {
  'core-vuln': {
    id: 'core-vuln',
    title: 'WordPress Core < 6.5 - XSS',
    software: [
      {
        type: 'core',
        name: 'WordPress',
        slug: 'wordpress',
        affected_versions: { r: { from_version: '0', from_inclusive: true, to_version: '6.5', to_inclusive: false } },
        patched: true,
        patched_versions: ['6.5'],
      },
    ],
    cve: 'CVE-2024-0001',
    cvss: { vector: 'x', score: 6.1, rating: 'Medium' },
  },
  'plugin-vuln': {
    id: 'plugin-vuln',
    title: 'Sample Plugin <= 1.0 - SQLi',
    software: [
      {
        type: 'plugin',
        name: 'Sample Plugin',
        slug: 'sample-plugin',
        affected_versions: { r: { from_version: '0', from_inclusive: true, to_version: '1.0', to_inclusive: true } },
        patched: true,
        patched_versions: ['1.0.1'],
      },
    ],
    cve: 'CVE-2024-0002',
    cvss: { vector: 'x', score: 9.8, rating: 'Critical' },
  },
  'theme-vuln': {
    id: 'theme-vuln',
    title: 'Sample Theme <= 2.0 - CSRF',
    software: [
      {
        type: 'theme',
        name: 'Sample Theme',
        slug: 'sample-theme',
        affected_versions: { r: { from_version: '0', from_inclusive: true, to_version: '2.0', to_inclusive: true } },
        patched: false,
        patched_versions: [],
      },
    ],
    cve: 'CVE-2024-0003',
    cvss: { vector: 'x', score: 5.0, rating: 'Medium' },
  },
  'mu-plugin-vuln': {
    id: 'mu-plugin-vuln',
    title: 'MU Sample <= 1.0 - Something',
    software: [
      {
        type: 'plugin',
        name: 'MU Sample',
        slug: 'mu-sample',
        affected_versions: { r: { from_version: '0', from_inclusive: true, to_version: '1.0', to_inclusive: true } },
        patched: false,
        patched_versions: [],
      },
    ],
    cve: 'CVE-2024-0004',
    cvss: { vector: 'x', score: 4.0, rating: 'Medium' },
  },
};

/** Fakes both endpoints, dispatching on URL. */
function fakeFetch(overrides: { wordfenceOk?: boolean } = {}): ReturnType<typeof vi.fn> {
  return vi.fn(async (url: string) => {
    if (url.includes('wordfence.com/api/intelligence/v3')) {
      if (overrides.wordfenceOk === false) {
        return { ok: false, status: 500, json: async () => ({}) } as unknown as Response;
      }
      return { ok: true, status: 200, json: async () => WORDFENCE_FEED } as unknown as Response;
    }
    if (url.includes('api.wordpress.org/plugins/info/1.2')) {
      const slugMatch = /request%5Bslug%5D=([^&]+)/.exec(url);
      const slug = slugMatch ? decodeURIComponent(slugMatch[1] as string) : '';
      if (slug === 'closed-plugin') {
        return {
          ok: false,
          status: 404,
          json: async () => ({
            error: 'closed',
            slug: 'closed-plugin',
            closed_date: '2021-01-30',
            reason: 'security-issue',
            reason_text: 'Security Issue',
          }),
        } as unknown as Response;
      }
      if (slug === 'stale-plugin') {
        return {
          ok: true,
          status: 200,
          json: async () => ({ slug: 'stale-plugin', last_updated: '2022-01-01 12:00am GMT' }),
        } as unknown as Response;
      }
      return {
        ok: true,
        status: 200,
        json: async () => ({ slug, last_updated: '2026-09-01 12:00am GMT' }),
      } as unknown as Response;
    }
    throw new Error(`unexpected fetch url: ${url}`);
  });
}

describe('wp_vuln_check_source', () => {
  it('matches Wordfence CVEs and flags a closed + a stale plugin, given a key and a live cache dir', async () => {
    const root = buildWpInstall();
    const cacheDir = makeTempDir('wpvcs-cache-');
    vi.stubEnv('GUARDIAN_OFFLINE', '0');
    vi.stubEnv('WORDFENCE_API_KEY', 'test-token');
    vi.stubEnv('LOCALAPPDATA', cacheDir);
    vi.stubEnv('XDG_CACHE_HOME', cacheDir);
    const fetchMock = fakeFetch();
    vi.stubGlobal('fetch', fetchMock);

    const tool = getTool('wp_vuln_check_source');
    const plugin = makePlugin();
    const r = (await tool.handler({ project_path: root }, plugin)) as {
      ok: true;
      scan_id: string;
      coverage: string;
      tools_run: { name: string; status: string }[];
      missing_tools: string[];
      findings_count_by_severity: Record<string, number>;
      wordfence: { status: string; matched_count: number };
      wp_org: { checked: number; found: number; closed: number; stale: number };
    };

    expect(r.ok).toBe(true);
    expect(r.coverage).toBe('full');
    expect(r.missing_tools).toEqual([]);
    expect(r.tools_run).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ name: 'wordfence-feed', status: 'ok' }),
        expect.objectContaining({ name: 'wp-plugin-api', status: 'ok' }),
      ]),
    );

    // 3 Wordfence matches (core, sample-plugin, sample-theme) + 1 closed +
    // 1 stale wp.org finding = 5.
    const total = Object.values(r.findings_count_by_severity).reduce((a, b) => a + b, 0);
    expect(total).toBe(5);
    expect(r.wordfence.matched_count).toBe(3);
    expect(r.wp_org).toMatchObject({ checked: 3, found: 2, closed: 1, stale: 1 });

    const cves = plugin.storage.cves.listActive(r.scan_id);
    expect(cves.map((c) => c.cve_id).sort()).toEqual(['CVE-2024-0001', 'CVE-2024-0002', 'CVE-2024-0003']);

    const findings = plugin.storage.findings.listByScan(r.scan_id);
    const closedFinding = findings.find((f) => f.subcategory === 'wordpress-plugin-closed');
    expect(closedFinding?.severity).toBe('high'); // security-issue closure
    const staleFinding = findings.find((f) => f.subcategory === 'wordpress-plugin-stale');
    expect(staleFinding?.severity).toBe('low');
  });

  it('reports coverage partial with a reason when no WORDFENCE_API_KEY is set, but wp.org checks still run', async () => {
    const root = buildWpInstall();
    const cacheDir = makeTempDir('wpvcs-cache-');
    vi.stubEnv('GUARDIAN_OFFLINE', '0');
    vi.stubEnv('WORDFENCE_API_KEY', '');
    vi.stubEnv('LOCALAPPDATA', cacheDir);
    vi.stubEnv('XDG_CACHE_HOME', cacheDir);
    const fetchMock = fakeFetch();
    vi.stubGlobal('fetch', fetchMock);

    const tool = getTool('wp_vuln_check_source');
    const plugin = makePlugin();
    const r = (await tool.handler({ project_path: root }, plugin)) as {
      ok: true;
      coverage: string;
      missing_tools: string[];
      tools_run: { name: string; status: string; reason?: string }[];
      wp_org: { checked: number; closed: number; stale: number };
    };

    expect(r.ok).toBe(true);
    expect(r.coverage).toBe('partial');
    expect(r.missing_tools).toContain('wordfence-feed');
    const wfRun = r.tools_run.find((t) => t.name === 'wordfence-feed');
    expect(wfRun?.status).toBe('skipped');
    expect(wfRun?.reason).toMatch(/WORDFENCE_API_KEY/);
    // wp.org still ran and still found the closed + stale plugins.
    expect(r.wp_org).toMatchObject({ checked: 3, closed: 1, stale: 1 });
    // Wordfence's own fetch was never attempted; wp.org's was.
    expect(fetchMock.mock.calls.some((c) => (c[0] as string).includes('wordfence.com'))).toBe(false);
    expect(fetchMock.mock.calls.some((c) => (c[0] as string).includes('api.wordpress.org'))).toBe(true);
  });

  it('under GUARDIAN_OFFLINE=1 with no cache, both passes are skipped and coverage is none', async () => {
    const root = buildWpInstall();
    const cacheDir = makeTempDir('wpvcs-cache-');
    // GUARDIAN_OFFLINE stays at the suite default ('1') here — deliberately
    // not cleared, to exercise the offline path.
    vi.stubEnv('WORDFENCE_API_KEY', 'test-token');
    vi.stubEnv('LOCALAPPDATA', cacheDir);
    vi.stubEnv('XDG_CACHE_HOME', cacheDir);
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);

    const tool = getTool('wp_vuln_check_source');
    const plugin = makePlugin();
    const r = (await tool.handler({ project_path: root }, plugin)) as {
      ok: true;
      coverage: string;
      missing_tools: string[];
      tools_run: { name: string; status: string; reason?: string }[];
    };

    expect(r.ok).toBe(true);
    expect(r.coverage).toBe('none');
    expect(r.missing_tools.sort()).toEqual(['wordfence-feed', 'wp-plugin-api']);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('warns when project_path does not look like a WordPress install root', async () => {
    const root = makeTempDir('wpvcs-notwp-');
    vi.stubEnv('WORDFENCE_API_KEY', 'test-token');
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);

    const tool = getTool('wp_vuln_check_source');
    const plugin = makePlugin();
    const r = (await tool.handler({ project_path: root }, plugin)) as {
      ok: true;
      warnings_extra?: string[];
    };

    expect(r.ok).toBe(true);
    expect(r.warnings_extra?.some((w) => w.includes('not_a_wordpress_install_root'))).toBe(true);
  });

  // Fix round 1, item 1 (GC3): a component found but with no readable
  // version used to vanish from matching with no signal anywhere.
  describe('unmatched-version coverage gap (fix round 1, item 1)', () => {
    it('marks wordfence-feed FAILED (not ok) when every installed component is unversioned', async () => {
      const root = makeTempDir('wpvcs-allunversioned-');
      writeFile(
        join(root, 'wp-content', 'plugins', 'no-version', 'no-version.php'),
        ['<?php', '/*', 'Plugin Name: No Version', '*/'].join('\n'),
      );
      // No wp-includes/version.php either — core is also unversioned.
      const cacheDir = makeTempDir('wpvcs-cache-');
      vi.stubEnv('GUARDIAN_OFFLINE', '0');
      vi.stubEnv('WORDFENCE_API_KEY', 'test-token');
      vi.stubEnv('LOCALAPPDATA', cacheDir);
      vi.stubEnv('XDG_CACHE_HOME', cacheDir);
      vi.stubGlobal('fetch', fakeFetch());

      const tool = getTool('wp_vuln_check_source');
      const r = (await tool.handler({ project_path: root }, makePlugin())) as {
        ok: true;
        tools_run: { name: string; status: string; reason?: string }[];
        wordfence: { matched_count: number };
      };

      expect(r.ok).toBe(true);
      const wfRun = r.tools_run.find((t) => t.name === 'wordfence-feed');
      expect(wfRun?.status).toBe('failed');
      expect(wfRun?.reason).toMatch(/0 of 2 installed component/);
      expect(r.wordfence.matched_count).toBe(0);
    });

    it('records a named partial gap when some, but not all, components are unversioned', async () => {
      const root = buildWpInstall(); // core + 3 versioned plugins + 1 versioned theme
      writeFile(
        join(root, 'wp-content', 'plugins', 'no-version', 'no-version.php'),
        ['<?php', '/*', 'Plugin Name: No Version', '*/'].join('\n'),
      );
      const cacheDir = makeTempDir('wpvcs-cache-');
      vi.stubEnv('GUARDIAN_OFFLINE', '0');
      vi.stubEnv('WORDFENCE_API_KEY', 'test-token');
      vi.stubEnv('LOCALAPPDATA', cacheDir);
      vi.stubEnv('XDG_CACHE_HOME', cacheDir);
      vi.stubGlobal('fetch', fakeFetch());

      const tool = getTool('wp_vuln_check_source');
      const r = (await tool.handler({ project_path: root }, makePlugin())) as {
        ok: true;
        coverage: string;
        missing_tools: string[];
        tools_run: { name: string; status: string }[];
        warnings_extra?: string[];
      };

      expect(r.ok).toBe(true);
      // The pass itself genuinely measured real matches, so it stays 'ok'…
      expect(r.tools_run.find((t) => t.name === 'wordfence-feed')?.status).toBe('ok');
      // …but the gap is still named and still moves coverage off 'full'.
      expect(r.missing_tools).toContain('wordfence-feed:unmatched-version');
      expect(r.coverage).toBe('partial');
      expect(r.warnings_extra?.some((w) => w.includes('no-version') && w.includes('could not be checked'))).toBe(
        true,
      );
    });
  });

  // Fix round 1, item 3: mu-plugins matched against Wordfence, never
  // wp.org-checked.
  it('matches a mu-plugin against the Wordfence feed but never checks it against wp.org', async () => {
    const root = buildWpInstall();
    writeFile(
      join(root, 'wp-content', 'mu-plugins', 'mu-sample.php'),
      ['<?php', '/*', 'Plugin Name: MU Sample', 'Version: 0.5', '*/'].join('\n'),
    );
    const cacheDir = makeTempDir('wpvcs-cache-');
    vi.stubEnv('GUARDIAN_OFFLINE', '0');
    vi.stubEnv('WORDFENCE_API_KEY', 'test-token');
    vi.stubEnv('LOCALAPPDATA', cacheDir);
    vi.stubEnv('XDG_CACHE_HOME', cacheDir);
    const fetchMock = fakeFetch();
    vi.stubGlobal('fetch', fetchMock);

    const tool = getTool('wp_vuln_check_source');
    const r = (await tool.handler({ project_path: root }, makePlugin())) as {
      ok: true;
      wordfence: { matched_count: number };
      wp_org: { checked: number };
      inventory: { mu_plugins_count: number };
    };

    expect(r.ok).toBe(true);
    expect(r.inventory.mu_plugins_count).toBe(1);
    // 3 from buildWpInstall (core, sample-plugin, sample-theme) + the
    // mu-plugin's own match against the same 'sample-plugin' feed entry.
    expect(r.wordfence.matched_count).toBe(4);
    // wp.org is only ever asked about the 3 REGULAR plugins.
    expect(r.wp_org.checked).toBe(3);
    const wpOrgSlugs = fetchMock.mock.calls
      .filter((c) => (c[0] as string).includes('api.wordpress.org'))
      .map((c) => /request%5Bslug%5D=([^&]+)/.exec(c[0] as string)?.[1]);
    expect(wpOrgSlugs).not.toContain('mu-sample');
  });
});
