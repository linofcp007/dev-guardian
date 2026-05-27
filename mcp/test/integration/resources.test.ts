/**
 * Integration tests for every guardian:// resource.
 *
 * Resources read directly from storage — no execa to mock. We seed an
 * in-memory DB with representative scans / findings / cves / suppressions
 * and verify each handler's JSON output.
 */

import Database from 'better-sqlite3';
import { beforeAll, beforeEach, describe, expect, it } from 'vitest';

import type { PluginContext } from '../../src/context.js';
import { runMigrations } from '../../src/storage/migrations/runner.js';
import { Storage } from '../../src/storage/index.js';
import { RESOURCES } from '../../src/resources/index.js';
import { makeFinding } from '../../src/runners/scannerParsers/index.js';

beforeAll(async () => {
  await import('../../src/resources/scans.js');
  await import('../../src/resources/findings.js');
  await import('../../src/resources/misc.js');
});

function getResource(name: string) {
  const r = RESOURCES.find((x) => x.name === name);
  if (!r) throw new Error(`Resource '${name}' not registered`);
  return r;
}

function makePlugin(): PluginContext {
  const db = new Database(':memory:');
  runMigrations(db);
  const storage = new Storage(db);
  return {
    storage,
    shell: null,
    scriptsDir: '',
    progressNotifier: { send: () => {} },
  };
}

function seedScan(
  plugin: PluginContext,
  args: { id: string; type: import('../../src/types.js').ScanType; findings?: number },
): void {
  plugin.storage.scans.insert({
    scan_id: args.id,
    scan_type: args.type,
    project_path: '/p',
    tree_hash: `h-${args.id}`,
  });
  if (args.findings) {
    const rows = Array.from({ length: args.findings }).map((_, i) => ({
      scan_id: args.id,
      ...makeFinding({
        tool: 'mock',
        severity: i === 0 ? 'critical' : 'high',
        category: 'security',
        title: `finding-${i}`,
        file_path: `src/${args.id}-${i}.ts`,
        line_start: i + 1,
      }),
    }));
    plugin.storage.findings.bulkInsert(rows);
  }
  plugin.storage.scans.finalize({
    scan_id: args.id,
    status: 'completed',
    tools_run: [],
    missing_tools: [],
  });
}

const fakeUri = new URL('guardian://placeholder/');

let plugin: PluginContext;
beforeEach(() => {
  plugin = makePlugin();
});

// ---------------------------------------------------------------------- scans

describe('guardian://scans/* resources', () => {
  it('latest returns last_run=null when no scan exists', async () => {
    const r = await getResource('guardian-scans-latest').handler(fakeUri, {}, plugin);
    expect((r.json as { last_run: null }).last_run).toBeNull();
  });

  it('latest returns the most recent completed scan with counts + top findings', async () => {
    seedScan(plugin, { id: 'A', type: 'sast', findings: 3 });

    const r = await getResource('guardian-scans-latest').handler(fakeUri, {}, plugin);
    const payload = r.json as {
      scan_id: string;
      findings_count_by_severity: { critical: number; high: number };
      top_findings: unknown[];
    };
    expect(payload.scan_id).toBe('A');
    expect(payload.findings_count_by_severity.critical).toBe(1);
    expect(payload.findings_count_by_severity.high).toBe(2);
    expect(payload.top_findings).toHaveLength(3);
  });

  it('history returns up to 50 scans newest-first', async () => {
    for (let i = 0; i < 4; i++) {
      seedScan(plugin, { id: `s-${i}`, type: 'sast' });
    }
    const r = await getResource('guardian-scans-history').handler(fakeUri, {}, plugin);
    const payload = r.json as { scans: Array<{ scan_id: string }> };
    expect(payload.scans).toHaveLength(4);
    expect(payload.scans[0]?.scan_id).toBe('s-3');
  });

  it('by-id returns ScanResult shape', async () => {
    seedScan(plugin, { id: 'one', type: 'sast', findings: 2 });
    const r = await getResource('guardian-scans-by-id').handler(
      fakeUri,
      { scan_id: 'one' },
      plugin,
    );
    const payload = r.json as { scan_id: string; top_findings: unknown[] };
    expect(payload.scan_id).toBe('one');
    expect(payload.top_findings).toHaveLength(2);
  });

  it('by-id throws -32602 when scan_id is unknown', async () => {
    await expect(
      getResource('guardian-scans-by-id').handler(fakeUri, { scan_id: 'nope' }, plugin),
    ).rejects.toMatchObject({ code: -32602 });
  });
});

// ---------------------------------------------------------------------- findings

describe('guardian://findings/* resources', () => {
  it('open returns empty when no scans exist', async () => {
    const r = await getResource('guardian-findings-open').handler(fakeUri, {}, plugin);
    const payload = r.json as { findings: unknown[]; last_run: null };
    expect(payload.findings).toEqual([]);
    expect(payload.last_run).toBeNull();
  });

  it('open hides suppressed fingerprints', async () => {
    seedScan(plugin, { id: 'A', type: 'sast', findings: 3 });
    const all = plugin.storage.findings.listByScan('A');
    plugin.storage.suppressions.insert({
      finding_fingerprint: all[0]!.fingerprint,
      reason: 'fp',
    });

    const r = await getResource('guardian-findings-open').handler(fakeUri, {}, plugin);
    const payload = r.json as { findings: Array<{ fingerprint: string }> };
    expect(payload.findings).toHaveLength(2);
    expect(payload.findings.find((f) => f.fingerprint === all[0]!.fingerprint)).toBeUndefined();
  });

  it('critical returns only severity=critical findings', async () => {
    seedScan(plugin, { id: 'A', type: 'sast', findings: 3 }); // 1 crit, 2 high
    const r = await getResource('guardian-findings-critical').handler(fakeUri, {}, plugin);
    const payload = r.json as { findings: Array<{ severity: string }> };
    expect(payload.findings).toHaveLength(1);
    expect(payload.findings[0]?.severity).toBe('critical');
  });

  it('by-severity/{level} filters correctly', async () => {
    seedScan(plugin, { id: 'A', type: 'sast', findings: 3 });
    const r = await getResource('guardian-findings-by-severity').handler(
      fakeUri,
      { level: 'high' },
      plugin,
    );
    const payload = r.json as { findings: Array<{ severity: string }> };
    expect(payload.findings).toHaveLength(2);
    expect(payload.findings.every((f) => f.severity === 'high')).toBe(true);
  });

  it('by-severity/{level} throws -32602 on invalid level', async () => {
    seedScan(plugin, { id: 'A', type: 'sast' });
    await expect(
      getResource('guardian-findings-by-severity').handler(
        fakeUri,
        { level: 'banana' },
        plugin,
      ),
    ).rejects.toMatchObject({ code: -32602 });
  });
});

// ---------------------------------------------------------------------- misc

describe('guardian://cves/active', () => {
  it('returns CVEs pinned to the latest deps scan', async () => {
    plugin.storage.scans.insert({
      scan_id: 'd1',
      scan_type: 'deps',
      project_path: '/p',
      tree_hash: 'h',
    });
    plugin.storage.cves.upsert({
      cve_id: 'CVE-2024-X',
      package_name: 'lodash',
      installed_version: '4.0.0',
      severity: 'high',
      scan_id: 'd1',
    });
    plugin.storage.scans.finalize({
      scan_id: 'd1',
      status: 'completed',
      tools_run: [],
      missing_tools: [],
    });

    const r = await getResource('guardian-cves-active').handler(fakeUri, {}, plugin);
    const payload = r.json as { cves: Array<{ cve_id: string }> };
    expect(payload.cves).toHaveLength(1);
    expect(payload.cves[0]?.cve_id).toBe('CVE-2024-X');
  });

  it('returns empty when no deps scan has run', async () => {
    const r = await getResource('guardian-cves-active').handler(fakeUri, {}, plugin);
    expect((r.json as { cves: unknown[] }).cves).toEqual([]);
  });
});

describe('guardian://stack', () => {
  it('returns the latest snapshot', async () => {
    plugin.storage.stack.insert({
      project_path: '/p',
      snapshot: {
        os: 'linux',
        arch: 'x86_64',
        languages: ['typescript'],
        package_managers: ['npm'],
        frameworks: ['react'],
        existing_tools: [],
        has_docker: false,
        has_compose: false,
        has_terraform: false,
        has_kubernetes: false,
        has_ansible: false,
        has_github_actions: false,
        has_gitlab_ci: false,
      },
    });

    const r = await getResource('guardian-stack').handler(fakeUri, {}, plugin);
    const payload = r.json as { snapshot: { languages: string[] } };
    expect(payload.snapshot.languages).toEqual(['typescript']);
  });

  it('returns snapshot=null when no snapshot exists', async () => {
    const r = await getResource('guardian-stack').handler(fakeUri, {}, plugin);
    expect((r.json as { snapshot: null }).snapshot).toBeNull();
  });
});

describe('guardian://compliance/status', () => {
  it('surfaces extras stored in scans.meta by compliance_check', async () => {
    plugin.storage.scans.insert({
      scan_id: 'c1',
      scan_type: 'compliance',
      project_path: '/p',
      tree_hash: 'h',
    });
    plugin.storage.scans.finalize({
      scan_id: 'c1',
      status: 'completed',
      tools_run: [],
      missing_tools: [],
      meta: {
        licenses_summary: [{ license: 'MIT', packages: ['x'], risk: 'low' }],
        risky_licenses: [],
        policy_documents_found: { privacy_policy: true, paths: ['PRIVACY.md'] },
      },
    });

    const r = await getResource('guardian-compliance-status').handler(fakeUri, {}, plugin);
    const payload = r.json as {
      scan_id: string;
      licenses_summary: Array<{ license: string }>;
      policy_documents_found: { privacy_policy: boolean };
    };
    expect(payload.scan_id).toBe('c1');
    expect(payload.licenses_summary[0]?.license).toBe('MIT');
    expect(payload.policy_documents_found.privacy_policy).toBe(true);
  });

  it('returns last_run=null when no compliance scan exists', async () => {
    const r = await getResource('guardian-compliance-status').handler(fakeUri, {}, plugin);
    expect((r.json as { last_run: null }).last_run).toBeNull();
  });
});

describe('guardian://baseline', () => {
  it('returns active=false when no baseline is set', async () => {
    const r = await getResource('guardian-baseline').handler(fakeUri, {}, plugin);
    expect((r.json as { active: false }).active).toBe(false);
  });

  it('returns the active baseline when one is set', async () => {
    seedScan(plugin, { id: 'A', type: 'sast' });
    plugin.storage.baselines.set({ scan_id: 'A', note: 'pinned' });
    const r = await getResource('guardian-baseline').handler(fakeUri, {}, plugin);
    const payload = r.json as { active: boolean; scan_id: string; note?: string };
    expect(payload.active).toBe(true);
    expect(payload.scan_id).toBe('A');
    expect(payload.note).toBe('pinned');
  });
});

describe('guardian://sbom', () => {
  it('returns metadata for the latest sbom scan', async () => {
    plugin.storage.scans.insert({
      scan_id: 'sb1',
      scan_type: 'sbom',
      project_path: '/p',
      tree_hash: '',
    });
    plugin.storage.scans.finalize({
      scan_id: 'sb1',
      status: 'completed',
      tools_run: [],
      missing_tools: [],
      meta: { format: 'cyclonedx-json', produced_by: 'syft', components_count: 42 },
    });

    const r = await getResource('guardian-sbom').handler(fakeUri, {}, plugin);
    const payload = r.json as { format: string; components_count: number };
    expect(payload.format).toBe('cyclonedx-json');
    expect(payload.components_count).toBe(42);
  });

  it('returns last_sbom=null when no SBOM has been generated', async () => {
    const r = await getResource('guardian-sbom').handler(fakeUri, {}, plugin);
    expect((r.json as { last_sbom: null }).last_sbom).toBeNull();
  });
});
