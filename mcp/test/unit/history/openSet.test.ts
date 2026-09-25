/**
 * The open set: a project's open findings are the union, over every
 * state-describing scan type, of the newest usable scan of that type for that
 * project — deduplicated by identity (fingerprint as the fallback), minus
 * active suppressions. See `src/history/openSet.ts`.
 */

import { afterAll, describe, expect, it } from 'vitest';
import { openSetForProject } from '../../../src/history/openSet.js';
import { SCAN_TYPE_ROLE, STATE_SCAN_TYPES, sourceTypesOf } from '../../../src/history/scanRoles.js';
import { SCAN_TYPES } from '../../../src/types.js';
import { cleanupTempDirs } from '../../helpers/tempDir.js';
import { freshPlugin, seedScan } from '../../helpers/historySeed.js';

afterAll(cleanupTempDirs);

const P = '/project';
const OTHER = '/other';

function tools(set: ReturnType<typeof openSetForProject>): string[] {
  return set.findings.map((f) => f.tool).sort();
}

describe('SCAN_TYPE_ROLE', () => {
  it('classifies every scan type exactly once', () => {
    expect(Object.keys(SCAN_TYPE_ROLE).sort()).toEqual([...SCAN_TYPES].sort());
  });

  it('never counts artefacts, roll-ups, third-party targets or diff reviews', () => {
    for (const t of ['sbom', 'detect_stack', 'init', 'observability', 'audit', 'skill_audit', 'review_pr'] as const) {
      expect(STATE_SCAN_TYPES).not.toContain(t);
    }
  });

  it('feeds sast, secrets and deps from security_full as well as from their own type', () => {
    expect(sourceTypesOf('sast')).toEqual(['sast', 'security_full']);
    expect(sourceTypesOf('secrets')).toEqual(['secrets', 'security_full']);
    expect(sourceTypesOf('deps')).toEqual(['deps', 'security_full']);
    expect(sourceTypesOf('bugs')).toEqual(['bugs']);
    expect(sourceTypesOf('security_full')).toEqual(['security_full']);
  });
});

describe('openSetForProject', () => {
  it('unions the latest scan of every state type, and ignores non-state types', () => {
    const s = freshPlugin();
    seedScan(s, { id: 'sast', type: 'sast', project: P, findings: [{ tool: 'semgrep' }] });
    seedScan(s, { id: 'sec', type: 'secrets', project: P, tools_run: [{ name: 'gitleaks', status: 'ok' }], findings: [{ tool: 'gitleaks' }] });
    seedScan(s, { id: 'audit', type: 'audit', project: P, findings: [{ tool: 'rollup' }] });
    seedScan(s, { id: 'sbom', type: 'sbom', project: P, tools_run: [{ name: 'syft', status: 'ok' }] });
    seedScan(s, { id: 'pr', type: 'review_pr', project: P, findings: [{ tool: 'semgrep-pr' }] });

    const set = openSetForProject(s.storage, P);
    expect(tools(set)).toEqual(['gitleaks', 'semgrep']);
    expect(set.sources.map((x) => x.scan_id).sort()).toEqual(['sast', 'sec']);
    expect(set.coverage).toBe('full');
  });

  it("never reads another project's scans", () => {
    const s = freshPlugin();
    seedScan(s, { id: 'mine', type: 'sast', project: P, findings: [{ tool: 'semgrep' }] });
    seedScan(s, { id: 'theirs', type: 'secrets', project: OTHER, findings: [{ tool: 'gitleaks' }] });
    expect(tools(openSetForProject(s.storage, P))).toEqual(['semgrep']);
  });

  it('reports coverage none, and no findings, for a project never scanned', () => {
    const s = freshPlugin();
    const set = openSetForProject(s.storage, P);
    expect(set.findings).toEqual([]);
    expect(set.coverage).toBe('none');
    expect(set.newest).toBeNull();
  });

  it('counts a security_full parent and its per-type children once', () => {
    // security_scan_full persists each child scan and keeps the merged set
    // on the parent row: the same finding lives in both.
    for (const parentLast of [false, true]) {
      const s = freshPlugin();
      const parent = {
        id: 'parent', type: 'security_full' as const, project: P,
        tools_run: [{ name: 'semgrep', status: 'ok' as const }, { name: 'gitleaks', status: 'ok' as const }],
        findings: [
          { tool: 'semgrep', identity: 'I-sast', file: 'a.ts' },
          { tool: 'gitleaks', identity: 'I-secret', file: 'b.env' },
        ],
      };
      if (!parentLast) seedScan(s, parent);
      seedScan(s, { id: 'c-sast', type: 'sast', project: P, findings: [{ tool: 'semgrep', identity: 'I-sast', file: 'a.ts', line: 3 }] });
      seedScan(s, {
        id: 'c-secrets', type: 'secrets', project: P, tools_run: [{ name: 'gitleaks', status: 'ok' }],
        findings: [{ tool: 'gitleaks', identity: 'I-secret', file: 'b.env', line: 4 }],
      });
      seedScan(s, { id: 'c-deps', type: 'deps', project: P, tools_run: [{ name: 'trivy', status: 'ok' }] });
      if (parentLast) seedScan(s, parent);

      const set = openSetForProject(s.storage, P);
      expect(set.findings.map((f) => f.identity).sort(), `parentLast=${parentLast}`).toEqual(['I-sast', 'I-secret']);
    }
  });

  it('deduplicates across types by identity, and by fingerprint where a side has none', () => {
    const s = freshPlugin();
    seedScan(s, { id: 'sast', type: 'sast', project: P, findings: [
      { fp: 'a'.repeat(64), identity: 'SAME' },
      { fp: 'l'.repeat(64) },
    ] });
    seedScan(s, { id: 'bugs', type: 'bugs', project: P, findings: [
      { fp: 'b'.repeat(64), identity: 'SAME' },
      { fp: 'l'.repeat(64) },
    ] });
    const set = openSetForProject(s.storage, P);
    expect(set.findings).toHaveLength(2);
  });

  it('keeps a legacy security_full row whole when nothing newer covers it', () => {
    const s = freshPlugin();
    seedScan(s, {
      id: 'legacy', type: 'security_full', project: P, tools_run: [],
      findings: [{ tool: 'semgrep' }, { tool: 'gitleaks' }, { tool: 'trivy' }, { tool: 'custom-scanner' }],
    });
    expect(tools(openSetForProject(s.storage, P))).toEqual(['custom-scanner', 'gitleaks', 'semgrep', 'trivy']);
  });

  it('lets a newer scan_sast supersede only the semgrep half of a security_full run', () => {
    const s = freshPlugin();
    seedScan(s, {
      id: 'full', type: 'security_full', project: P,
      tools_run: [{ name: 'semgrep', status: 'ok' }, { name: 'gitleaks', status: 'ok' }],
      findings: [{ tool: 'semgrep', rule_id: 'old-rule' }, { tool: 'gitleaks' }],
    });
    seedScan(s, { id: 'sast', type: 'sast', project: P, findings: [{ tool: 'semgrep', rule_id: 'new-rule' }] });
    const set = openSetForProject(s.storage, P);
    expect(set.findings.map((f) => `${f.tool}:${f.rule_id ?? ''}`).sort()).toEqual(['gitleaks:rule', 'semgrep:new-rule']);
  });

  it('skips a scan that measured nothing, uses the one before it, and says so', () => {
    const s = freshPlugin();
    seedScan(s, { id: 'good', type: 'sast', project: P, findings: [{ tool: 'semgrep' }] });
    seedScan(s, {
      id: 'blind', type: 'sast', project: P,
      tools_run: [{ name: 'semgrep', status: 'skipped', reason: 'not_installed' }],
      missing_tools: ['semgrep'],
    });
    const set = openSetForProject(s.storage, P);
    expect(set.findings).toHaveLength(1);
    expect(set.sources.map((x) => x.scan_id)).toEqual(['good']);
    expect(set.skipped).toEqual([expect.objectContaining({ scan_id: 'blind', slot: 'sast', reason: 'coverage_none' })]);
    expect(set.coverage).toBe('partial');
  });

  it("judges a security_full run's coverage per type: a missing gitleaks does not blank the secrets", () => {
    const s = freshPlugin();
    seedScan(s, { id: 'secrets', type: 'secrets', project: P, tools_run: [{ name: 'gitleaks', status: 'ok' }], findings: [{ tool: 'gitleaks' }] });
    seedScan(s, {
      id: 'full', type: 'security_full', project: P,
      tools_run: [{ name: 'semgrep', status: 'ok' }, { name: 'gitleaks', status: 'skipped', reason: 'not_installed' }],
      missing_tools: ['gitleaks'],
      findings: [{ tool: 'semgrep' }],
    });
    const set = openSetForProject(s.storage, P);
    expect(tools(set)).toEqual(['gitleaks', 'semgrep']);
    expect(set.skipped).toEqual([expect.objectContaining({ scan_id: 'full', slot: 'secrets' })]);
  });

  it('never lets a scoped (diff/partial) run supersede a full one', () => {
    const s = freshPlugin();
    seedScan(s, { id: 'full', type: 'sast', project: P, findings: [{ tool: 'semgrep' }, { tool: 'semgrep' }] });
    seedScan(s, { id: 'diff', type: 'sast', project: P, meta: { scope: { files: ['x.ts'] } } });
    const set = openSetForProject(s.storage, P);
    expect(set.findings).toHaveLength(2);
    expect(set.sources.map((x) => x.scan_id)).toEqual(['full']);
  });

  it("does not let wp_plugin_check's single-plugin lookup shadow a wp_vuln_check scan", () => {
    const s = freshPlugin();
    seedScan(s, { id: 'vulns', type: 'wp_vuln_check', project: P, tools_run: [{ name: 'wpscan', status: 'ok' }], findings: [{ tool: 'wpscan' }] });
    seedScan(s, { id: 'lookup', type: 'wp_vuln_check', project: P, tools_run: [{ name: 'wp_plugin_check', status: 'ok' }], meta: { slug: 'akismet' } });
    expect(tools(openSetForProject(s.storage, P))).toEqual(['wpscan']);
  });

  it('removes findings suppressed by fingerprint or by identity, as of the given clock', () => {
    const s = freshPlugin();
    seedScan(s, { id: 'sast', type: 'sast', project: P, findings: [
      { fp: '1'.repeat(64) },
      { fp: '2'.repeat(64), identity: 'ID-2' },
      { fp: '3'.repeat(64) },
    ] });
    s.storage.suppressions.insert({ finding_fingerprint: '1'.repeat(64), reason: 'fp' });
    s.storage.suppressions.insert({ finding_fingerprint: 'stale-line', finding_identity: 'ID-2', reason: 'moved' });
    s.storage.suppressions.insert({
      finding_fingerprint: '3'.repeat(64), reason: 'expired', expires_at: '2026-02-01T00:00:00.000Z',
    });
    const now = Date.parse('2026-03-01T00:00:00.000Z');
    expect(openSetForProject(s.storage, P, { now }).findings.map((f) => f.fingerprint)).toEqual(['3'.repeat(64)]);
    const before = Date.parse('2026-01-15T00:00:00.000Z');
    expect(openSetForProject(s.storage, P, { now: before }).findings).toHaveLength(0);
  });

  it('names the source scan of every finding', () => {
    const s = freshPlugin();
    seedScan(s, { id: 'sast', type: 'sast', project: P, findings: [{ tool: 'semgrep' }] });
    expect(openSetForProject(s.storage, P).findings[0]?.scan_id).toBe('sast');
  });
});
