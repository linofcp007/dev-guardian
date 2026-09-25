/**
 * How create_fix_pr re-verifies a target (Task 11 item 2 and the Task 10
 * handoff): the SAME tool and rule packs that produced it, and a re-scan
 * whose own bookkeeping says the scanner that must re-check it ran ok —
 * including Trivy's per-ecosystem gaps.
 */
import { describe, expect, it } from 'vitest';
import { rescanOriginOf, scannerNotVerified } from '../../../src/fixpr/rescan.js';
import type { Finding, ScanRecord } from '../../../src/types.js';

function finding(over: Partial<Finding> = {}): Finding {
  return {
    fingerprint: 'f'.repeat(64), tool: 'semgrep', rule_id: 'r', severity: 'high', category: 'security',
    title: 't', fix_available: true, file_path: 'a.js', line_start: 1,
    ...over,
  };
}

function scan(over: Partial<ScanRecord> = {}): ScanRecord {
  return {
    scan_id: 's', scan_type: 'sast', project_path: '/p', tree_hash: 'h', started_at: '', finished_at: '',
    status: 'completed', tools_run: [], missing_tools: [], report_paths: [],
    ...over,
  };
}

describe('rescanOriginOf', () => {
  it('re-scans a scan_sast target with scan_sast, and the local_only that scan recorded', () => {
    expect(rescanOriginOf(finding(), scan())).toMatchObject({ tool: 'scan_sast', input: { local_only: false } });
    expect(rescanOriginOf(finding(), scan({ meta: { local_only: true } }))).toMatchObject({
      tool: 'scan_sast', input: { local_only: true },
    });
  });

  it('re-scans a bug_hunt target with bug_hunt — never scan_sast, which does not load the bugfix packs', () => {
    expect(rescanOriginOf(finding(), scan({ scan_type: 'bugs' }))).toMatchObject({
      tool: 'bug_hunt', input: { include_language_packs: false },
    });
    expect(rescanOriginOf(finding(), scan({ scan_type: 'bugs', meta: { include_language_packs: true } }))).toMatchObject({
      tool: 'bug_hunt', input: { include_language_packs: true },
    });
  });

  it('re-scans dependency targets with the deps tool that found them', () => {
    const trivy = finding({ tool: 'trivy', file_path: 'package-lock.json', line_start: undefined });
    expect(rescanOriginOf(trivy, scan({ scan_type: 'deps_audit' }))?.tool).toBe('deps_audit');
    expect(rescanOriginOf(trivy, scan({ scan_type: 'deps' }))?.tool).toBe('scan_deps');
    // A 2.0.x deps_audit row was typed 'deps' and carries bot_configured.
    expect(rescanOriginOf(trivy, scan({ scan_type: 'deps', meta: { bot_configured: false } }))?.tool).toBe('deps_audit');
  });

  it('has no re-scan for what no tool can re-run with the same packs', () => {
    expect(rescanOriginOf(finding(), scan({ scan_type: 'wordpress' }))).toBeNull();
    expect(rescanOriginOf(finding({ tool: 'wpscan' }), scan({ scan_type: 'wp_vuln_check' }))).toBeNull();
  });
});

describe('scannerNotVerified', () => {
  const trivyNpm = finding({ tool: 'trivy', file_path: 'package-lock.json', line_start: undefined });

  it('Task 10 handoff: Trivy ok overall but with a gap for the TARGET\'s own ecosystem cannot verify it', () => {
    const partial = { tools_run: [{ name: 'trivy', status: 'ok' as const }], missing_tools: ['trivy:npm'] };
    expect(scannerNotVerified(trivyNpm, partial)).toBe('trivy:npm');
  });

  it('a gap in ANOTHER ecosystem does not block this target', () => {
    const partial = { tools_run: [{ name: 'trivy', status: 'ok' as const }], missing_tools: ['trivy:dotnet'] };
    expect(scannerNotVerified(trivyNpm, partial)).toBeNull();
  });

  it('a Trivy that failed is not a Trivy that found nothing — even with nothing in missing_tools', () => {
    expect(scannerNotVerified(trivyNpm, { tools_run: [{ name: 'trivy', status: 'failed' }], missing_tools: [] })).toBe('trivy');
  });

  it('checks npm audit under the name deps_audit records it by (npm), and never trusts a scanner it cannot re-run', () => {
    const npm = finding({ tool: 'npm-audit', line_start: undefined });
    expect(scannerNotVerified(npm, { tools_run: [{ name: 'npm', status: 'ok' }], missing_tools: [] })).toBeNull();
    expect(scannerNotVerified(npm, { tools_run: [{ name: 'trivy', status: 'ok' }], missing_tools: [] })).toBe('npm-audit');
    expect(scannerNotVerified(finding({ tool: 'wpscan' }), { tools_run: [], missing_tools: [] })).toBe('wpscan');
  });

  it('a Semgrep re-scan that was not ok (GC3: scanned nothing, errors) cannot verify', () => {
    expect(scannerNotVerified(finding(), { tools_run: [{ name: 'semgrep', status: 'ok' }], missing_tools: [] })).toBeNull();
    expect(scannerNotVerified(finding(), { tools_run: [{ name: 'semgrep', status: 'failed' }], missing_tools: [] })).toBe('semgrep');
    expect(scannerNotVerified(finding(), { tools_run: [{ name: 'semgrep', status: 'skipped' }], missing_tools: ['semgrep'] })).toBe('semgrep');
  });
});
