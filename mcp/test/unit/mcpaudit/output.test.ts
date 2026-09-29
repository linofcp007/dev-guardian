/**
 * `mcpaudit/output.ts` — what `audit_mcp_tools` returns is bounded (fix
 * round 5, I-3): a 1.8 MB fixture produced two findings with 1.29 MB
 * messages, and 50 servers 7725 findings in a 6.4 MB result.
 */

import { describe, expect, it } from 'vitest';
import { capFindings, capList, capText, MAX_FINDINGS_PER_SERVER, MAX_FINDINGS_TOTAL } from '../../../src/mcpaudit/output.js';
import { makeFinding } from '../../../src/runners/scannerParsers/index.js';
import type { Finding, Severity } from '../../../src/types.js';

function f(i: number, severity: Severity, rule = `rule-${i % 3}`): Finding {
  return makeFinding({
    tool: 'mcp-tool-audit',
    rule_id: rule,
    severity,
    category: 'security',
    title: `finding ${i}`,
    message: 'm',
    file_path: '.mcp.json',
    snippet: `s${i}`,
  });
}

describe('capText / capList', () => {
  it('cuts a string to its bound in UTF-8 bytes, and says so', () => {
    const cut = capText('x'.repeat(5000), 2048);
    expect(Buffer.byteLength(cut)).toBe(2048);
    expect(cut.endsWith('…')).toBe(true);
    expect(capText('short', 2048)).toBe('short');
    // Four-byte code points: never split, never over the bound.
    const emoji = capText('😀'.repeat(1000), 2048);
    expect(Buffer.byteLength(emoji)).toBeLessThanOrEqual(2048);
    expect(emoji.slice(0, -1)).toBe('😀'.repeat(511));
  });

  it('cuts a list to its bound, each entry too, and says how many more', () => {
    const out = capList(Array.from({ length: 150 }, (_, i) => `${'k'.repeat(300)}${i}`), 100, 128);
    expect(out).toHaveLength(101);
    expect(out.slice(0, 100).every((s) => s.length <= 128)).toBe(true);
    expect(out[100]).toBe('… and 50 more');
  });
});

describe('capFindings', () => {
  const severities: Severity[] = ['info', 'low', 'medium', 'high', 'critical'];

  it('keeps at most 50 per server, the most severe, and says what the rest were', () => {
    const server = Array.from({ length: 80 }, (_, i) => f(i, severities[i % 5] ?? 'low'));
    const out = capFindings([{ label: "MCP server 's'", sourceLabel: '.mcp.json', findings: server }]);
    expect(out).toHaveLength(MAX_FINDINGS_PER_SERVER + 1);
    const summary = out[out.length - 1];
    expect(summary?.rule_id).toBe('mcp-audit-findings-capped');
    expect(summary?.message).toMatch(/30 more findings/);
    expect(summary?.message).toMatch(/rule-\d ×\d+/);
    // The 50 kept are the most severe: all 16 critical and all 16 high are in.
    const kept = out.slice(0, MAX_FINDINGS_PER_SERVER);
    expect(kept.filter((x) => x.severity === 'critical')).toHaveLength(16);
    expect(kept.filter((x) => x.severity === 'high')).toHaveLength(16);
  });

  it('keeps at most 500 in total, with one more summary', () => {
    const servers = Array.from({ length: 12 }, (_, s) => ({
      label: `MCP server 's${s}'`,
      sourceLabel: '.mcp.json',
      findings: Array.from({ length: 50 }, (_, i) => f(s * 100 + i, 'medium')),
    }));
    const out = capFindings(servers);
    expect(out).toHaveLength(MAX_FINDINGS_TOTAL + 1);
    expect(out[out.length - 1]?.message).toMatch(/100 more findings/);
  });

  it('a per-server summary the total cap drops is counted in the total summary', () => {
    // Ten servers of 50 high each fill the 500; the eleventh has 60 low: 50
    // kept for it and a summary of 10, then both dropped by the total cap.
    const servers = Array.from({ length: 11 }, (_, s) => ({
      label: `MCP server 's${s}'`,
      sourceLabel: '.mcp.json',
      findings: Array.from({ length: s === 10 ? 60 : 50 }, (_, i) => f(s * 100 + i, s === 10 ? 'low' : 'high')),
    }));
    const out = capFindings(servers);
    expect(out).toHaveLength(MAX_FINDINGS_TOTAL + 1);
    expect(out.slice(0, MAX_FINDINGS_TOTAL).every((x) => x.severity === 'high')).toBe(true);
    const last = out[out.length - 1];
    expect(last?.message).toMatch(/60 more findings/);
    expect(last?.severity).toBe('low');
  });

  it('cuts every text field of a kept finding to its bound', () => {
    const big = { ...f(1, 'high'), title: 't'.repeat(10_000), message: 'm'.repeat(1_000_000), snippet: 's'.repeat(50_000) };
    const [out] = capFindings([{ label: "MCP server 's'", sourceLabel: '.mcp.json', findings: [big] }]);
    expect(Buffer.byteLength(out?.message ?? '')).toBeLessThanOrEqual(2048);
    expect(Buffer.byteLength(out?.title ?? '')).toBeLessThanOrEqual(512);
    expect(Buffer.byteLength(out?.snippet ?? '')).toBeLessThanOrEqual(1024);
  });

  it('leaves a small result alone', () => {
    const out = capFindings([{ label: "MCP server 's'", sourceLabel: '.mcp.json', findings: [f(1, 'high'), f(2, 'low')] }]);
    expect(out.map((x) => x.title)).toEqual(['finding 1', 'finding 2']);
  });
});
