/**
 * Helper tests for the briefs renderer (no planned T-ID): the hunt templates'
 * class list never drifts from HUNT_CLASSES, no brief keeps a literal
 * placeholder, and quoted data is never re-expanded.
 */

import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { renderBrief } from '../../../src/llmscan/briefs.js';
import { HUNT_CLASSES } from '../../../src/llmscan/classes.js';
import type { LlmScanTask, TaskKind } from '../../../src/llmscan/types.js';
import { makeFinding } from '../../../src/runners/scannerParsers/index.js';
import type { RouteRecord } from '../../../src/types.js';

/** Every shipped prompt version: the class list may drift in none of them. */
const VERSIONS = ['v1', 'v2', 'v3', 'v4', 'v5'] as const;
const promptsOf = (v: string): string => fileURLToPath(new URL(`../../../../configs/llm-scan/prompts/${v}/`, import.meta.url));

function task(kind: TaskKind, files: string[]): LlmScanTask {
  return {
    plan_id: 'p',
    task_id: 't-0001',
    kind,
    target: { files },
    status: 'leased',
    lease_token: 'l',
    lease_expires_at: null,
    attempts: 0,
    file_hashes: {},
    brief_chars: null,
    response_chars: null,
    independence: null,
    result: null,
    closed_reason: null,
    delivered_at: null,
    closed_at: null,
  };
}

const PLACEHOLDER = /\{(boundary|finding|excerpt|schema|entry_points|scanner_findings)\}/;

describe('prompt templates and the renderer', () => {
  it.each(VERSIONS)('%s: both hunt templates list exactly the HUNT_CLASSES', (version) => {
    for (const name of ['hunt-entrypoint', 'hunt-crosscut']) {
      const text = readFileSync(join(promptsOf(version), `${name}.md`), 'utf8');
      const line = text.split('\n').find((l) => l.includes('`class`: exactly one of'));
      expect(line, name).toBeDefined();
      const list = (line ?? '').split('exactly one of')[1]?.split(';')[0] ?? '';
      const listed = [...list.matchAll(/`([a-z-]+)`/g)].map((m) => m[1]);
      expect(listed, name).toEqual([...HUNT_CLASSES]);
    }
  });

  it('a crosscut task with no files leaves no placeholder and says (none); the boundary is one value', () => {
    let n = 0;
    const r = renderBrief(task('crosscut', []), { root: '.', reader: () => ({ status: 'absent' }), boundary: () => `B${String(n++)}` });
    expect(r.text).not.toMatch(PLACEHOLDER);
    expect(r.text).toContain('BEGIN B0\n(none)\nEND B0');
    expect(n).toBe(1);
  });

  it('a placeholder inside quoted code is not expanded, and a colliding boundary is redrawn', () => {
    const f = makeFinding({ tool: 'semgrep', rule_id: 'r', severity: 'high', category: 'security', title: 't', message: 'm', file_path: 'a.js', line_start: 1 });
    const draws = ['COLLIDE', 'FRESH'];
    const r = renderBrief(task('verify', ['a.js']), {
      root: '.',
      reader: () => ({ status: 'ok', text: 'x = "{schema} {boundary} COLLIDE"' }),
      boundary: () => draws.shift() ?? 'LATE',
      finding: f,
    });
    expect(r.text).toContain('x = "{schema} {boundary} COLLIDE"');
    expect(r.text).toContain('BEGIN FRESH');
  });

  it('a missing prompt version is a fixed-text error', () => {
    expect(() => renderBrief(task('crosscut', []), { root: '.', reader: () => ({ status: 'absent' }), boundary: () => 'B', prompt_version: 'v999' })).toThrow(/not available/);
  });
});

describe('hard ceiling, data channels and a stale line number', () => {
  const finding = (line: number, over: Partial<Parameters<typeof makeFinding>[0]> = {}) =>
    makeFinding({ tool: 'semgrep', rule_id: 'r', severity: 'high', category: 'security', title: 't', message: 'm', file_path: 'a.js', line_start: line, ...over });
  const lines = Array.from({ length: 300 }, (_, i) => `  const value_${String(i)} = compute(${String(i)}); // padding padding padding`);
  const reader = (text: string) => () => ({ status: 'ok' as const, text });

  it('an oversized excerpt is cut around the flagged line, which stays; the brief never passes the ceiling', () => {
    lines[149] = '  const flagged_here = run(input);';
    const text = lines.join('\n');
    const full = renderBrief(task('verify', ['a.js']), { root: '.', reader: reader(text), boundary: () => 'B', finding: finding(150) });
    const limit = full.estimated_tokens - 400;
    const r = renderBrief(task('verify', ['a.js']), { root: '.', reader: reader(text), boundary: () => 'B', finding: finding(150), max_tokens: limit });
    expect(r.estimated_tokens).toBeLessThanOrEqual(limit);
    expect(r.text).toContain('>150 | ');
    expect(r.text).toContain('flagged_here');
    expect(r.chars).toBeLessThan(full.chars);
  });

  it('an oversized scanner-findings list is dropped first, the rest of the brief kept', () => {
    const many = Array.from({ length: 200 }, (_, i) => finding(i + 1, { message: `message ${String(i)} ${'detail '.repeat(40)}`, file_path: `f${String(i)}.js` }));
    const ctx = { root: '.', reader: reader(''), boundary: () => 'B', scanner_findings: many };
    const full = renderBrief(task('crosscut', []), ctx);
    const limit = full.estimated_tokens - 500;
    const r = renderBrief(task('crosscut', []), { ...ctx, max_tokens: limit });
    expect(r.estimated_tokens).toBeLessThanOrEqual(limit);
    expect(r.text).toContain('(omitted: the brief size limit)');
  });

  it('a brief that cannot fit even cut to the minimum is refused with a fixed-text error', () => {
    expect(() => renderBrief(task('crosscut', []), { root: '.', reader: reader(''), boundary: () => 'B', max_tokens: 100 })).toThrow(/exceeds the size limit/);
  });

  it('a token inside a route path, rule id, tool or file path is replaced by a marker', () => {
    const token = `ghp_${'A1b2C3d4E5f6'.repeat(3)}`;
    const route: RouteRecord = {
      method: 'GET', provenance: 'code', path_raw: `/hook/${token}`, path_resolved: `/hook/${token}`, path_partial: false, file: 'src/r.ts', line: 3,
      framework: 'express', language: 'typescript', auth_hint: 'unknown', params: [], confidence: 'high',
    };
    const h = renderBrief(task('hunt', ['src/r.ts']), { root: '.', reader: reader(''), boundary: () => 'B', entry_points: [route] });
    expect(h.text).not.toContain(token);
    expect(h.text).toMatch(/‹github-token line 1›/);
    const f = finding(1, { tool: token, rule_id: `rule-${token}`, file_path: `dir/${token}.js` });
    const v = renderBrief(task('verify', ['a.js']), { root: '.', reader: reader('x'), boundary: () => 'B', finding: f, scanner_findings: [f] });
    expect(v.text).not.toContain(token);
    const s = renderBrief(task('crosscut', []), { root: '.', reader: reader(''), boundary: () => 'B', scanner_findings: [f] });
    expect(s.text).not.toContain(token);
  });

  it('a line number past the end of the file marks the last line and says so', () => {
    const r = renderBrief(task('verify', ['a.js']), { root: '.', reader: reader('one\ntwo\nthree'), boundary: () => 'B', finding: finding(99) });
    expect(r.text).toContain('(the flagged line 99 is beyond the end of the file; the last line, 3, is marked)');
    expect(r.text).toContain('>3 | three');
  });
});
