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

const PROMPTS = fileURLToPath(new URL('../../../../configs/llm-scan/prompts/v1/', import.meta.url));

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
  it('both hunt templates list exactly the HUNT_CLASSES', () => {
    for (const name of ['hunt-entrypoint', 'hunt-crosscut']) {
      const text = readFileSync(join(PROMPTS, `${name}.md`), 'utf8');
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
