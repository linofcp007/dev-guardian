/**
 * The `file:line` references a hunt finding's free-text `evidence` must hold
 * (US-2.AC-3: "at least one reference must exist").
 *
 * A model cites a span as often as a line: in the v2 eval run (2026-10-08)
 * three of four findings of one VAmPI hunt task were refused with "needs at
 * least one file:line reference that exists", each a real finding the hunt
 * had made. A range (`users.py:185-187`, with a hyphen or an en dash) and a
 * reference in brackets are references too; both ends of a range must exist.
 * Reads stay the same: one contained read per distinct file.
 */

import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { validateHuntSubmission, type ProjectReader } from '../../../src/llmscan/submission.js';
import type { HuntFinding } from '../../../src/llmscan/types.js';

const FIXTURES = fileURLToPath(new URL('../../fixtures/llm-scan/submissions/', import.meta.url));
const hunt = JSON.parse(readFileSync(join(FIXTURES, 'hunt-valid.json'), 'utf8')) as { entry_points_reviewed: string[]; findings: HuntFinding[] };
const template = hunt.findings[0] as HuntFinding;
const TEXT = Array.from({ length: 30 }, (_, i) => `line ${i + 1}`).join('\n');
const reader: ProjectReader = () => ({ status: 'ok', text: TEXT });

function judged(evidence: string): { accepted: number; problems: string[] } {
  const r = validateHuntSubmission({ ...hunt, findings: [{ ...template, file: 'a/x.ts', line: 3, evidence }] }, { root: 'r', reader });
  if (!r.ok) return { accepted: 0, problems: r.errors.map((e) => e.problem) };
  return { accepted: r.value.findings.length, problems: r.rejected.map((e) => e.problem) };
}

describe('a hunt finding\'s evidence: the references a model writes', () => {
  it.each([
    ['a plain reference', 'the role check is missing at a/x.ts:12'],
    ['a range with a hyphen', 'the handler at a/x.ts:12-14 never checks the owner'],
    ['a range with an en dash', 'the handler at a/x.ts:12–14 never checks the owner'],
    ['a reference in brackets', 'see [a/x.ts:12] where the owner is not compared'],
    ['a range in brackets', 'see [a/x.ts:12-14]'],
  ])('%s holds', (_what, evidence) => {
    expect(judged(evidence)).toEqual({ accepted: 1, problems: [] });
  });

  it.each([
    ['a range whose end is past the file', 'a/x.ts:28-31'],
    ['a range whose start is past the file', 'a/x.ts:31-33'],
    ['no reference at all', 'the owner is never compared'],
    ['a reference outside the project', '../etc/passwd:1'],
  ])('%s does not', (_what, evidence) => {
    const r = judged(evidence);
    expect(r.accepted).toBe(0);
    expect(r.problems.join()).toContain('needs at least one file:line reference that exists in the project');
  });
});
