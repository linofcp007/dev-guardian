/**
 * Fix round 1 of llm-scan task 3: what one submission may make the server
 * read (cap per file, distinct files per submission, a file read once), the
 * Windows spellings that are never a project file, and error paths that never
 * reproduce submitted text.
 */

import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import {
  MAX_CITED_FILES,
  MAX_CITED_FILE_BYTES,
  validateHuntSubmission,
  validateVerifySubmission,
  type ProjectReader,
} from '../../../src/llmscan/submission.js';
import type { HuntFinding } from '../../../src/llmscan/types.js';

const FIXTURES = fileURLToPath(new URL('../../fixtures/llm-scan/submissions/', import.meta.url));
const json = <T>(name: string): T => JSON.parse(readFileSync(join(FIXTURES, name), 'utf8')) as T;
const hunt = json<{ entry_points_reviewed: string[]; findings: HuntFinding[] }>('hunt-valid.json');
const verify = json<Record<string, unknown>>('verify-valid.json');
const template = hunt.findings[0] as HuntFinding;
const TEXT = Array.from({ length: 30 }, (_, i) => `line ${i + 1}`).join('\n');
const ROOT = 'unused-by-a-fake-reader';

function recording(answer: (path: string) => ReturnType<ProjectReader>): { reader: ProjectReader; calls: Array<{ path: string; max: number | undefined }> } {
  const calls: Array<{ path: string; max: number | undefined }> = [];
  return {
    calls,
    reader: (_root, path, max) => {
      calls.push({ path, max });
      return answer(path);
    },
  };
}

describe('reads are bounded', () => {
  it('passes a 1 MiB cap, and reads a file cited by many findings once', () => {
    expect(MAX_CITED_FILE_BYTES).toBe(1024 * 1024);
    const s = recording(() => ({ status: 'ok', text: TEXT }));
    const findings = Array.from({ length: 40 }, (_, i) => ({ ...template, file: 'a/x.ts', line: 1 + (i % 20), evidence: 'a/x.ts:3 ok' }));
    const r = validateHuntSubmission({ ...hunt, findings }, { root: ROOT, reader: s.reader });
    expect(r.ok && r.value.findings).toHaveLength(40);
    expect(s.calls).toEqual([{ path: 'a/x.ts', max: MAX_CITED_FILE_BYTES }]);
  });

  it('a file the reader refuses for size reads as "could not be read"', () => {
    const s = recording(() => ({ status: 'refused', reason: 'too-large' as never }));
    const r = validateVerifySubmission(verify, { root: ROOT, reader: s.reader });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.errors.map((e) => e.problem).join()).toContain('could not be read');
  });

  it('after 100 distinct files, further citations are rejected unread with a fixed problem', () => {
    expect(MAX_CITED_FILES).toBe(100);
    // Each finding cites its own file, then evidence whose first reference is absent and the second present.
    const s = recording((p) => (p.startsWith('m/') ? { status: 'absent' } : { status: 'ok', text: TEXT }));
    const findings = Array.from({ length: 50 }, (_, i) => ({
      ...template,
      file: `f/f${i}.ts`,
      line: 1,
      evidence: `m/m${i}.ts:1 g/g${i}.ts:1`,
    }));
    const r = validateHuntSubmission({ ...hunt, findings }, { root: ROOT, reader: s.reader });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(s.calls).toHaveLength(MAX_CITED_FILES);
    expect(new Set(s.calls.map((c) => c.path)).size).toBe(MAX_CITED_FILES);
    expect(r.rejected.some((e) => e.problem.includes('too many distinct files cited'))).toBe(true);
    expect(r.value.findings.length).toBeLessThan(50);
  });
});

describe('Windows spellings are never read', () => {
  it.each([
    'src/a.ts:stream:12',
    'CON:1',
    'src/nul:1',
    'con.txt:1',
    'src/AUX.js:1',
    'lpt1:1',
    'x/Com3.log:1',
    'x/prn:1',
    'a/b/NUL.tar.gz:1',
  ])('%s is rejected without a read', (cite) => {
    const s = recording(() => ({ status: 'ok', text: TEXT }));
    const r = validateVerifySubmission({ ...verify, operation: cite }, { root: ROOT, reader: s.reader });
    expect(r.ok).toBe(false);
    // The other two citations (src/routes/users.ts) may be read; this one never.
    expect(s.calls.map((c) => c.path).filter((p) => p !== 'src/routes/users.ts')).toEqual([]);
  });

  it('a device name inside a longer segment is an ordinary file', () => {
    const s = recording(() => ({ status: 'ok', text: TEXT }));
    const r = validateVerifySubmission({ ...verify, operation: 'src/console.ts:3' }, { root: ROOT, reader: s.reader });
    expect(r.ok).toBe(true);
  });
});

describe('error paths never reproduce submitted text', () => {
  it('an unknown key is not in any path, and a non-identifier key is not reproduced at all', () => {
    const hostile = '../../etc/passwd; rm -rf /';
    const r = validateVerifySubmission({ ...verify, [hostile]: 1, tool_call: 1 }, { root: ROOT, reader: () => ({ status: 'absent' }) });
    expect(r.ok).toBe(false);
    if (r.ok) return;
    const unknown = r.errors.filter((e) => e.problem.startsWith('unknown field'));
    expect(unknown).toHaveLength(2);
    expect(unknown.map((e) => e.path)).toEqual(['[unknown field #0]', '[unknown field #1]']);
    expect(JSON.stringify(r.errors)).not.toContain('passwd');
  });
});
