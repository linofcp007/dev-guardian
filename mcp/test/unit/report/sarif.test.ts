/**
 * Unit tests for `report/sarif.ts` — the `artifactLocation.uri` encoding
 * and `region.startLine`/`endLine` pairing rules (task 4 brief, item 5).
 *
 * `ci/report.test.ts` already validates full SARIF documents against the
 * OASIS schema with `ajv-formats` enabled; these tests pin `toUri`'s exact
 * output and the region-pairing rule directly, independent of that harness.
 */
import { describe, expect, it } from 'vitest';
import { toSarif } from '../../../src/report/sarif.js';
import type { Finding } from '../../../src/types.js';

function finding(over: Partial<Finding> = {}): Finding {
  return {
    fingerprint: 'fp1',
    tool: 'semgrep',
    severity: 'high',
    category: 'security',
    title: 'SQL injection',
    file_path: 'src/db.ts',
    fix_available: false,
    ...over,
  };
}

function uriOf(doc: unknown): string | undefined {
  const results = (doc as { runs: [{ results: Array<{
    locations?: Array<{ physicalLocation: { artifactLocation: { uri: string } } }>;
  }> }] }).runs[0].results;
  return results[0]?.locations?.[0]?.physicalLocation.artifactLocation.uri;
}

describe('toSarif — artifact URI encoding', () => {
  // Measured defect (task 4 brief, item 5): a raw space or `%` in
  // `artifactLocation.uri` fails the SARIF schema's `uri-reference` format
  // (confirmed against `ajv-formats`, which is what actually enforces
  // `format` — the base `ajv`/`ajv-draft-04` combination this repo already
  // carries does NOT, so this gap shipped unnoticed under the existing
  // schema test).
  it('percent-encodes a space in the file path', () => {
    const doc = JSON.parse(toSarif([finding({ file_path: 'src/my file.ts' })]));
    expect(uriOf(doc)).toBe('src/my%20file.ts');
  });

  it('percent-encodes a bare percent sign', () => {
    const doc = JSON.parse(toSarif([finding({ file_path: 'src/100%.ts' })]));
    expect(uriOf(doc)).toBe('src/100%25.ts');
  });

  // `#` is syntactically LEGAL in a uri-reference (it starts the fragment),
  // so this is not a format-validation failure — it is silent corruption: a
  // file literally named `notes#3.md` would read back to any SARIF consumer
  // as artifact `notes` with fragment `3.md`.
  it('percent-encodes # so it is never read as a fragment delimiter', () => {
    const doc = JSON.parse(toSarif([finding({ file_path: 'src/notes#3.md' })]));
    const uri = uriOf(doc);
    expect(uri).not.toContain('#');
    expect(uri).toBe('src/notes%233.md');
  });

  it('keeps the `/` separators literal — encoding is per segment, not of the whole string', () => {
    const doc = JSON.parse(toSarif([finding({ file_path: 'src/a b/c d.ts' })]));
    expect(uriOf(doc)).toBe('src/a%20b/c%20d.ts');
  });

  it('leaves an already-safe path unchanged', () => {
    const doc = JSON.parse(toSarif([finding({ file_path: 'src/db.ts' })]));
    expect(uriOf(doc)).toBe('src/db.ts');
  });

  it('still converts backslashes to forward slashes ahead of encoding', () => {
    const doc = JSON.parse(toSarif([finding({ file_path: 'src\\db.ts' })]));
    expect(uriOf(doc)).toBe('src/db.ts');
  });
});

describe('toSarif — region pairing', () => {
  // Measured defect (task 4 brief, item 5): a `Finding` can carry `line_end`
  // without `line_start` (both are independently optional on the type) —
  // emitting a bare `endLine` produced a region the SARIF schema rejects
  // (`region` requires `startLine` before `endLine` is meaningful).
  it('never emits endLine without startLine', () => {
    const doc = JSON.parse(toSarif([finding({ line_start: undefined, line_end: 9 })]));
    const region = (doc.runs[0].results[0].locations[0].physicalLocation as {
      region?: { startLine?: number; endLine?: number };
    }).region;
    expect(region?.endLine).toBeUndefined();
    expect(region?.startLine).toBeUndefined();
  });

  it('emits both when startLine is present', () => {
    const doc = JSON.parse(toSarif([finding({ line_start: 5, line_end: 9 })]));
    const region = doc.runs[0].results[0].locations[0].physicalLocation.region;
    expect(region.startLine).toBe(5);
    expect(region.endLine).toBe(9);
  });

  it('emits startLine alone when there is no endLine', () => {
    const doc = JSON.parse(toSarif([finding({ line_start: 5, line_end: undefined })]));
    const region = doc.runs[0].results[0].locations[0].physicalLocation.region;
    expect(region.startLine).toBe(5);
    expect(region.endLine).toBeUndefined();
  });
});
