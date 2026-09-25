import { describe, expect, it } from 'vitest';
import { hadolintParser } from '../../../../src/runners/scannerParsers/hadolint.js';

const SAMPLE = JSON.stringify([
  { file: 'Dockerfile', line: 1, column: 1, level: 'warning', code: 'DL3006', message: 'Always tag the version of an image explicitly' },
  { file: 'Dockerfile', line: 5, column: 1, level: 'error', code: 'DL3002', message: 'Last USER should not be root' },
  { file: 'Dockerfile', line: 8, column: 1, level: 'style', code: 'DL3059', message: 'Multiple consecutive RUN instructions' },
  { file: 'Dockerfile', line: 2, column: 1, level: 'info', code: 'DL3059', message: 'Multiple consecutive RUN instructions' },
]);

describe('hadolintParser', () => {
  it('produces one Finding per entry', () => {
    const { findings } = hadolintParser.parse(SAMPLE);
    expect(findings).toHaveLength(4);
  });

  it('maps level to severity: error->high, warning->medium, info->info, style->medium (default)', () => {
    const { findings } = hadolintParser.parse(SAMPLE);
    const byCode = (code: string, line: number) => findings.find((f) => f.rule_id === code && f.line_start === line);
    expect(byCode('DL3006', 1)?.severity).toBe('medium');
    expect(byCode('DL3002', 5)?.severity).toBe('high');
    expect(byCode('DL3059', 8)?.severity).toBe('medium');
    expect(byCode('DL3059', 2)?.severity).toBe('info');
  });

  it('uses category=security, subcategory=dockerfile-lint, tool=hadolint', () => {
    const { findings } = hadolintParser.parse(SAMPLE);
    expect(findings.every((f) => f.category === 'security')).toBe(true);
    expect(findings.every((f) => f.subcategory === 'dockerfile-lint')).toBe(true);
    expect(findings.every((f) => f.tool === 'hadolint')).toBe(true);
  });

  it('carries the file and line', () => {
    const { findings } = hadolintParser.parse(SAMPLE);
    const first = findings[0];
    expect(first?.file_path).toBe('Dockerfile');
    expect(first?.line_start).toBe(1);
    expect(first?.line_end).toBe(1);
  });

  it('title falls back to the rule code when no message is present', () => {
    const { findings } = hadolintParser.parse(JSON.stringify([{ file: 'Dockerfile', line: 1, level: 'error', code: 'DL1000' }]));
    expect(findings[0]?.title).toBe('DL1000');
  });

  it('skips an entry with no code (malformed input), never throws', () => {
    const { findings } = hadolintParser.parse(JSON.stringify([{ file: 'Dockerfile', line: 1, level: 'error' }]));
    expect(findings).toEqual([]);
  });

  it('returns no findings on empty array input', () => {
    expect(hadolintParser.parse('[]').findings).toEqual([]);
  });

  it('returns no findings on unparseable input rather than throwing', () => {
    expect(hadolintParser.parse('not json').findings).toEqual([]);
  });
});
