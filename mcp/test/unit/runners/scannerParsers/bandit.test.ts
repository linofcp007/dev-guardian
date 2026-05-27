import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { banditParser } from '../../../../src/runners/scannerParsers/bandit.js';

const here = dirname(fileURLToPath(import.meta.url));
const FIXTURE = resolve(here, '../../../fixtures/scanners/bandit.json');

describe('banditParser', () => {
  it('emits one Finding per result with category=security', () => {
    const { findings } = banditParser.parse(readFileSync(FIXTURE, 'utf8'));
    expect(findings).toHaveLength(2);
    expect(findings.every((f) => f.category === 'security')).toBe(true);
  });

  it('maps issue_severity HIGH→high, MEDIUM→medium', () => {
    const { findings } = banditParser.parse(readFileSync(FIXTURE, 'utf8'));
    const b605 = findings.find((f) => f.rule_id === 'B605');
    const b301 = findings.find((f) => f.rule_id === 'B301');
    expect(b605?.severity).toBe('high');
    expect(b301?.severity).toBe('medium');
  });

  it('includes confidence in the message', () => {
    const { findings } = banditParser.parse(readFileSync(FIXTURE, 'utf8'));
    const b605 = findings.find((f) => f.rule_id === 'B605');
    expect(b605?.message?.toLowerCase()).toContain('confidence: medium');
  });

  it('uses line_range when line_number is absent', () => {
    const json = JSON.stringify({
      results: [
        {
          test_id: 'B999',
          test_name: 'made_up',
          issue_severity: 'LOW',
          issue_text: 'made-up issue',
          filename: 'a.py',
          line_range: [10, 12],
        },
      ],
    });
    const { findings } = banditParser.parse(json);
    expect(findings[0]?.line_start).toBe(10);
    expect(findings[0]?.line_end).toBe(12);
  });
});
