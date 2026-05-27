import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { phpcsParser } from '../../../../src/runners/scannerParsers/phpcs.js';

const here = dirname(fileURLToPath(import.meta.url));
const FIXTURE = resolve(here, '../../../fixtures/scanners/phpcs.json');

describe('phpcsParser', () => {
  it('emits one Finding per message across files', () => {
    const { findings } = phpcsParser.parse(readFileSync(FIXTURE, 'utf8'));
    expect(findings).toHaveLength(3);
  });

  it('routes WordPress.Security.* and WordPress.DB.* to category=security', () => {
    const { findings } = phpcsParser.parse(readFileSync(FIXTURE, 'utf8'));
    const secCount = findings.filter((f) => f.category === 'security').length;
    expect(secCount).toBe(2);
  });

  it('maps PHPCS severity 5 to high and 2 to low', () => {
    const { findings } = phpcsParser.parse(readFileSync(FIXTURE, 'utf8'));
    const high = findings.find((f) => /esc_html/.test(f.title));
    const low = findings.find((f) => /Line exceeds/.test(f.title));
    expect(high?.severity).toBe('high');
    expect(low?.severity).toBe('low');
  });

  it('uses the dotted prefix of `source` as subcategory', () => {
    const { findings } = phpcsParser.parse(readFileSync(FIXTURE, 'utf8'));
    const esc = findings.find((f) => /esc_html/.test(f.title));
    expect(esc?.subcategory).toBe('WordPress.Security.EscapeOutput');
  });

  it('preserves file_path and line numbers', () => {
    const { findings } = phpcsParser.parse(readFileSync(FIXTURE, 'utf8'));
    const esc = findings.find((f) => /esc_html/.test(f.title));
    expect(esc?.file_path).toBe('src/plugin.php');
    expect(esc?.line_start).toBe(42);
  });
});
