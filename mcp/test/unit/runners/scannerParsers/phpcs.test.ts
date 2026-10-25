import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { phpcsParser, phpcsUnprocessed } from '../../../../src/runners/scannerParsers/phpcs.js';

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

/**
 * 3.6.1. Real output of PHP_CodeSniffer 3.13.5 with WPCS 3.3.0
 * (`--standard=WordPress --report=json`, PHP 8.4.4 with `short_open_tag=0`,
 * 2026-10-25; the vendor path in the exception's message shortened):
 * `nocode.php` (only HTML) got `Internal.NoCodeFound` and nothing else was
 * checked; `broken5.php` got `Internal.Exception` — a sniff threw and
 * "checking has been aborted"; `ok.php` is the control. Those became
 * ordinary findings (the exception a high one) and phpcs-wpcs stayed ok.
 */
describe('phpcs: files PHPCS did not process', () => {
  const INTERNAL = resolve(here, '../../../fixtures/scanners/phpcs/internal-messages.json');

  it('names each file, once, with the code and PHPCS’s message', () => {
    const partial = phpcsUnprocessed(readFileSync(INTERNAL, 'utf8'));
    expect(partial.map((p) => [p.file, p.type])).toEqual([
      ['nocode.php', 'Not analysed'],
      ['broken5.php', 'Not analysed'],
    ]);
    expect(partial[0]?.message).toMatch(/^Internal\.NoCodeFound: No PHP code was found/);
    expect(partial[1]?.message).toMatch(/^Internal\.Exception: An error occurred during processing; checking has been aborted/);
  });

  it('none of them is a finding; the rest of the report still is', () => {
    const { findings } = phpcsParser.parse(readFileSync(INTERNAL, 'utf8'));
    expect(findings.filter((f) => f.rule_id?.startsWith('Internal.') === true)).toEqual([]);
    expect(findings.some((f) => f.file_path === 'ok.php' && f.category === 'security')).toBe(true);
  });

  it('Internal.Tokenizer.Exception too (hand-made: PHPCS 3 raises it from its JS and CSS tokenizers)', () => {
    const report = JSON.stringify({
      files: {
        '/p/assets/app.min.js': {
          messages: [
            { message: 'File appears to be minified and cannot be processed', source: 'Internal.Tokenizer.Exception', severity: 5, fixable: false, type: 'WARNING', line: 1, column: 1 },
          ],
        },
      },
    });
    expect(phpcsUnprocessed(report, '/p')).toEqual([
      { file: 'assets/app.min.js', type: 'Not analysed', message: 'Internal.Tokenizer.Exception: File appears to be minified and cannot be processed' },
    ]);
    expect(phpcsParser.parse(report).findings).toEqual([]);
  });

  it('fix_available is PHPCS’s boolean `fixable`', () => {
    const { findings } = phpcsParser.parse(readFileSync(INTERNAL, 'utf8'));
    const fixable = findings.filter((f) => f.fix_available);
    expect(fixable.length).toBeGreaterThan(0);
    expect(fixable.length).toBeLessThan(findings.length);
  });
});
