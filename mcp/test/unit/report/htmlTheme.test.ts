/**
 * Unit tests for the branded HTML shell + Markdown subset converter.
 * Pure string logic — no filesystem, no DB.
 */

import { describe, expect, it } from 'vitest';

import {
  markdownToSafeHtml,
  renderHtmlDocument,
  SEVERITY_COLORS,
  severityBar,
  severityChip,
} from '../../../src/report/htmlTheme.js';

describe('renderHtmlDocument', () => {
  const doc = renderHtmlDocument({ title: 'T', subtitle: 'S', sections: ['<p>hello</p>'] });

  it('embeds both dark and light brand tokens', () => {
    expect(doc).toContain('#040405'); // dark bg-primary
    expect(doc).toContain('#F8F9FA'); // light bg-primary
    expect(doc).toContain('#11689B'); // brand blue
    expect(doc).toContain('#00AAFF'); // electric accent
  });

  it('supports a system default with explicit theme override', () => {
    expect(doc).toContain('prefers-color-scheme: light');
    expect(doc).toContain(':root:not([data-theme="dark"])');
    expect(doc).toContain('[data-theme="light"]');
    expect(doc).toContain('[data-theme="dark"]');
  });

  it('ships a persistent toggle', () => {
    expect(doc).toContain('id="pdk-theme-toggle"');
    expect(doc).toContain('pdk-report-theme');
    expect(doc).toContain('localStorage');
  });

  it('is fully offline — no external assets', () => {
    expect(doc).not.toContain('https://');
    expect(doc).not.toContain('http://');
    expect(doc).not.toContain('<link');
    expect(doc.toLowerCase()).not.toContain('@import');
    expect(doc).not.toContain('fonts.googleapis');
    expect(doc).not.toContain('<script src');
  });

  it('renders title, subtitle and sections, escaping the title', () => {
    expect(doc).toContain('<h1 class="pdk-title">T</h1>');
    expect(doc).toContain('S');
    expect(doc).toContain('<p>hello</p>');
    expect(renderHtmlDocument({ title: '<x>&"', sections: [] })).toContain('&lt;x&gt;&amp;&quot;');
  });

  it('applies the saved theme in <head> before paint (no FOUC)', () => {
    expect(doc.indexOf("getItem('pdk-report-theme')")).toBeGreaterThan(-1);
    expect(doc.indexOf("getItem('pdk-report-theme')")).toBeLessThan(doc.indexOf('<style>'));
  });

  it('ships print styles that force a light, toggle-free layout', () => {
    expect(doc).toContain('@media print');
    expect(doc).toContain('.pdk-toggle { display: none');
  });

  it('localises the footer and <html lang>', () => {
    const pt = renderHtmlDocument({ title: 'X', sections: [], lang: 'pt' });
    expect(pt).toContain('<html lang="pt">');
    expect(pt).toContain('sem telemetria');
    expect(renderHtmlDocument({ title: 'X', sections: [], lang: 'es' })).toContain('sin telemetría');
    expect(doc).toContain('<html lang="en">');
    expect(doc).toContain('no telemetry');
  });
});

describe('markdownToSafeHtml', () => {
  it('renders headings, bold, italic and code', () => {
    const h = markdownToSafeHtml('# Title\n\nSome **bold**, *em* and `code` here.');
    expect(h).toContain('<h1>Title</h1>');
    expect(h).toContain('<strong>bold</strong>');
    expect(h).toContain('<em>em</em>');
    expect(h).toContain('<code>code</code>');
  });

  it('preserves spaces and numbers (code-token regression)', () => {
    expect(markdownToSafeHtml('We cut work in 5 days by 30 percent.')).toContain(
      'We cut work in 5 days by 30 percent.',
    );
  });

  it('renders unordered and ordered lists', () => {
    expect(markdownToSafeHtml('- a\n- b')).toContain('<ul><li>a</li><li>b</li></ul>');
    expect(markdownToSafeHtml('1. a\n2. b')).toContain('<ol><li>a</li><li>b</li></ol>');
  });

  it('renders GFM tables', () => {
    const h = markdownToSafeHtml('| A | B |\n| --- | --- |\n| 1 | 2 |');
    expect(h).toContain('<table>');
    expect(h).toContain('<th>A</th>');
    expect(h).toContain('<td>1</td>');
  });

  it('renders safe links and drops javascript: URLs', () => {
    expect(markdownToSafeHtml('[site](https://x.com)')).toContain('<a href="https://x.com">site</a>');
    const js = markdownToSafeHtml('[x](javascript:alert(1))');
    expect(js).not.toContain('javascript:');
    expect(js).toContain('x');
  });

  it('escapes raw HTML — no injection', () => {
    const h = markdownToSafeHtml('hello <script>alert(1)</script> world');
    expect(h).not.toContain('<script>alert(1)</script>');
    expect(h).toContain('&lt;script&gt;');
  });

  it('renders blockquotes and horizontal rules', () => {
    expect(markdownToSafeHtml('> quote')).toContain('<blockquote>quote</blockquote>');
    expect(markdownToSafeHtml('---')).toContain('<hr>');
  });
});

describe('severity rendering', () => {
  it('chip uses the severity colour and label', () => {
    const chip = severityChip('critical');
    expect(chip).toContain(SEVERITY_COLORS.critical.bg);
    expect(chip).toContain('critical');
  });

  it('bar sizes by counts and skips zeros', () => {
    const bar = severityBar({ critical: 2, high: 0, medium: 1, low: 0, info: 0 });
    expect(bar).toContain('critical: 2');
    expect(bar).toContain('medium: 1');
    expect(bar).not.toContain('high:');
  });
});
