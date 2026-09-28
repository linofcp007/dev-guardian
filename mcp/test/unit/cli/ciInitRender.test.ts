/**
 * Unit test for `renderCiTemplate`, exported from `cli/dev-guardian.mjs`
 * (Task 21 coordinator review, altitude pass): the leftover-placeholder
 * safety net used a generic `\{\{[^}]*\}\}` pattern, which also matches the
 * INNER text of GitHub Actions' own live expression syntax —
 * `${{ github.event_name }}` contains `{{ github.event_name }}`, shaped
 * exactly like an unresolved placeholder even though the leading `$` makes
 * it something `renderCiTemplate` never touches. A template that legitimately
 * needed a real `${{ }}` expression would have thrown
 * "unresolved placeholder" on perfectly correct output. Fixed by making the
 * leftover check reuse the exact same token shape as the substitution regex
 * (`[A-Z0-9_]+`, no spaces or dots) instead of a wider one.
 *
 * See `browserOpener.test.ts` for why this is a plain relative dynamic
 * import rather than a subprocess: `renderCiTemplate` is pure, no I/O, and
 * the entry-point guard at the bottom of `cli/dev-guardian.mjs` keeps this
 * import from also running `main()` against this test runner's own argv.
 */

import { describe, expect, it } from 'vitest';

// mcp/test/unit/cli -> ../../../.. -> repo root -> cli/dev-guardian.mjs
const { renderCiTemplate } = await import('../../../../cli/dev-guardian.mjs');

describe('renderCiTemplate', () => {
  it('substitutes every {{KEY}} token from vars', () => {
    const out = renderCiTemplate('hello {{NAME}}, tag {{TAG}}', { NAME: 'world', TAG: 'v1.2.3' });
    expect(out).toBe('hello world, tag v1.2.3');
  });

  it('does NOT choke on a real GitHub Actions `${{ }}` expression', () => {
    const text = 'run: echo "${{ github.event_name }}" && echo {{NAME}}';
    const out = renderCiTemplate(text, { NAME: 'ok' });
    expect(out).toBe('run: echo "${{ github.event_name }}" && echo ok');
  });

  it('a template with ONLY a live expression (no placeholders at all) renders unchanged', () => {
    const text = 'uses: actions/checkout@${{ github.sha }}';
    expect(renderCiTemplate(text, {})).toBe(text);
  });

  it('still throws on a genuinely unresolved {{KEY}} the template referenced', () => {
    expect(() => renderCiTemplate('{{MISSING}}', {})).toThrow(/unknown placeholder \{\{MISSING\}\}/);
  });

  it('throws if, after substitution, something still looks like an unresolved placeholder', () => {
    // vars itself supplies a value that LOOKS like an unresolved token —
    // this must still be caught, not accidentally treated as "already fine"
    // because it came from a real substitution.
    expect(() => renderCiTemplate('{{A}}', { A: '{{B}}' })).toThrow(/unresolved placeholder/);
  });

  it('a bare `${{ github.event_name }}` alone is never mistaken for an unresolved placeholder', () => {
    expect(() => renderCiTemplate('${{ github.event_name }}', {})).not.toThrow();
  });
});

// `ci-init --attest`: one template, two renderings. A `# {{#NAME}}` …
// `# {{/NAME}}` block is kept only when the caller turns NAME on, a
// `# {{^NAME}}` … `# {{/NAME}}` block only when it is off; the marker lines
// themselves never reach the output, and anything malformed throws rather
// than leak a half-rendered pipeline.
describe('renderCiTemplate: sections', () => {
  const text = [
    'jobs:',
    '  # {{#ATTEST}}',
    '  attest: {{NAME}}',
    '  # {{/ATTEST}}',
    '        # {{^ATTEST}}',
    '  human: true',
    '        # {{/ATTEST}}',
    'end',
  ].join('\n');

  it('keeps a {{#X}} block and drops a {{^X}} block when X is on — marker lines removed', () => {
    expect(renderCiTemplate(text, { NAME: 'ok' }, { ATTEST: true })).toBe('jobs:\n  attest: ok\nend');
  });

  it('the reverse when X is off', () => {
    expect(renderCiTemplate(text, { NAME: 'ok' }, { ATTEST: false })).toBe('jobs:\n  human: true\nend');
  });

  it('a dropped block may reference placeholders the caller does not supply', () => {
    expect(renderCiTemplate('# {{#ATTEST}}\n{{ONLY_WITH_ATTEST}}\n# {{/ATTEST}}\nx', {}, { ATTEST: false })).toBe('x');
  });

  it('throws on a section the caller did not declare — never silently kept or dropped', () => {
    expect(() => renderCiTemplate('# {{#OTHER}}\nx\n# {{/OTHER}}', {}, { ATTEST: true })).toThrow(/unknown section OTHER/);
    expect(() => renderCiTemplate('# {{#ATTEST}}\nx\n# {{/ATTEST}}', {})).toThrow(/unknown section ATTEST/);
  });

  it('throws on an unclosed, a mismatched or a nested section', () => {
    expect(() => renderCiTemplate('# {{#ATTEST}}\nx', {}, { ATTEST: true })).toThrow(/unclosed section ATTEST/);
    expect(() => renderCiTemplate('x\n# {{/ATTEST}}', {}, { ATTEST: true })).toThrow(/without an opening/);
    expect(() =>
      renderCiTemplate('# {{#ATTEST}}\n# {{#B}}\nx\n# {{/B}}\n# {{/ATTEST}}', {}, { ATTEST: true, B: true }),
    ).toThrow(/nested section B/);
  });

  it('throws on a marker that is not on a line of its own', () => {
    expect(() => renderCiTemplate('run: x # {{#ATTEST}}', {}, { ATTEST: true })).toThrow(/section marker/);
  });

  // Review M7: a near-miss used to pass as a plain YAML comment, so its
  // block was kept whatever the flag said.
  it.each(['# {{#attest}}', '# {{ #ATTEST }}', '#{{#ATTEST}}', '  # {{/ ATTEST}}', '# {{^Attest}}', '# {{#ATTEST-2}}'])(
    'a malformed marker %j throws — it is never read as a plain comment',
    (marker) => {
      const text = ['a', marker, 'b'].join('\n');
      expect(() => renderCiTemplate(text, {}, { ATTEST: false })).toThrow(/malformed section marker/);
    },
  );

  it('a GitHub expression is not a marker: `${{ !cancelled() }}` and `${{ github.ref }}` render untouched', () => {
    const text = "if: ${{ !cancelled() && github.event_name == 'push' }}\nx: ${{ github.ref }}";
    expect(renderCiTemplate(text, {}, { ATTEST: true })).toBe(text);
  });
});
