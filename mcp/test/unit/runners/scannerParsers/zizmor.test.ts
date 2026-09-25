import { describe, expect, it } from 'vitest';
import { zizmorParser } from '../../../../src/runners/scannerParsers/zizmor.js';

/**
 * Real shape, trimmed from zizmorcore/zizmor's own `docs/usage.md` worked
 * example and `crates/zizmor/tests/integration/e2e/snapshots/
 * integration__e2e__json_v1__json_v1.snap` (the tool's own e2e fixture).
 * Locations use 0-based `row` per zizmor's documented `--format=json`
 * convention (unlike `plain`/SARIF, which are 1-based).
 */
function finding(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    ident: 'template-injection',
    desc: 'code injection via template expansion',
    url: 'https://docs.zizmor.sh/audits/#template-injection',
    determinations: { confidence: 'High', severity: 'High', persona: 'Regular' },
    locations: [
      {
        symbolic: {
          key: { Local: { verbatim_path: './.github/workflows/ci.yml' } },
          annotation: 'this step',
          route: { route: [{ Key: 'jobs' }] },
          feature_kind: 'Normal',
          kind: 'Hidden',
        },
        concrete: {
          location: {
            start_point: { row: 6, column: 8 },
            end_point: { row: 7, column: 0 },
            offset_span: { start: 86, end: 136 },
          },
          feature: 'run: echo "Hello ${{ github.event.issue.title }}"\n',
          comments: [],
        },
      },
      {
        symbolic: {
          key: { Local: { verbatim_path: './.github/workflows/ci.yml' } },
          annotation: 'may expand into attacker-controllable code',
          route: { route: [{ Key: 'jobs' }] },
          feature_kind: { Subfeature: { after: 13, fragment: { Raw: 'github.event.issue.title' } } },
          kind: 'Primary',
        },
        concrete: {
          location: {
            start_point: { row: 6, column: 29 },
            end_point: { row: 6, column: 53 },
            offset_span: { start: 107, end: 131 },
          },
          feature: 'echo "Hello ${{ github.event.issue.title }}"',
          comments: [],
        },
      },
    ],
    ignored: false,
    fixes: [],
    ...overrides,
  };
}

describe('zizmorParser', () => {
  it('produces one Finding per non-ignored entry', () => {
    const { findings } = zizmorParser.parse(JSON.stringify([finding()]));
    expect(findings).toHaveLength(1);
  });

  it('uses category=security, subcategory=ci, tool=zizmor', () => {
    const { findings } = zizmorParser.parse(JSON.stringify([finding()]));
    expect(findings[0]?.category).toBe('security');
    expect(findings[0]?.subcategory).toBe('ci');
    expect(findings[0]?.tool).toBe('zizmor');
  });

  it('maps ident to rule_id and desc to title', () => {
    const { findings } = zizmorParser.parse(JSON.stringify([finding()]));
    expect(findings[0]?.rule_id).toBe('template-injection');
    expect(findings[0]?.title).toBe('code injection via template expansion');
  });

  it('maps determinations.severity through the shared normalizer (High -> high)', () => {
    const { findings } = zizmorParser.parse(JSON.stringify([finding()]));
    expect(findings[0]?.severity).toBe('high');
  });

  it('maps Informational severity to info', () => {
    const f = finding({ determinations: { confidence: 'Low', severity: 'Informational', persona: 'Regular' } });
    const { findings } = zizmorParser.parse(JSON.stringify([f]));
    expect(findings[0]?.severity).toBe('info');
  });

  it('carries confidence and the doc url in the message, not just severity', () => {
    const { findings } = zizmorParser.parse(JSON.stringify([finding()]));
    expect(findings[0]?.message).toContain('confidence: High');
    expect(findings[0]?.message).toContain('https://docs.zizmor.sh/audits/#template-injection');
  });

  it('picks the Primary-tagged location over Hidden ones for file/line/snippet', () => {
    const { findings } = zizmorParser.parse(JSON.stringify([finding()]));
    // Primary location's start_point.row is 0-based 6 -> line 7.
    expect(findings[0]?.line_start).toBe(7);
    expect(findings[0]?.line_end).toBe(7);
    expect(findings[0]?.snippet).toBe('echo "Hello ${{ github.event.issue.title }}"');
  });

  it('strips the leading "./" from verbatim_path', () => {
    const { findings } = zizmorParser.parse(JSON.stringify([finding()]));
    expect(findings[0]?.file_path).toBe('.github/workflows/ci.yml');
  });

  it('falls back to the first location when none is tagged Primary', () => {
    const f = finding();
    const locations = f['locations'] as Array<{ symbolic: Record<string, unknown> }>;
    for (const loc of locations) loc.symbolic['kind'] = 'Hidden';
    const { findings } = zizmorParser.parse(JSON.stringify([f]));
    // First location's start_point.row is 0-based 6 -> line 7 too, but via a different location object.
    expect(findings[0]?.line_start).toBe(7);
  });

  it('drops a finding the workflow already annotated `# zizmor: ignore[...]` (ignored: true)', () => {
    const { findings } = zizmorParser.parse(JSON.stringify([finding({ ignored: true })]));
    expect(findings).toEqual([]);
  });

  it('skips an entry with no ident or no desc (malformed input), never throws', () => {
    expect(zizmorParser.parse(JSON.stringify([{ desc: 'x' }])).findings).toEqual([]);
    expect(zizmorParser.parse(JSON.stringify([{ ident: 'x' }])).findings).toEqual([]);
  });

  it('still produces a finding with no file_path/line when locations is empty', () => {
    const f = finding({ locations: [] });
    const { findings } = zizmorParser.parse(JSON.stringify([f]));
    expect(findings).toHaveLength(1);
    expect(findings[0]?.file_path).toBeUndefined();
    expect(findings[0]?.line_start).toBeUndefined();
  });

  it('returns no findings on empty array input', () => {
    expect(zizmorParser.parse('[]').findings).toEqual([]);
  });

  it('returns no findings on unparseable input rather than throwing', () => {
    expect(zizmorParser.parse('not json').findings).toEqual([]);
  });
});
