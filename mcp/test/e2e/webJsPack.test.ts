/**
 * Runs `configs/semgrep/web-js.yml` -- the plugin's Node/Express sink pack
 * (feature `js-sink-rules`) -- against `mcp/test/fixtures/web-js/`:
 *
 *   - `web-js-sql-template` (CWE-89): SQL text built by a template literal
 *     with an interpolation, or a concatenation with a value that is not a
 *     literal, as the statement of a Node SQL driver;
 *   - `web-js-path-traversal` (CWE-22): a value of `req.query|params|body`
 *     joined into a path that is read or sent in the same function;
 *   - `web-js-ssrf` (CWE-918): a value of the request as the URL of an
 *     outgoing request in the same function.
 *
 * The fixture tree:
 *
 *   hits/         one file per rule and sink shape. Every `// BUG: <rule-id>`
 *                 line fires that rule exactly once, and no rule fires
 *                 anywhere else -- the repo's marker convention (llm, rgpd,
 *                 bugfix-php), with the rule named because this pack has three.
 *   misses/       the safe shape of every exclusion criterion; nothing fires.
 *   spike-app-s/  four files of the llm-scan spike's synthetic app, copied
 *                 byte for byte so the answer key's line numbers hold. The
 *                 answer key itself is NOT copied -- it stays out of every
 *                 scanned tree -- and the lines it gives are recorded below.
 *
 * Test ids are the feature's test plan. T-08 (`--validate` and the banned
 * characters) is `integration/semgrepPacks.test.ts`, which discovers packs
 * from disk; T-09 is the ablation registry (`test/ablate/packs.ts`); T-10 is
 * `unit/tools/scanSastPlan.test.ts`.
 *
 * Every test asserts the pack exists FIRST, so while it does not the file
 * fails by that assertion -- never by Semgrep refusing a missing config.
 *
 * Fixtures are copied to a temp dir before scanning: their in-repo path holds
 * a `test/` segment, which Semgrep's default ignore list skips wholesale --
 * and the scanned count is asserted every time, so "nothing fired" can never
 * mean "nothing was read".
 *
 * SKIPPED, not silently passed, when Semgrep is absent;
 * `GUARDIAN_REQUIRE_SEMGREP=1` turns that absence into a hard failure.
 */

import { afterAll, describe, expect, it, vi } from 'vitest';

// Real, synchronous `semgrep` calls are not bounded by vitest's default
// testTimeout (see integration/baseRules.test.ts).
vi.setConfig({ testTimeout: 180_000 });
import { cpSync, existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { basename, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { semgrepAvailable, semgrepStdout } from '../helpers/semgrep.js';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';

afterAll(cleanupTempDirs);

const REPO_ROOT = resolve(fileURLToPath(new URL('../../..', import.meta.url)));
const PACK_DIR = resolve(REPO_ROOT, 'configs', 'semgrep');
const PACK = resolve(PACK_DIR, 'web-js.yml');
const FIXTURES = resolve(REPO_ROOT, 'mcp', 'test', 'fixtures', 'web-js');
const HITS = resolve(FIXTURES, 'hits');
const MISSES = resolve(FIXTURES, 'misses');
const SPIKE = resolve(FIXTURES, 'spike-app-s');
const REQUIRE_SEMGREP = process.env['GUARDIAN_REQUIRE_SEMGREP'] === '1';

const AVAILABLE = semgrepAvailable();

const SQL_RULE = 'web-js-sql-template';
const PATH_RULE = 'web-js-path-traversal';
const SSRF_RULE = 'web-js-ssrf';
const RULE_IDS: readonly string[] = [SQL_RULE, PATH_RULE, SSRF_RULE];

/** The CWE each rule declares in `metadata.cwe` (a list of `CWE-n: Name`, as in base.yml). */
const CWE: Readonly<Record<string, string>> = {
  [SQL_RULE]: 'CWE-89',
  [PATH_RULE]: 'CWE-22',
  [SSRF_RULE]: 'CWE-918',
};

/**
 * The spike's answer key (`answer-key-app-s.tsv`), for the four files copied
 * into `spike-app-s/`. Paths are relative to the app root.
 *
 * S04: the SQL text is built at 63-64 and prepared at 66; the key -- and
 * US-1.AC-3 -- put the finding on the template, so 63 or 64 (where the
 * template starts, or where its interpolations are) and not 66.
 *
 * S06: the key -- and US-2.AC-3 -- name line 79, the `path.join` of the
 * query parameter; the `res.download` it reaches is line 81. The design of
 * record makes this rule intra-procedural TAINT, and a taint finding is
 * reported at its sink, so either line is accepted as "the finding for S06".
 */
const S04 = { file: 'src/repositories/shifts.ts', lines: [63, 64] } as const;
const S06 = { file: 'src/routes/attachments.ts', lines: [79, 81] } as const;
const DECOYS = [
  // ORDER BY from a constant map and a ternary of literals, plus a WHERE of
  // literal fragments joined -- interpolated, and safe.
  { id: 'D01', file: 'src/repositories/shifts.ts', from: 55, to: 58 },
  // execFile with a fixed argv and a server-generated path (and, next line, a
  // read of that path).
  { id: 'D02', file: 'src/services/exporter.ts', from: 54, to: 54 },
  // A redirect of a query parameter after an exact allowlist match.
  { id: 'D03', file: 'src/routes/auth.ts', from: 58, to: 59 },
] as const;

interface Row {
  readonly rule: string;
  /** Relative to the scanned root, `/`-separated. */
  readonly file: string;
  readonly line: number;
  readonly endLine: number;
  readonly cwe: readonly string[];
}

interface Scan {
  readonly rows: readonly Row[];
  readonly scanned: number;
  readonly errors: readonly unknown[];
}

interface RawResult {
  readonly check_id?: unknown;
  readonly path?: unknown;
  readonly start?: { readonly line?: unknown };
  readonly end?: { readonly line?: unknown };
  readonly extra?: { readonly metadata?: { readonly cwe?: unknown } };
}

function expectPack(): void {
  expect(existsSync(PACK), 'configs/semgrep/web-js.yml exists').toBe(true);
}

/**
 * The part of a reported path below the scanned root. The root is a fresh
 * temp dir with a unique name, so the path is cut at that name rather than
 * compared with the root's spelling (8.3 aliases, drive-letter case).
 */
function relativeTo(root: string, reported: string): string {
  const posix = reported.replace(/\\/g, '/');
  const marker = `/${basename(root)}/`;
  const at = posix.indexOf(marker);
  return at === -1 ? posix : posix.slice(at + marker.length);
}

function semgrepArgs(target: string, configs: readonly string[]): string[] {
  return [...configs.map((c) => `--config=${c}`), '--json', '--quiet', '--no-git-ignore', '--metrics=off', target];
}

function parseScan(stdout: string, root: string): Scan {
  const report = JSON.parse(stdout) as { results?: RawResult[]; errors?: unknown[]; paths?: { scanned?: unknown[] } };
  const rows = (report.results ?? []).map((r): Row => {
    const id = String(r.check_id ?? '');
    const cwe = r.extra?.metadata?.cwe;
    return {
      // Semgrep prefixes the config's path onto the id; the rule is the last segment.
      rule: id.split('.').pop() ?? id,
      file: relativeTo(root, String(r.path ?? '')),
      line: Number(r.start?.line),
      endLine: Number(r.end?.line),
      cwe: Array.isArray(cwe) ? cwe.map(String) : [],
    };
  });
  return { rows, scanned: (report.paths?.scanned ?? []).length, errors: report.errors ?? [] };
}

/** One scan per fixture directory per file run: every assertion reads the same result. */
const scans = new Map<string, Scan>();
function scanOf(dir: string): Scan {
  const cached = scans.get(dir);
  if (cached !== undefined) return cached;
  const work = makeTempDir('guardian-webjs-');
  cpSync(dir, work, { recursive: true });
  const result = parseScan(semgrepStdout(semgrepArgs(work, [PACK]), { cwd: work }), work);
  scans.set(dir, result);
  return result;
}

function countFiles(dir: string): number {
  return readdirSync(dir).reduce((n, entry) => {
    const child = join(dir, entry);
    return n + (statSync(child).isDirectory() ? countFiles(child) : 1);
  }, 0);
}

/** No rule failed to load and every file was read -- or "nothing fired" means nothing. */
function expectCompleteScan(scan: Scan, dir: string): void {
  expect(scan.errors).toEqual([]);
  expect(scan.scanned).toBe(countFiles(dir));
}

/** `file:line` of every finding of `rule`, sorted (duplicates kept: one finding per marked line). */
function linesOf(scan: Scan, rule: string): string[] {
  return scan.rows
    .filter((r) => r.rule === rule)
    .map((r) => `${r.file}:${String(r.line)}`)
    .sort();
}

const MARKER = /\/\/ BUG: ([a-z0-9-]+)/;

/** Every `// BUG: <rule-id>` marker in hits/, as `file:line` per rule id. */
function markers(): Map<string, string[]> {
  const byRule = new Map<string, string[]>();
  for (const file of readdirSync(HITS).sort()) {
    readFileSync(join(HITS, file), 'utf8')
      .split('\n')
      .forEach((text, i) => {
        const rule = MARKER.exec(text)?.[1];
        if (rule === undefined) return;
        const list = byRule.get(rule) ?? [];
        list.push(`${file}:${String(i + 1)}`);
        byRule.set(rule, list);
      });
  }
  return byRule;
}

/** The marked lines of one rule -- asserted non-empty, and no marker names an unknown rule. */
function expectedLines(rule: string): string[] {
  const all = markers();
  expect([...all.keys()].filter((id) => !RULE_IDS.includes(id)), 'markers naming an unknown rule').toEqual([]);
  const lines = [...(all.get(rule) ?? [])].sort();
  expect(lines.length, `hits/ carries markers for ${rule}`).toBeGreaterThan(0);
  return lines;
}

/** Every finding of `rule` carries the rule's CWE in `metadata.cwe`. */
function expectCwe(scan: Scan, rule: string): void {
  const cwe = CWE[rule] ?? '';
  const without = scan.rows
    .filter((r) => r.rule === rule && !r.cwe.some((c) => c === cwe || c.startsWith(`${cwe}:`)))
    .map((r) => `${r.file}:${String(r.line)} cwe=${JSON.stringify(r.cwe)}`);
  expect(without, `every ${rule} finding declares ${cwe}`).toEqual([]);
}

/** Any finding of the pack, of any rule, that touches one of the spike app's decoys. */
function decoyFindings(scan: Scan): string[] {
  return scan.rows
    .filter((r) => DECOYS.some((d) => r.file === d.file && r.line <= d.to && r.endLine >= d.from))
    .map((r) => `${r.file}:${String(r.line)}-${String(r.endLine)} ${r.rule}`);
}

function isAt(spot: { readonly file: string; readonly lines: readonly number[] }): (key: string) => boolean {
  return (key) => spot.lines.some((line) => key === `${spot.file}:${String(line)}`);
}

describe('web-js pack (js-sink-rules)', () => {
  it.runIf(REQUIRE_SEMGREP)('the toolchain must be usable when the flag is set', () => {
    expect(AVAILABLE).toBe(true);
  });

  // ------------------------------------------------------------ US-1: SQL

  it.skipIf(!AVAILABLE)('T-01 web-js-sql-template fires CWE-89 on exactly the marked line of every SQL hit (US-1.AC-1)', () => {
    expectPack();
    const expected = expectedLines(SQL_RULE);
    const run = scanOf(HITS);
    expectCompleteScan(run, HITS);
    expect(linesOf(run, SQL_RULE)).toEqual(expected);
    expectCwe(run, SQL_RULE);
  });

  it.skipIf(!AVAILABLE)('T-02 web-js-sql-template fires nothing on the safe SQL shapes in misses/ (US-1.AC-2, EC-1, EC-2)', () => {
    expectPack();
    const run = scanOf(MISSES);
    expectCompleteScan(run, MISSES);
    expect(linesOf(run, SQL_RULE)).toEqual([]);
  });

  it.skipIf(!AVAILABLE)('T-03 spike app: S04 is flagged on its template, and no decoy is (US-1.AC-3, SC-001)', () => {
    expectPack();
    const run = scanOf(SPIKE);
    expectCompleteScan(run, SPIKE);
    const sql = linesOf(run, SQL_RULE);
    expect(sql.filter(isAt(S04)).length, `S04 (${S04.file}:63-64) among the SQL findings ${JSON.stringify(sql)}`).toBeGreaterThan(0);
    // The only SQL finding in these four files is S04: the multi-line
    // templates with no interpolation (EC-1) at shifts.ts:72, 92, 118 and
    // exporter.ts:44 stay silent too.
    expect(sql.filter((key) => !isAt(S04)(key))).toEqual([]);
    expect(decoyFindings(run)).toEqual([]);
  });

  // ------------------------------------------------ US-2: path traversal

  it.skipIf(!AVAILABLE)('T-04 web-js-path-traversal fires CWE-22 on exactly the marked line of every path hit (US-2.AC-1)', () => {
    expectPack();
    const expected = expectedLines(PATH_RULE);
    const run = scanOf(HITS);
    expectCompleteScan(run, HITS);
    expect(linesOf(run, PATH_RULE)).toEqual(expected);
    expectCwe(run, PATH_RULE);
  });

  it.skipIf(!AVAILABLE)('T-05 web-js-path-traversal fires nothing after basename, a startsWith check on path.resolve, or on literals (US-2.AC-2, EC-3)', () => {
    expectPack();
    const run = scanOf(MISSES);
    expectCompleteScan(run, MISSES);
    expect(linesOf(run, PATH_RULE)).toEqual([]);
  });

  it.skipIf(!AVAILABLE)('T-06 spike app: S06 is flagged, and nothing else by the path rule (US-2.AC-3, SC-001)', () => {
    expectPack();
    const run = scanOf(SPIKE);
    expectCompleteScan(run, SPIKE);
    const paths = linesOf(run, PATH_RULE);
    expect(paths.filter(isAt(S06)).length, `S06 (${S06.file}:79, or the download at 81) among ${JSON.stringify(paths)}`).toBeGreaterThan(0);
    // Not the upload WRITE at attachments.ts:56, nor D02's read of a
    // server-generated path at exporter.ts:55.
    expect(paths.filter((key) => !isAt(S06)(key))).toEqual([]);
  });

  // ------------------------------------------------------------ US-3: SSRF

  it.skipIf(!AVAILABLE)('T-07 web-js-ssrf fires CWE-918 on exactly the marked line of every SSRF hit, and nothing on an allowlisted, constant or stored URL (US-3.AC-1, US-3.AC-2, EC-4)', () => {
    expectPack();
    const expected = expectedLines(SSRF_RULE);
    const hits = scanOf(HITS);
    expectCompleteScan(hits, HITS);
    expect(linesOf(hits, SSRF_RULE)).toEqual(expected);
    expectCwe(hits, SSRF_RULE);
    const misses = scanOf(MISSES);
    expectCompleteScan(misses, MISSES);
    expect(linesOf(misses, SSRF_RULE)).toEqual([]);
  });

  // EC-4 is a non-finding the pack must SAY it does not cover. No Semgrep
  // needed, so this one is red even where Semgrep is absent.
  it('T-07 the pack documents stored SSRF as a known gap (EC-4)', () => {
    expectPack();
    expect(readFileSync(PACK, 'utf8')).toMatch(/SSRF armazenado/i);
  });
});
