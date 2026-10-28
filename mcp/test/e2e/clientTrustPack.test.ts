/**
 * Runs `configs/semgrep/client-trust.yml` — the plugin's client-trust pack —
 * against `mcp/test/fixtures/client-trust/`:
 *
 *   - `client-public-env-secret` (CWE-798): a browser-exposed env variable
 *     (`NEXT_PUBLIC_`, `VITE_`, `EXPO_PUBLIC_`, `REACT_APP_`, `NUXT_PUBLIC_`,
 *     `GATSBY_`, `VUE_APP_`, SvelteKit's `PUBLIC_`) whose name says secret;
 *   - `client-supabase-service-role` (CWE-284): the service-role key handed to
 *     `createClient` in a `'use client'` file, or to `createBrowserClient`;
 *   - `client-webhook-unverified` (CWE-345): a handler that decides on a
 *     payment event type with no signature verification in sight;
 *   - `client-webhook-parsed-body` (CWE-347): `constructEvent` fed a parsed
 *     body.
 *
 *   hits/    every `// BUG: <rule-id>` line fires that rule exactly once (the
 *            line a finding STARTS on: a webhook finding covers its handler),
 *            and no rule fires anywhere else;
 *   misses/  the safe shape of every exclusion — public-by-design keys,
 *            server-only modules, verified webhooks (constructEvent, an HMAC,
 *            a verify helper, Paddle's unmarshal), non-payment events, a raw
 *            body. Nothing fires.
 *
 * Fixtures are copied to a temp dir before scanning (their in-repo path holds
 * `test/`, which Semgrep's default ignore list skips), and the scanned count
 * is asserted, so "nothing fired" never means "nothing was read". SKIPPED,
 * not passed, when Semgrep is absent; `GUARDIAN_REQUIRE_SEMGREP=1` makes that
 * a failure. The severity, category and CWE checks read the pack itself and
 * run without Semgrep.
 */

import { afterAll, describe, expect, it, vi } from 'vitest';

vi.setConfig({ testTimeout: 180_000 });
import { cpSync, existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { basename, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parse as parseYaml } from 'yaml';
import { PLUGIN_PACK_FILES } from '../../src/runners/semgrepConfigs.js';
import { semgrepParser } from '../../src/runners/scannerParsers/semgrep.js';
import { semgrepAvailable, semgrepStdout } from '../helpers/semgrep.js';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';

afterAll(cleanupTempDirs);

const REPO_ROOT = resolve(fileURLToPath(new URL('../../..', import.meta.url)));
const PACK = resolve(REPO_ROOT, 'configs', 'semgrep', 'client-trust.yml');
const FIXTURES = resolve(REPO_ROOT, 'mcp', 'test', 'fixtures', 'client-trust');
const HITS = resolve(FIXTURES, 'hits');
const MISSES = resolve(FIXTURES, 'misses');
const REQUIRE_SEMGREP = process.env['GUARDIAN_REQUIRE_SEMGREP'] === '1';
const AVAILABLE = semgrepAvailable();

/** Each rule, the CWE it declares and the severity it has on the repo's scheme (after the Semgrep parser). */
const RULES: Readonly<Record<string, { cwe: string; severity: string }>> = {
  'client-public-env-secret': { cwe: 'CWE-798', severity: 'critical' },
  'client-supabase-service-role': { cwe: 'CWE-284', severity: 'critical' },
  'client-webhook-unverified': { cwe: 'CWE-345', severity: 'critical' },
  'client-webhook-parsed-body': { cwe: 'CWE-347', severity: 'medium' },
};
const RULE_IDS = Object.keys(RULES);

interface Row {
  rule: string;
  file: string;
  line: number;
}

function expectPack(): void {
  expect(existsSync(PACK), 'configs/semgrep/client-trust.yml exists').toBe(true);
}

function relativeTo(root: string, reported: string): string {
  const posix = reported.replace(/\\/g, '/');
  const marker = `/${basename(root)}/`;
  const at = posix.indexOf(marker);
  return at === -1 ? posix : posix.slice(at + marker.length);
}

function countFiles(dir: string): number {
  return readdirSync(dir).reduce((n, e) => n + (statSync(join(dir, e)).isDirectory() ? countFiles(join(dir, e)) : 1), 0);
}

interface Scan {
  rows: Row[];
  scanned: number;
  errors: unknown[];
  raw: unknown;
}

const scans = new Map<string, Scan>();
function scanOf(dir: string): Scan {
  const cached = scans.get(dir);
  if (cached !== undefined) return cached;
  const work = makeTempDir('guardian-client-trust-');
  cpSync(dir, work, { recursive: true });
  const stdout = semgrepStdout([`--config=${PACK}`, '--json', '--quiet', '--no-git-ignore', '--metrics=off', work], { cwd: work });
  const report = JSON.parse(stdout) as {
    results?: Array<{ check_id?: string; path?: string; start?: { line?: number } }>;
    errors?: unknown[];
    paths?: { scanned?: unknown[] };
  };
  const rows = (report.results ?? []).map((r) => ({
    rule: String(r.check_id ?? '').split('.').pop() ?? '',
    file: relativeTo(work, String(r.path ?? '')),
    line: Number(r.start?.line),
  }));
  const scan = { rows, scanned: (report.paths?.scanned ?? []).length, errors: report.errors ?? [], raw: report };
  scans.set(dir, scan);
  return scan;
}

const MARKER = /\/\/ BUG: ([a-z0-9-]+)/;

/** `rule file:line` of every marker in hits/. */
function markers(): string[] {
  const out: string[] = [];
  for (const file of readdirSync(HITS).sort()) {
    readFileSync(join(HITS, file), 'utf8')
      .split('\n')
      .forEach((text, i) => {
        const rule = MARKER.exec(text)?.[1];
        if (rule !== undefined) out.push(`${rule} ${file}:${String(i + 1)}`);
      });
  }
  return out.sort();
}

describe('configs/semgrep/client-trust.yml', () => {
  it.runIf(REQUIRE_SEMGREP)('the toolchain must be usable when the flag is set', () => {
    expect(AVAILABLE).toBe(true);
  });

  it('is a plugin pack: every Semgrep run of scan_sast and review_pr passes it', () => {
    expectPack();
    expect(PLUGIN_PACK_FILES).toContain('client-trust.yml');
  });

  it('declares exactly the four rules, each with its CWE, category security and the planned Semgrep severity', () => {
    expectPack();
    const doc = parseYaml(readFileSync(PACK, 'utf8')) as {
      rules: Array<{ id: string; severity: string; metadata: { category: string; cwe: string[] } }>;
    };
    expect(doc.rules.map((r) => r.id)).toEqual(RULE_IDS);
    for (const r of doc.rules) {
      expect(r.metadata.category, r.id).toBe('security');
      expect(r.metadata.cwe.some((c) => c.startsWith(`${RULES[r.id]?.cwe ?? '?'}:`)), r.id).toBe(true);
    }
  });

  it.skipIf(!AVAILABLE)('fires every rule on exactly its marked lines in hits/, and nowhere else', () => {
    expectPack();
    const expected = markers();
    for (const id of RULE_IDS) expect(expected.some((m) => m.startsWith(`${id} `)), `hits/ carries markers for ${id}`).toBe(true);
    expect(expected.filter((m) => !RULE_IDS.includes(m.split(' ')[0] ?? '')), 'markers naming an unknown rule').toEqual([]);
    const scan = scanOf(HITS);
    expect(scan.errors).toEqual([]);
    expect(scan.scanned).toBe(countFiles(HITS));
    expect(scan.rows.map((r) => `${r.rule} ${r.file}:${String(r.line)}`).sort()).toEqual(expected);
  });

  it.skipIf(!AVAILABLE)('fires nothing on the safe shapes in misses/', () => {
    expectPack();
    const scan = scanOf(MISSES);
    expect(scan.errors).toEqual([]);
    expect(scan.scanned).toBe(countFiles(MISSES));
    expect(scan.rows).toEqual([]);
  });

  it.skipIf(!AVAILABLE)('reaches the repo scheme through the Semgrep parser: severity, category and CWE per rule', () => {
    expectPack();
    const { findings } = semgrepParser.parse(scanOf(HITS).raw);
    expect(findings.length).toBeGreaterThan(0);
    for (const f of findings) {
      const rule = (f.rule_id ?? '').split('.').pop() ?? '';
      expect(f.severity, rule).toBe(RULES[rule]?.severity);
      expect(f.category, rule).toBe('security');
      expect(f.cwe, rule).toContain(RULES[rule]?.cwe);
    }
  });

  it('documents its known gaps (a verification the handler text does not name; a pages/ API req.body)', () => {
    expectPack();
    const text = readFileSync(PACK, 'utf8');
    const prose = text.replace(/\n#\s+/g, ' ');
    expect(prose).toMatch(/falso positivo; nesse caso a corre..o . uma supress.o com a raz.o/);
    expect(prose).toMatch(/pages\/\) sem `bodyParser: false` n.o . visto/);
  });
});
