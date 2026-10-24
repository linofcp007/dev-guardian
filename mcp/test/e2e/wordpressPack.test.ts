/**
 * Runs `configs/semgrep/wordpress.yml` -- the plugin's WordPress pack -- against
 * `mcp/test/fixtures/wordpress/`:
 *
 *   hits/    every line marked `// BUG` is one `wordpress-esc-sql-unquoted`
 *            finding: an `esc_sql(...)` value after `=`, `IN (`, `>=` and
 *            `LIMIT`, in a double- and a single-quoted PHP literal, after a
 *            quoted value, at the end of a chain; through a variable,
 *            `implode` and a list that brings its own parentheses;
 *            interpolated (`$id`, `{$id}`, in a string over two lines); a
 *            `sprintf` argument for an unquoted `%s` / `%1$s`. Nothing else
 *            may fire;
 *   misses/  the safe shapes: the value between quotes (also a quote opened in
 *            an earlier literal of the chain, and `"` as the SQL quote), an
 *            identifier between backticks and an operator, text that is not
 *            SQL, a value converted inside `esc_sql(...)` or after it, a list
 *            the concatenation quotes itself, an interpolation between quotes
 *            or of another variable, code that is not a string, a `sprintf`
 *            with a quoted `%s`, a `%d` or a mixed format, `$wpdb->prepare`;
 *            nothing fires.
 *
 * That `scan_wordpress` passes it beside the registry's `p/php` and
 * `p/wordpress`, and stores its rule id bare, is
 * `integration/scanWordpressSemgrep.test.ts`; that scan_sast passes it,
 * `integration/scanSastProjectRules.test.ts`.
 *
 * `--validate` and the banned characters are `integration/semgrepPacks.test.ts`
 * (it discovers packs from disk); the ablation registry is `test/ablate/packs.ts`.
 * Fixtures are copied to a temp dir before scanning: their in-repo path holds a
 * `test/` segment, which Semgrep's default ignore list skips.
 *
 * SKIPPED, not silently passed, when Semgrep is absent;
 * `GUARDIAN_REQUIRE_SEMGREP=1` turns that absence into a hard failure.
 */

import { afterAll, describe, expect, it, vi } from 'vitest';

vi.setConfig({ testTimeout: 180_000 });
import { cpSync, existsSync, readFileSync } from 'node:fs';
import { basename, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { semgrepAvailable, semgrepStdout } from '../helpers/semgrep.js';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';

afterAll(cleanupTempDirs);

const REPO_ROOT = resolve(fileURLToPath(new URL('../../..', import.meta.url)));
const PACK = resolve(REPO_ROOT, 'configs', 'semgrep', 'wordpress.yml');
const FIXTURES = resolve(REPO_ROOT, 'mcp', 'test', 'fixtures', 'wordpress');
const REQUIRE_SEMGREP = process.env['GUARDIAN_REQUIRE_SEMGREP'] === '1';
const AVAILABLE = semgrepAvailable();

const RULE = 'wordpress-esc-sql-unquoted';

/** The `// BUG` lines of hits/unquoted.php, as `file:line`. */
function bugLines(): string[] {
  return readFileSync(resolve(FIXTURES, 'hits', 'unquoted.php'), 'utf8')
    .split(/\r?\n/)
    .flatMap((line, i) => (/\/\/ BUG\s*$/.test(line) ? [`unquoted.php:${String(i + 1)}`] : []));
}

interface RawResult {
  readonly check_id?: unknown;
  readonly path?: unknown;
  readonly start?: { readonly line?: unknown };
  readonly extra?: { readonly metadata?: { readonly cwe?: unknown } };
}

function scan(dir: string): { rows: Array<{ rule: string; at: string; cwe: string[] }>; scanned: number; errors: unknown[] } {
  const work = makeTempDir('guardian-wp-pack-');
  cpSync(dir, work, { recursive: true });
  const stdout = semgrepStdout([`--config=${PACK}`, '--json', '--quiet', '--no-git-ignore', '--metrics=off', work], { cwd: work });
  const report = JSON.parse(stdout) as { results?: RawResult[]; errors?: unknown[]; paths?: { scanned?: unknown[] } };
  return {
    rows: (report.results ?? []).map((r) => {
      const id = String(r.check_id ?? '');
      const cwe = r.extra?.metadata?.cwe;
      return {
        rule: id.split('.').pop() ?? id,
        at: `${basename(String(r.path ?? ''))}:${String(r.start?.line)}`,
        cwe: Array.isArray(cwe) ? cwe.map(String) : [],
      };
    }),
    scanned: (report.paths?.scanned ?? []).length,
    errors: report.errors ?? [],
  };
}

describe('configs/semgrep/wordpress.yml', () => {
  it('exists, and the fixture marks fifteen bugs', () => {
    expect(existsSync(PACK)).toBe(true);
    expect(bugLines()).toHaveLength(15);
  });

  it.runIf(!AVAILABLE && REQUIRE_SEMGREP)('GUARDIAN_REQUIRE_SEMGREP=1: semgrep must be on PATH', () => {
    expect(AVAILABLE, 'semgrep is not on PATH').toBe(true);
  });

  it.skipIf(!AVAILABLE)('hits/: exactly the BUG lines, each CWE-89', () => {
    const s = scan(resolve(FIXTURES, 'hits'));
    expect(s.errors).toEqual([]);
    expect(s.scanned).toBe(1);
    expect(s.rows.map((r) => r.at).sort()).toEqual(bugLines().sort());
    for (const r of s.rows) {
      expect(r.rule).toBe(RULE);
      expect(r.cwe[0]).toMatch(/^CWE-89:/);
    }
  });

  it.skipIf(!AVAILABLE)('misses/: nothing fires, and the file was read', () => {
    const s = scan(resolve(FIXTURES, 'misses'));
    expect(s.errors).toEqual([]);
    expect(s.scanned).toBe(1);
    expect(s.rows).toEqual([]);
  });
});
