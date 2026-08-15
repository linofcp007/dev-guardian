/**
 * Pins `resolveVersion()` to the REAL release version — not just "some
 * string", which a wrong `..` count landing on an unrelated JSON file that
 * happens to carry its own `version` key would also satisfy. Independently
 * computed from `.claude-plugin/plugin.json` (this test file's own path
 * arithmetic, not `version.ts`'s), so the test and the implementation cannot
 * share the same mistake — same technique as `scriptsDir.test.ts`, and a
 * second, cross-checking assertion against `mcp/package.json` (which
 * CLAUDE.md's own release checklist keeps in lock-step with plugin.json).
 *
 * Only exercises the UNBUNDLED code path (this file, and `dist/ci/report.js`
 * / `dist/report/sarif.js` in production, are all plain, unbundled ES
 * modules — vitest never executes the esbuild bundle). The BUNDLED path
 * (`dist/server.js`, where every import collapses to one file and
 * `import.meta.url` means something different — see `version.ts`'s own doc
 * comment) was instead verified by running the actual built server/CLI and
 * reading the version each one reports; see the task report for that
 * evidence, since a bundle can't be exercised from inside vitest.
 */
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { resolveVersion } from '../../../src/platform/version.js';

/** This test file lives at mcp/test/unit/platform/ — four levels under the
 *  plugin root (platform -> unit -> test -> mcp -> root). Computed
 *  independently of version.ts's own arithmetic on purpose. */
function readJsonVersion(...segments: string[]): string {
  const here = dirname(fileURLToPath(import.meta.url));
  const parsed = JSON.parse(readFileSync(resolve(here, ...segments), 'utf8')) as {
    version?: string;
  };
  if (!parsed.version) throw new Error(`no "version" field at ${segments.join('/')}`);
  return parsed.version;
}

describe('resolveVersion', () => {
  it('resolves to the real plugin.json version, independently computed', () => {
    const expected = readJsonVersion('..', '..', '..', '..', '.claude-plugin', 'plugin.json');
    expect(resolveVersion()).toBe(expected);
  });

  it('matches mcp/package.json — the release checklist keeps both in lock-step', () => {
    const expected = readJsonVersion('..', '..', '..', 'package.json');
    expect(resolveVersion()).toBe(expected);
  });

  it('is stable across repeated calls', () => {
    expect(resolveVersion()).toBe(resolveVersion());
  });
});
