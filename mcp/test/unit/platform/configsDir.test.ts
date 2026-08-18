/**
 * Pins `resolveConfigsDir()` / `resolveBugfixRules()` to the REAL `configs/`
 * directory and the REAL `configs/semgrep/bugfix-*.yml` files — not just
 * "some path exists", which a wrong `..` count, or a copy-paste bug that
 * resolves `base.yml` or `routes.yml` instead (both real, both present in
 * this repo), would also satisfy. Mirrors `scriptsDir.test.ts`'s own
 * discipline:
 *
 *  1. `resolveConfigsDir()` equals the plugin's `configs/` directory,
 *     computed here by an entirely separate path calculation (this test
 *     file's own location), so the test and the implementation cannot share
 *     the same mistake.
 *  2. It contains `semgrep/base.yml`, the exact marker `resolveConfigsDir`
 *     itself probes for.
 *  3. `resolveBugfixRules()`'s result is pinned to the EXACT array of
 *     `semgrep/bugfix-*.yml` paths, independently computed — a bare
 *     `existsSync` check, or a bare `*.yml` glob, alone would also pass for
 *     an implementation that (wrongly) also returned `.../semgrep/base.yml`
 *     or `.../semgrep/routes.yml`, since both files are real too.
 *
 * Only the UNBUNDLED code path is exercised here (this file, like every
 * other unit test, imports the plain compiled module — vitest never runs
 * the esbuild bundle). The BUNDLED path (`dist/server.js`, where every
 * import collapses into one file and `import.meta.url` means something
 * different — see `configsDir.ts`'s own doc comment, which mirrors
 * `scriptsDir.ts`'s) was verified separately by running the actual built
 * `dist/server.js` end-to-end through `bug_hunt` against a real fixture;
 * see the task report for that evidence, since a bundle can't be exercised
 * from inside vitest.
 */
import { existsSync } from 'node:fs';
import { basename, dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { resolveBugfixRules, resolveConfigsDir } from '../../../src/platform/configsDir.js';

/** This test file lives at mcp/test/unit/platform/ — four levels under the
 *  plugin root (platform -> unit -> test -> mcp -> root). Computed
 *  independently of configsDir.ts's own arithmetic on purpose. */
function expectedConfigsDir(): string {
  const here = dirname(fileURLToPath(import.meta.url));
  return resolve(here, '..', '..', '..', '..', 'configs');
}

describe('resolveConfigsDir', () => {
  it('resolves to the plugin configs/ directory, independently computed', () => {
    expect(resolveConfigsDir()).toBe(expectedConfigsDir());
  });

  it('resolves to a directory that actually holds base.yml', () => {
    // The marker-file probe, not a `..` count: resolveScriptsDir exists because
    // the same code runs bundled and unbundled, at different depths.
    expect(existsSync(resolve(resolveConfigsDir(), 'semgrep', 'base.yml'))).toBe(true);
  });

  it('is stable across repeated calls', () => {
    expect(resolveConfigsDir()).toBe(resolveConfigsDir());
  });
});

describe('resolveBugfixRules', () => {
  it('returns every bugfix-*.yml in configs/semgrep, sorted, as absolute paths', () => {
    const dir = join(resolveConfigsDir(), 'semgrep');
    expect(resolveBugfixRules()).toEqual([
      join(dir, 'bugfix-js.yml'),
      join(dir, 'bugfix-py.yml'),
    ]);
  });

  it('every returned path exists on disk', () => {
    for (const p of resolveBugfixRules()) {
      expect(existsSync(p)).toBe(true);
    }
  });

  it('returns ONLY bugfix-*.yml — never base.yml or routes.yml, which are real too', () => {
    // A glob over `*.yml` would also return these and would satisfy any
    // "contains bugfix-py.yml" assertion. They must not be passed as
    // bug_hunt --config values.
    const names = resolveBugfixRules().map((p) => basename(p));
    expect(names).not.toContain('base.yml');
    expect(names).not.toContain('routes.yml');
    for (const name of names) {
      expect(name.startsWith('bugfix-')).toBe(true);
      expect(name.endsWith('.yml')).toBe(true);
    }
  });

  it('is stable across repeated calls', () => {
    expect(resolveBugfixRules()).toEqual(resolveBugfixRules());
  });
});
