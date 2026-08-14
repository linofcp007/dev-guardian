/**
 * Pins `resolveScriptsDir()` to the REAL `scripts/` directory — not just
 * "some directory exists", which a wrong `..` count pointed at an empty or
 * unrelated folder would also satisfy. Two independent checks:
 *
 *  1. It equals the plugin's `scripts/` directory, computed here by an
 *     entirely separate path calculation (this test file's own location),
 *     so the test and the implementation cannot share the same mistake.
 *  2. It contains the exact scripts the tools that consume `scriptsDir`
 *     actually invoke.
 *
 * This only exercises the UNBUNDLED code path (this file, this test's
 * import of `scriptsDir.ts`, and `dist/ci/runScans.js` in production, are
 * all plain, unbundled ES modules — vitest never executes the esbuild
 * bundle). The BUNDLED path (`dist/server.js`, where every import collapses
 * to one file and `import.meta.url` means something different — see
 * `scriptsDir.ts`'s own doc comment) was instead verified by running the
 * actual built `dist/server.js` and confirming the resolved directory in
 * its startup diagnostics; see the task report for that evidence, since a
 * bundle can't be exercised from inside vitest.
 */
import { existsSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { resolveScriptsDir } from '../../../src/platform/scriptsDir.js';

/** This test file lives at mcp/test/unit/platform/ — four levels under the
 *  plugin root (platform -> unit -> test -> mcp -> root). Computed
 *  independently of scriptsDir.ts's own arithmetic on purpose. */
function expectedScriptsDir(): string {
  const here = dirname(fileURLToPath(import.meta.url));
  return resolve(here, '..', '..', '..', '..', 'scripts');
}

describe('resolveScriptsDir', () => {
  it('resolves to the plugin scripts/ directory, independently computed', () => {
    expect(resolveScriptsDir()).toBe(expectedScriptsDir());
  });

  it('resolves to a directory that exists', () => {
    expect(existsSync(resolveScriptsDir())).toBe(true);
  });

  it('contains the scripts the tools actually invoke', () => {
    const dir = resolveScriptsDir();
    // detect_stack's SCRIPT_REL_PATH (detectStack.ts) and
    // security_scan_full's SCRIPT_REL_PATH (securityScanFull.ts).
    expect(existsSync(join(dir, 'detect', 'detect-stack.sh'))).toBe(true);
    expect(existsSync(join(dir, 'scan', 'full-security-scan.sh'))).toBe(true);
  });

  it('is stable across repeated calls', () => {
    expect(resolveScriptsDir()).toBe(resolveScriptsDir());
  });
});
