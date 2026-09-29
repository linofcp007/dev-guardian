/**
 * Regression test for the CLI entry-point symlink/junction bug — item 3,
 * fixed in `fix(cli): entry-point realpath guard, win32 opener, lazy
 * node:sqlite, usage errors`, regression test added in fix round 1, item 5
 * (2026-09-25 full review).
 *
 * `cli/dev-guardian.mjs`'s entry-point guard used to compare
 * `pathToFileURL(process.argv[1]).href` against `import.meta.url` directly.
 * Through a symlink/junction, Node's ESM loader resolves `import.meta.url`
 * to the link's REAL target, while `process.argv[1]` stays the path that
 * was actually invoked (the link) — two different strings naming the same
 * file compared unequal, `main()` never ran, and `check --bash 'rm -rf /'`
 * printed nothing and exited 0 (the same as a clean/ok command, on a
 * catastrophic one). The fix compares REALPATHS on both sides instead.
 *
 * Feasible without admin privileges on Windows: a DIRECTORY JUNCTION
 * (`fs.symlinkSync(target, link, 'junction')`) is a plain NTFS reparse
 * point any user can create — unlike an NTFS SYMLINK, which needs
 * `SeCreateSymbolicLinkPrivilege` (Developer Mode or an elevated prompt).
 * Linking the `cli/` DIRECTORY (not the file itself) and invoking
 * `<link>/dev-guardian.mjs` reproduces the exact bug mechanism: Node still
 * resolves `import.meta.url` through the junction to the real file. POSIX
 * uses an ordinary directory symlink (`'dir'`), which never needs elevated
 * privileges there either.
 *
 * `canLink` is computed at MODULE SCOPE, synchronously, before any
 * `describe`/`it` runs — `it.skipIf` needs to know its condition at
 * collection time, before hooks like `beforeAll` would otherwise have a
 * chance to attempt the link. A failure to create the link (an
 * unexpectedly locked-down environment) is a SKIP, logged to stderr so it
 * reads as a skip rather than a silent pass — never a silent, un-exercised
 * "pass" for the one test whose entire job is proving this exact bug
 * mechanism is gone.
 */

import { mkdtempSync, rmSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, describe, expect, it, vi } from 'vitest';
import { spawnSyncCapped, testTimeoutAbove } from '../helpers/spawnCap.js';

const REPO_ROOT = resolve(fileURLToPath(new URL('../../..', import.meta.url)));
const REAL_CLI_DIR = resolve(REPO_ROOT, 'cli');
const TIMEOUT_MS = 15_000;
// Above the cap: a hung CLI is reported by the cap, naming it (R7-I1).
vi.setConfig({ testTimeout: testTimeoutAbove(TIMEOUT_MS) });

const sandbox = mkdtempSync(join(tmpdir(), 'guardian-cli-link-'));
const linkDir = join(sandbox, 'cli-link');

let canLink = true;
try {
  // Windows: a directory JUNCTION needs no special privilege. POSIX: an
  // ordinary directory symlink, same reason.
  symlinkSync(REAL_CLI_DIR, linkDir, process.platform === 'win32' ? 'junction' : 'dir');
} catch (e) {
  canLink = false;
  process.stderr.write(
    `[cliEntryPointLink.test.ts] SKIPPING: could not create a directory ${
      process.platform === 'win32' ? 'junction' : 'symlink'
    } (${e instanceof Error ? e.message : String(e)}). This is the one test proving the symlink entry-point ` +
      'fix; its absence here means that fix is UNVERIFIED in this run, not that it is fine.\n',
  );
  // Every test below is then skipped, and vitest runs no afterAll in a file
  // with nothing to run: the sandbox goes now or never.
  rmSync(sandbox, { recursive: true, force: true });
}

afterAll(() => {
  rmSync(sandbox, { recursive: true, force: true });
});

describe('cli/dev-guardian.mjs — entry-point guard through a directory junction/symlink', () => {
  it.skipIf(!canLink)(
    'main() still runs through the link — catastrophic bash is BLOCKED (exit 1), never silently ok (exit 0)',
    () => {
      const linkedCli = join(linkDir, 'dev-guardian.mjs');
      const r = spawnSyncCapped(process.execPath, [linkedCli, 'check', '--bash', 'rm -rf /'], {
        encoding: 'utf8',
        timeout: TIMEOUT_MS,
      });
      // The exact pre-fix symptom: main() never ran, so nothing was
      // printed and the process exited 0 — indistinguishable from a clean
      // command. Asserting BOTH the exit code and the BLOCK output rules
      // that out, not just one or the other.
      expect(r.status).toBe(1);
      expect(r.stdout).toMatch(/BLOCK/);
      expect(r.stdout.trim().length).toBeGreaterThan(0);
    },
  );

  it.skipIf(!canLink)('an ordinary, well-formed invocation through the link still works end to end', () => {
    const linkedCli = join(linkDir, 'dev-guardian.mjs');
    const r = spawnSyncCapped(process.execPath, [linkedCli, '--help'], { encoding: 'utf8', timeout: TIMEOUT_MS });
    expect(r.status).toBe(0);
    expect(r.stdout).toMatch(/dev-guardian/);
  });
});
