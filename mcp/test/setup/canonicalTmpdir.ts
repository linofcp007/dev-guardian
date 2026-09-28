/**
 * Makes `os.tmpdir()` return its CANONICAL spelling in every vitest worker.
 *
 * `resolveProjectPath` returns a canonical path (`realpathSync.native`: long
 * names, links resolved, upper-case drive letter), because the same project
 * stored under two spellings split its history in two. On many Windows
 * machines `os.tmpdir()` is itself an 8.3 alias — `C:\Users\ADMINI~1\…` for
 * `C:\Users\Administrator\…` — and on macOS it is `/var/folders/…`, a symlink
 * into `/private/var`. A test that builds a project under the temp dir, seeds
 * rows under that raw spelling and then calls a tool (which resolves the
 * canonical one) would be testing the alias, not the tool: 8 files failed
 * that way, with production code consistent throughout.
 *
 * So workers get the canonical temp dir, the way a real project path usually
 * is. The alias itself stays tested, explicitly, in
 * `test/unit/platform/projectPath.test.ts`, which reads the original spelling
 * from `GUARDIAN_TEST_RAW_TMPDIR`.
 */

import { realpathSync } from 'node:fs';
import { tmpdir } from 'node:os';

const raw = tmpdir();
let canonical = raw;
try {
  canonical = realpathSync.native(raw);
} catch {
  /* leave the environment alone */
}

if (canonical !== raw) {
  process.env['GUARDIAN_TEST_RAW_TMPDIR'] = raw;
  // os.tmpdir() reads TEMP/TMP on Windows and TMPDIR (then TMP/TEMP) elsewhere.
  for (const key of ['TMPDIR', 'TEMP', 'TMP']) process.env[key] = canonical;
}
