/**
 * What this account may do to a filesystem, probed once per test file rather
 * than assumed: symlink creation needs admin or Developer Mode on Windows.
 */
import { mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

export const POSIX = process.platform !== 'win32';

/** Whether this account may create symlinks (Windows needs admin or Developer Mode). */
export const CAN_SYMLINK = ((): boolean => {
  const probe = mkdtempSync(join(tmpdir(), 'fs-capability-symlink-probe-'));
  try {
    writeFileSync(join(probe, 't'), 'x');
    symlinkSync(join(probe, 't'), join(probe, 'l'));
    return true;
  } catch {
    return false;
  } finally {
    rmSync(probe, { recursive: true, force: true });
  }
})();
