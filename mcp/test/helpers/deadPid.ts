/**
 * A pid no running process has — for a scan row whose owner must read as dead.
 *
 * These tests used the pid of a child that had just exited. On a loaded
 * Windows machine that pid was handed to another process before the reaper
 * looked, the reaper saw its owner alive, and "reaped 1 orphaned scan" never
 * came (measured: 2 full-suite runs in 5 on Windows 11, the file green in
 * isolation every time). A pid nobody can be assigned removes the race:
 * 0x7ffffff0 is a multiple of 4 like every Windows pid, above Linux's
 * PID_MAX_LIMIT (2^22) and macOS's 99 999, and `process.kill(pid, 0)` answers
 * ESRCH for it everywhere.
 */
export const DEAD_PID = 0x7ffffff0;

/** {@link DEAD_PID}, checked: throws if something does run under it. */
export function deadPid(): number {
  try {
    process.kill(DEAD_PID, 0);
  } catch (error) {
    if (error instanceof Error && 'code' in error && error.code === 'ESRCH') return DEAD_PID;
  }
  throw new Error(`pid ${String(DEAD_PID)} is not free on this machine; the dead-owner tests cannot run`);
}
