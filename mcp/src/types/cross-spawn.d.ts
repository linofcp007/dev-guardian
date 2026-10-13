/**
 * The one export of `cross-spawn` (7.x) dev-guardian uses: Node's `spawn`,
 * with Windows' command resolution — a `.cmd` / `.bat` shim run through
 * `cmd.exe` with its arguments escaped, a shebang read — done for it. The
 * package ships no types; `runners/childProcess.ts` is its only importer.
 */
declare module 'cross-spawn' {
  import type { ChildProcess, SpawnOptions } from 'node:child_process';

  function spawn(command: string, args?: readonly string[], options?: SpawnOptions): ChildProcess;
  export default spawn;
}
