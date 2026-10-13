/**
 * What dev-guardian uses of `cross-spawn` (7.x): its parse — Node's `spawn`
 * arguments with Windows' command resolution done, a `.cmd` / `.bat` file
 * turned into a `cmd.exe /d /s /c "…"` line with its arguments escaped, a
 * shebang read — and the ENOENT hook its own `spawn` adds. `runners/spawn.ts`
 * is the only importer: it parses, judges what `cmd.exe` would be handed, and
 * only then spawns. The package ships no types.
 */
declare module 'cross-spawn' {
  import type { ChildProcess, SpawnOptions } from 'node:child_process';

  /** `lib/parse.js`: what `spawn` hands Node's own spawn. */
  interface CrossSpawnParsed {
    command: string;
    args: string[];
    /** `windowsVerbatimArguments` is set exactly when the command runs through `cmd.exe`. */
    options: SpawnOptions & { windowsVerbatimArguments?: boolean };
    /** The resolved file, when the command was found. */
    file?: string;
    original: { command: string; args: string[] };
  }

  interface CrossSpawn {
    (command: string, args?: readonly string[], options?: SpawnOptions): ChildProcess;
    /** `index.js` exports the parse as `_parse`. */
    _parse(command: string, args: readonly string[], options: SpawnOptions): CrossSpawnParsed;
    /** `index.js` exports the ENOENT hook as `_enoent`: a command `cmd.exe` did not find exits 1, reported as ENOENT. */
    _enoent: { hookChildProcess(child: ChildProcess, parsed: CrossSpawnParsed): void };
  }

  const spawn: CrossSpawn;
  export default spawn;
}
