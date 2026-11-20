/**
 * Which folders a hook call works in: the session's (the payload's `cwd`, else
 * the hook process's own) and the project's (`CLAUDE_PROJECT_DIR`).
 *
 * Logic only, no `node:child_process` and no disk of its own: the dispatcher
 * hands in the disk question (`exists`), the network-path rule and, when a
 * folder is on the network, the probe that asks a child process whether it
 * answers (`folderProbe.ts`, its own part of the hooks bundle) — so a
 * `\\host\share` that does not answer is never opened in the hook's own
 * process, where Windows waits about 21 s for it (bug `hook-unc-cwd-hang`).
 *
 * SKELETON (task 1 of that bugfix): the choice the dispatcher made inline
 * before — `exists` for every folder, nothing ever unreachable. The probe, the
 * deadline and the notice lines arrive in task 2.
 */

/** What asking about one folder came back with. */
export type FolderAnswer = 'there' | 'absent' | 'silent';

/** Asks, in a process of its own, whether each folder answers, within one deadline for all of them. */
export type FolderProbe = (paths: readonly string[], deadlineMs: number) => Promise<ReadonlyMap<string, FolderAnswer>>;

interface SessionDirsInput {
  /** The payload's `cwd`, as it came: anything. */
  payloadCwd: unknown;
  /** `CLAUDE_PROJECT_DIR`. */
  envProjectDir: string | undefined;
  /** The hook process's own working folder. */
  processCwd: string;
}

interface SessionDirsDeps {
  exists(path: string): boolean;
  isNetworkPath(path: string): boolean;
  /** `undefined` when the part that asks could not be loaded. */
  probe: FolderProbe | undefined;
}

/** Which of the two folders a network path that could not be used was. */
type UnreachableRole = 'session' | 'project' | 'both';

export interface UnreachableFolder {
  path: string;
  role: UnreachableRole;
}

interface SessionDirs {
  /** The folder the call works in. */
  cwd: string;
  /** The project's folder, `undefined` when there is none to use. */
  projectDir: string | undefined;
  /** The network folders that could not be used. */
  unreachable: ReadonlyArray<UnreachableFolder>;
}

/** Chooses the session's and the project's folder; never throws. */
export async function chooseSessionDirs(input: SessionDirsInput, deps: SessionDirsDeps): Promise<SessionDirs> {
  const { payloadCwd, envProjectDir, processCwd } = input;
  const cwd = typeof payloadCwd === 'string' && payloadCwd !== '' && deps.exists(payloadCwd) ? payloadCwd : processCwd;
  const projectDir = envProjectDir !== undefined && envProjectDir !== '' && deps.exists(envProjectDir) ? envProjectDir : undefined;
  return { cwd, projectDir, unreachable: [] };
}

/** The notice lines for the folders that could not be used, one per share. */
export function unreachableLines(_unreachable: ReadonlyArray<UnreachableFolder>): string[] {
  return [];
}
