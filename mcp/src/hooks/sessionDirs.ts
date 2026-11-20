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
 */

/** What asking about one folder came back with. */
export type FolderAnswer = 'there' | 'absent' | 'silent';

/** Asks, in a process of its own, whether each folder answers, within one deadline for all of them. */
export type FolderProbe = (paths: readonly string[], deadlineMs: number) => Promise<ReadonlyMap<string, FolderAnswer>>;

/** How long the probe has, all the network folders of a call together, ms. */
export const NETWORK_PROBE_DEADLINE_MS = 2000;

/** Most notice lines a call carries: the session's folder and the project's are at most two shares. */
const MAX_LINES = 2;

/** The longest host or share name the notice repeats. */
const MAX_NAME = 64;

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
  /** The project's folder as given (the caller resolves it), `undefined` when there is none to use. */
  projectDir: string | undefined;
  /** The network folders that could not be used. */
  unreachable: ReadonlyArray<UnreachableFolder>;
}

/** What the probe says of each network path; a probe that is missing, throws or rejects says nothing. */
async function askAbout(paths: readonly string[], probe: FolderProbe | undefined): Promise<ReadonlyMap<string, FolderAnswer>> {
  if (paths.length === 0 || probe === undefined) return new Map();
  try {
    return await probe(paths, NETWORK_PROBE_DEADLINE_MS);
  } catch {
    // The child could not be asked: the folders are as good as silent (EC-2).
    return new Map();
  }
}

/**
 * Chooses the session's and the project's folder; never throws. A network
 * folder is never given to `exists`: only the probe's answer `'there'` makes
 * it usable, anything else treats it as a folder that does not exist — the
 * session falls back to the hook's own folder, the project is ignored — and
 * names it in `unreachable`. The hook's own folder is used as it is: it was
 * there when the process started.
 */
export async function chooseSessionDirs(input: SessionDirsInput, deps: SessionDirsDeps): Promise<SessionDirs> {
  const { payloadCwd, envProjectDir, processCwd } = input;
  try {
    const session = typeof payloadCwd === 'string' && payloadCwd !== '' ? payloadCwd : undefined;
    const project = envProjectDir !== undefined && envProjectDir !== '' ? envProjectDir : undefined;
    const network = [...new Set([session, project].filter((p): p is string => p !== undefined && deps.isNetworkPath(p)))];
    const answers = await askAbout(network, deps.probe);
    const usable = (path: string): boolean => (deps.isNetworkPath(path) ? answers.get(path) === 'there' : deps.exists(path));
    const sessionUsable = session !== undefined && usable(session);
    const projectUsable = project !== undefined && usable(project);
    const unreachable: UnreachableFolder[] = [];
    for (const path of network) {
      if (answers.get(path) === 'there') continue;
      const isSession = path === session;
      const isProject = path === project;
      unreachable.push({ path, role: isSession && isProject ? 'both' : isSession ? 'session' : 'project' });
    }
    return {
      cwd: sessionUsable && session !== undefined ? session : processCwd,
      projectDir: projectUsable ? project : undefined,
      unreachable,
    };
  } catch {
    return { cwd: processCwd, projectDir: undefined, unreachable: [] };
  }
}

/** Letters, digits, `.`, `-`, `_` and `$` only, at most 64: the payload is not trusted with the notice. */
const cleanName = (name: string): string => name.replace(/[^A-Za-z0-9._$-]/g, '').slice(0, MAX_NAME);

/** The share a network path is on, host and share between two backslashes: `//h/s/p` and the `UNC` device spelling too. */
function shareOf(path: string): string {
  const device = /^(?:[\\/]{2}[?.]|\\\?\?)[\\/]UNC[\\/]/i.exec(path);
  const rest = device === null ? path.replace(/^[\\/]{2}/, '') : path.slice(device[0].length);
  const [host = '', share = ''] = rest.split(/[\\/]/);
  const bs = String.fromCharCode(92);
  return `${bs}${bs}${cleanName(host)}${bs}${cleanName(share)}`;
}

/** The subject of the sentence, and its verb, by the folders on the share. */
function subjectOf(role: UnreachableRole): { who: string; be: string; their: string } {
  if (role === 'session') return { who: "the session's folder", be: 'is', their: 'its' };
  if (role === 'project') return { who: 'the project folder (CLAUDE_PROJECT_DIR)', be: 'is', their: 'its' };
  return { who: "the session's folder and the project folder", be: 'are', their: 'their' };
}

/** The notice lines for the folders that could not be used: one per share, two at most. */
export function unreachableLines(unreachable: ReadonlyArray<UnreachableFolder>): string[] {
  const roles = new Map<string, Set<UnreachableRole>>();
  for (const { path, role } of unreachable) {
    const share = shareOf(path);
    const seen = roles.get(share) ?? new Set<UnreachableRole>();
    seen.add(role);
    roles.set(share, seen);
  }
  return [...roles]
    .slice(0, MAX_LINES)
    .map(([share, seen]) => {
      const { who, be, their } = subjectOf(seen.size > 1 || seen.has('both') ? 'both' : (seen.values().next().value ?? 'session'));
      return (
        `dev-guardian: ${who} ${be} on a network share that could not be reached or does not exist (${share}) — ` +
        `${their} hook settings and registry configuration were not read; the hook's own folder is used instead.`
      );
    });
}
