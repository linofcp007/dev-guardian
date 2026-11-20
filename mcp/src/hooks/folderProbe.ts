/**
 * Asks whether folders answer, in a process of its own that this one gives a
 * deadline (bug `hook-unc-cwd-hang`): a folder on a network host that is down
 * holds whoever asks for about 21 s, and a process stuck on it cannot even
 * exit — only a parent with a deadline over a child gets an answer in time.
 * Its own part of the hooks bundle (`src/hooksProbe.ts`), loaded only when a
 * folder is on the network; it imports nothing of this repository's.
 *
 * SKELETON (task 1 of that bugfix): answers `'there'` to everything and starts
 * nothing. The child arrives in task 2.
 *
 * The protocol the tests' stand-in children speak (`sessionDirs.test.ts`): the
 * child gets the paths as arguments after its own `args`, and writes one line
 * per answer as it has it — `<index of the path> there` or `<index> absent`.
 * What is written by the deadline counts; the rest is `'silent'`.
 */
import type { FolderAnswer } from './sessionDirs.js';

/** The program that asks, with the arguments it takes before the paths. */
export interface ProbeChild {
  command: string;
  args: readonly string[];
}

/** One answer per path, as given; never throws. */
export async function probeFolders(
  paths: readonly string[],
  _deadlineMs: number,
  _child?: ProbeChild,
): Promise<ReadonlyMap<string, FolderAnswer>> {
  return new Map(paths.map((path): [string, FolderAnswer] => [path, 'there']));
}
