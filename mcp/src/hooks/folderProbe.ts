/**
 * Asks whether folders answer, in a process of its own that this one gives a
 * deadline (bug `hook-unc-cwd-hang`): a folder on a network host that is down
 * holds whoever asks for about 21 s, and a process stuck on it cannot even
 * exit — only a parent with a deadline over a child gets an answer in time.
 * Its own part of the hooks bundle (`src/hooksProbe.ts`), loaded only when a
 * folder is on the network; it imports nothing of this repository's (the type
 * below is erased by the build).
 *
 * The child is `node -e <fixed text> <path>...`: the paths are arguments, never
 * part of the text, and the child's working folder is the one of the Node
 * executable — a process cannot even be started with its working folder on a
 * dead share. It asks about every path at once and writes one line per answer
 * as it has it — `<index of the path> there` or `<index> absent` — and what is
 * written by the deadline counts; the rest is `'silent'`. A child that cannot be
 * started, that fails, or that is killed by the deadline leaves what it did not
 * answer `'silent'`.
 */
import { spawnSync } from 'node:child_process';
import { dirname } from 'node:path';
import type { FolderAnswer } from './sessionDirs.js';

/** The program that asks, with the arguments it takes before the paths. */
export interface ProbeChild {
  command: string;
  args: readonly string[];
}

/** The text the child runs: a stat of every path, side by side, each answer written as soon as it is known. */
const CHILD_SCRIPT = [
  "const fs = require('node:fs');",
  'process.argv.slice(1).forEach((path, index) => {',
  "  fs.promises.stat(path).then(() => fs.writeSync(1, index + ' there\\n'), () => fs.writeSync(1, index + ' absent\\n'));",
  '});',
].join('\n');

/** Reads the child's lines: the answer of each path it wrote one for. */
function answersOf(output: string, count: number): Map<number, FolderAnswer> {
  const answers = new Map<number, FolderAnswer>();
  for (const line of output.split('\n')) {
    const space = line.indexOf(' ');
    if (space < 1) continue;
    const index = Number(line.slice(0, space));
    const word = line.slice(space + 1).trim();
    if (!Number.isInteger(index) || index < 0 || index >= count) continue;
    if (word === 'there' || word === 'absent') answers.set(index, word);
  }
  return answers;
}

/** One answer per path, as given; never throws. */
export async function probeFolders(
  paths: readonly string[],
  deadlineMs: number,
  child: ProbeChild = { command: process.execPath, args: ['-e', CHILD_SCRIPT] },
): Promise<ReadonlyMap<string, FolderAnswer>> {
  const result = new Map<string, FolderAnswer>(paths.map((path): [string, FolderAnswer] => [path, 'silent']));
  if (paths.length === 0) return result;
  let output = '';
  try {
    const run = spawnSync(child.command, [...child.args, ...paths], {
      timeout: deadlineMs,
      windowsHide: true,
      encoding: 'utf8',
      cwd: dirname(process.execPath),
      stdio: ['ignore', 'pipe', 'ignore'],
    });
    output = typeof run.stdout === 'string' ? run.stdout : '';
  } catch {
    // The child could not be started (a NUL in a path, the permission model): nothing answered.
    return result;
  }
  for (const [index, answer] of answersOf(output, paths.length)) {
    const path = paths[index];
    if (path !== undefined) result.set(path, answer);
  }
  return result;
}
