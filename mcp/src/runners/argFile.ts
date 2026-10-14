/**
 * Text a program reads from a file instead of its command line: the body
 * of a pull request or an issue, handed to `gh … --body-file` (review 10,
 * finding 3).
 *
 * A body is markdown built from findings — text the scanned repository
 * wrote: rule messages, file names, titles. On the command line, a `gh`
 * installed as a batch file would hand it to `cmd.exe`, where a `"` ends the
 * quotes it is wrapped in and a line break ends the command
 * (`runners/spawn.ts` refuses both, and so refused every multi-line body);
 * and a long body runs past `cmd.exe`'s 8 191-character line. From a file,
 * every byte arrives, through any `gh`.
 */

import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

/** Writes `text` to a file in a fresh temp directory, runs `use` with its path, and removes the directory. */
export async function withTextFile<T>(text: string, use: (path: string) => Promise<T>): Promise<T> {
  const dir = mkdtempSync(join(tmpdir(), 'dev-guardian-body-'));
  try {
    const file = join(dir, 'body.md');
    writeFileSync(file, text, 'utf8');
    return await use(file);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}
