/**
 * deps-tools-host-other-texts, task 2, T-10 (red until the fix): the lines `runProcess` hands to `onLog`. The callback
 * gets each piece the stream decoder produces, split at line ends, so a line that a pipe cut in two reaches it as two
 * halves (`… https://U:T` and `@H/x.tgz`): no rule can see the URL whole, and the heartbeat of a progress message
 * says the first half. `onLog` must get whole lines: what has no line end yet is kept for the next piece; what is left
 * at the end of the stream is sent at the end; a rest of more than 4 096 characters is sent as one line.
 *
 * A real child (`node -e`, no package manager) writes the pieces to its stderr with a pause between them, so they
 * reach the parent as separate pieces. Every credential-looking value is MADE UP and built from parts.
 */

import { execPath } from 'node:process';
import { afterAll, describe, expect, it } from 'vitest';
import { runProcess } from '../../../src/runners/processRunner.js';
import { cleanupTempDirs, makeTempDir } from '../../helpers/tempDir.js';

afterAll(cleanupTempDirs);

const FEATURE = 'deps-tools-host-other-texts';
const T = ['tok', 'ZzQ', '7731'].join('');
const U = ['dg', 'user', 'zq'].join('');
const H = 'host.example';

/** The lines `onLog` gets when the child writes `pieces` to its stderr, 60 ms apart. */
async function linesOf(pieces: string[]): Promise<string[]> {
  const script = [
    `const pieces = ${JSON.stringify(pieces)};`,
    'let i = 0;',
    'const next = () => {',
    '  if (i >= pieces.length) return;',
    '  process.stderr.write(pieces[i]);',
    '  i += 1;',
    '  setTimeout(next, 60);',
    '};',
    'next();',
  ].join('\n');
  const lines: string[] = [];
  const result = await runProcess({ command: execPath, args: ['-e', script], cwd: makeTempDir('dg-lines-'), timeoutMs: 30_000, onLog: (line) => lines.push(line) });
  expect(result.outcome).toBe('completed');
  return lines;
}

describe(`${FEATURE} T-10 onLog gets whole lines`, () => {
  it('T-10 a line cut in two pieces by the pipe reaches onLog as one line', async () => {
    const lines = await linesOf([`a https://${U}:${T}`, `@${H}/x.tgz\n`]);
    expect(lines).toEqual([`a https://${U}:${T}@${H}/x.tgz`]);
  }, 30_000);

  it('T-10 a rest with no line end at the end of the stream is sent at the end, joined to the piece before it', async () => {
    const lines = await linesOf(['first\nsecond', ' part']);
    expect(lines).toEqual(['first', 'second part']);
  }, 30_000);

  it('T-10 a rest of 5 000 characters with no line end is sent as one line', async () => {
    const lines = await linesOf(Array.from({ length: 5 }, () => 'x'.repeat(1000)));
    expect(lines.map((l) => l.length)).toEqual([5000]);
  }, 30_000);
});
