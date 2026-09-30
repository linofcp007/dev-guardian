/**
 * Child-process entry point for the concurrent-open test
 * (`test/integration/storageConcurrency.test.ts`): open (and so migrate) the
 * project database exactly as the server does, then close it.
 *
 *   node --import <tsx> openDbChild.ts <projectPath>
 *
 * The opens have to really overlap, not be serialised by process start-up
 * time, so the child and the test shake hands: the child prints `ready` once
 * it is loaded, the test waits for every child's `ready` and then sends each
 * one `go <epoch ms>` on stdin — the same instant, a moment ahead. The child
 * waits for it with a timer to just before it and a spin to it (a timer alone
 * wakes a scheduler tick late — 15.6 ms on Windows — as long as an open).
 *
 * It used to sleep until a fixed `startAt` passed on the command line, three
 * seconds after the test spawned it: a child slower to start than that opened
 * after the others had finished, and the test passed with no concurrency at
 * all (review 3.0, R7).
 *
 * On success it prints one JSON line — `{"late":…,"start":…,"end":…}`, epoch
 * milliseconds: when the open began and ended, and how far past the shared
 * instant the child got there — so the test checks the overlap rather than
 * assume it. Exit 0 on success; exit 1 with the error on stderr otherwise.
 */

import { openDatabase } from '../../src/storage/db.js';

const [projectPath] = process.argv.slice(2);
if (projectPath === undefined) {
  process.stderr.write('usage: openDbChild.ts <projectPath>, then "go <epoch ms>" on stdin\n');
  process.exit(2);
}
const project: string = projectPath;
const now = (): number => performance.timeOrigin + performance.now();

function open(startAt: number): void {
  while (now() < startAt) {
    /* spin to the shared instant */
  }
  const start = now();
  const late = start - startAt;
  let line: string;
  try {
    const { db } = openDatabase({ projectPath: project });
    db.close();
    line = `${JSON.stringify({ late, start, end: now() })}\n`;
  } catch (error) {
    // Exit once the write is flushed: a pipe is asynchronous on Windows.
    process.stderr.write(`${error instanceof Error ? (error.stack ?? error.message) : String(error)}\n`, () =>
      process.exit(1),
    );
    return;
  }
  process.stdout.write(line, () => process.exit(0));
}

let input = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', (chunk: string) => {
  input += chunk;
  const go = /^go (\d+(?:\.\d+)?)$/m.exec(input);
  if (go?.[1] === undefined) return;
  process.stdin.pause();
  const startAt = Number(go[1]);
  setTimeout(() => open(startAt), Math.max(0, startAt - now() - 30));
});
process.stdout.write('ready\n');
