/**
 * Child-process harness for `processRunner.test.ts`'s exit-cleanup test.
 *
 * Runs under `node --import tsx` as its OWN process, because what is under
 * test is what happens to a scanner's process group when the process that
 * started it goes away — something no in-process test can observe.
 *
 *   argv: <forking-parent.cjs> <grandchild-pid-file> <exit|SIGTERM>
 *
 * Starts `runProcess` on the forking parent (which records its grandchild's
 * pid), waits until the pid file exists, then ends this process either with
 * `process.exit(0)` (the MCP server's shutdown path) or with an unhandled
 * SIGTERM (a CI runner stopping the CLI). The test then checks that the
 * grandchild did not survive.
 */
import { existsSync } from 'node:fs';
import { dirname } from 'node:path';
import { runProcess } from '../../src/runners/processRunner.js';

const [parentScript, pidFile, mode] = process.argv.slice(2);
if (parentScript === undefined || pidFile === undefined || mode === undefined) {
  process.stderr.write('usage: processRunnerExitHarness <parent.cjs> <pid-file> <exit|SIGTERM>\n');
  process.exit(2);
}

void runProcess({
  command: process.execPath,
  args: [parentScript, pidFile],
  cwd: dirname(parentScript),
  timeoutMs: 60_000,
});

const poll = setInterval(() => {
  if (!existsSync(pidFile)) return;
  clearInterval(poll);
  if (mode === 'exit') process.exit(0);
  process.kill(process.pid, 'SIGTERM');
}, 50);
