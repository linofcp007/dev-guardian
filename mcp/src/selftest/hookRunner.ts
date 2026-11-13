/**
 * Starting the hooks' dispatcher for a selftest check — the way Claude Code
 * starts it: `node hooks/guardian-hook.mjs <event>`, the payload on its
 * standard input, no shell anywhere. The check's command is in that payload
 * and nowhere else: never an argument, never a line a shell reads.
 */

import { spawnNoShell, readText } from '../runners/spawn.js';
import type { HookAnswer, HookRunArgs } from './run.js';

/** The most of the dispatcher's answer kept: its answers are a few hundred bytes. */
const MAX_ANSWER_BYTES = 256 * 1024;

/** Run the dispatcher once and return what it printed. Never rejects. */
export function runDispatcher(args: HookRunArgs): Promise<HookAnswer> {
  return new Promise((resolve) => {
    let child;
    try {
      child = spawnNoShell(process.execPath, [args.dispatcher, args.event], { cwd: args.cwd, env: args.env, stdio: ['pipe', 'pipe', 'ignore'] });
    } catch (error) {
      resolve({ exitCode: null, stdout: '', timedOut: false, spawnError: error instanceof Error ? error.message : String(error) });
      return;
    }
    let stdout = '';
    let settled = false;
    let timedOut = false;
    const finish = (answer: HookAnswer): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      args.signal.removeEventListener('abort', stop);
      resolve(answer);
    };
    const stop = (): void => {
      timedOut = true;
      child.kill();
    };
    const timer = setTimeout(stop, args.timeoutMs);
    timer.unref();
    args.signal.addEventListener('abort', stop, { once: true });
    readText(child.stdout, (text, total) => {
      if (total <= MAX_ANSWER_BYTES) stdout += text;
    });
    child.on('error', (error) => finish({ exitCode: null, stdout: '', timedOut: false, spawnError: error.message }));
    child.on('close', (code) => finish({ exitCode: code, stdout, timedOut }));
    // A dispatcher that exits before it reads must not take this process down with EPIPE.
    child.stdin?.on('error', () => undefined);
    child.stdin?.end(JSON.stringify(args.payload));
  });
}
