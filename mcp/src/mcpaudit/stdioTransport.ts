/**
 * The stdio transport `audit_mcp_tools` starts a server with.
 *
 * The SDK's own `StdioClientTransport` spawns the same way — `cross-spawn`
 * (here through `runners/childProcess.ts`, which uses it), `shell: false`, the SDK's
 * `getDefaultEnvironment()` allowlist plus the entry's own `env` — but its
 * `close()` signals only the direct child, and it hands every message to the
 * client the moment it arrives. Both matter against a server that is not
 * cooperating:
 *
 * ## The process tree
 *
 * A server started as `npx -y pkg`, `uvx pkg` or `cmd /c …` is a launcher
 * with the real server as a GRANDCHILD, and that grandchild would outlive the
 * audit. So this transport owns the process the way
 * `runners/processRunner.ts` does, with the same tree kill
 * (`runners/childProcess.ts`):
 *
 *   - POSIX: spawned `detached`, the leader of its own process group, and
 *     the NEGATIVE pid signals the whole group (SIGTERM, then SIGKILL). A
 *     descendant that calls `setsid()` itself leaves the group and is out of
 *     reach — the same honest limit `processRunner.ts` documents.
 *   - Windows: `taskkill /T /F` plus the MSYS descendants found by the
 *     per-child `GUARDIAN_PROC_TREE_ID` token (`runners/windowsTreeKill.ts`).
 *     `taskkill /T` walks the parent/child table, so it reaches a detached
 *     grandchild (one started outside the job object) only while every
 *     process between it and the root is still alive: a descendant whose
 *     parent has already exited keeps a stale parent pid, is out of reach,
 *     and survives — the Windows counterpart of the POSIX `setsid()` limit
 *     (and one the MSYS token covers only for processes Git Bash started).
 *   - Before any of this, on Windows: a `PATH` entry that looks local but
 *     reaches the network (a mapped drive, a junction to a share) is still
 *     `stat`ed while the command is resolved — off the event loop, bounded
 *     by the deadline, but an SMB request all the same (`launch.ts`).
 *
 * `close()` ALWAYS kills the tree — after a successful listing too: a server
 * that answered is still running, and nothing here needs it afterwards. If
 * this process exits mid-probe, a `signal-exit` hook SIGKILLs the group.
 *
 * ## What the server may send
 *
 * Measured on Windows (fix round 3, C1): a server writing 200 notifications
 * of 1 KB every millisecond after `initialize` starved this process's event
 * loop — a 500 ms heartbeat stretched to 25 s, no timer fired, and a 5 s
 * `timeout_ms` was still running after five minutes (POSIX failed on time).
 * The transport delivered every message synchronously from the pipe's data
 * event, with nothing between them. So:
 *
 *   - after each chunk the pipe is PAUSED, and resumed on `setImmediate`:
 *     one chunk per turn of the event loop, and timers run between turns;
 *   - the deadline is checked inside the data handler, and the transport
 *     closes itself once it has passed;
 *   - an inbound budget — bytes (stdout and stderr together), messages, and
 *     the size of one message — closes it too.
 *
 * Every close the transport decides on itself records {@link closeReason},
 * so the audit reports what happened instead of the process's exit code.
 *
 * The environment is exactly `getDefaultEnvironment()` + the entry's `env`
 * (+ the Windows tree token): `extendEnv: false`, so nothing else of this
 * server's environment — tokens, keys — reaches the third-party process.
 */

import { getDefaultEnvironment } from '@modelcontextprotocol/sdk/client/stdio.js';
import { ReadBuffer, serializeMessage } from '@modelcontextprotocol/sdk/shared/stdio.js';
import type { Transport } from '@modelcontextprotocol/sdk/shared/transport.js';
import type { JSONRPCMessage } from '@modelcontextprotocol/sdk/types.js';
import { startChild, stopTree, type Child } from '../runners/childProcess.js';

export interface StdioLaunch {
  command: string;
  args: string[];
  /** The entry's own `env` — merged over the SDK's minimal default, never over this process's. */
  env: Record<string, string>;
  cwd: string;
}

interface ProcessExit {
  exitCode: number | null;
  signal: string | null;
  /** Set when the process never started (`spawn … ENOENT`). */
  spawnError?: string;
}

/** What one server may send before the transport closes itself. */
interface InboundLimits {
  /** Epoch ms: past it, the transport closes itself from its data handler. */
  deadline: number;
  /** Bytes, stdout and stderr together. */
  maxBytes: number;
  maxMessages: number;
  /** One newline-delimited message. */
  maxMessageBytes: number;
}

const MiB = 1024 * 1024;

/**
 * What real listings need, with a wide margin (fix round 4, measured): the
 * largest listing of the servers launched for the measurement — dev-guardian
 * itself, 58 tools, 14 resources, 6 templates — is 101 KB; playwright-mcp
 * 0.0.82 is 20 KB, server-everything and -filesystem 12-13 KB. 4 MiB per
 * server is 40x the largest, 2 MiB per message 20x; 10 000 messages is far
 * past the handful a listing takes. The first cut (32 MiB, 8 MiB) let a
 * single server hold the analysis for tens of seconds.
 */
export const DEFAULT_INBOUND_LIMITS: Omit<InboundLimits, 'deadline'> = {
  maxBytes: 4 * MiB,
  maxMessages: 10_000,
  maxMessageBytes: 2 * MiB,
};

/** How much of the server's stderr is kept, from the end. */
const STDERR_TAIL_CHARS = 2048;
const TERM_GRACE_MS = 2_000;
const KILL_GRACE_MS = 2_000;

function formatBytes(n: number): string {
  return n % MiB === 0 ? `${n / MiB} MiB` : `${n} bytes`;
}

/** The environment a probed server is started with (the Windows tree token is added when it starts). */
export function probeEnvironment(entryEnv: Record<string, string>): Record<string, string> {
  const base: Record<string, string> = {};
  for (const [k, v] of Object.entries(getDefaultEnvironment())) if (typeof v === 'string') base[k] = v;
  return { ...base, ...entryEnv };
}

export class ProbeStdioTransport implements Transport {
  onclose?: () => void;
  onerror?: (error: Error) => void;
  onmessage?: <T extends JSONRPCMessage>(message: T) => void;

  private child: Child | undefined;
  private done: Promise<void> | undefined;
  private readonly readBuffer: ReadBuffer;
  private stderr = '';
  private exited: ProcessExit | null = null;
  private closing: Promise<void> | null = null;
  private closeNotified = false;
  private bytesIn = 0;
  private messagesIn = 0;
  private selfClosed: string | null = null;

  constructor(
    private readonly launch: StdioLaunch,
    private readonly limits: InboundLimits,
  ) {
    this.readBuffer = new ReadBuffer({ maxBufferSize: limits.maxMessageBytes });
  }

  /** Last {@link STDERR_TAIL_CHARS} characters the server wrote to stderr. */
  get stderrTail(): string {
    return this.stderr;
  }

  /** How the process ended, once it has; null while it runs. */
  get exit(): ProcessExit | null {
    return this.exited;
  }

  /** Why the transport closed itself (a budget, the deadline); null when it did not. */
  get closeReason(): string | null {
    return this.selfClosed;
  }

  async start(): Promise<void> {
    if (this.child !== undefined) throw new Error('ProbeStdioTransport already started');
    // Exactly this environment — nothing else of this server's reaches the
    // third-party process — and SIGKILL for its tree if this process exits first.
    const child = startChild(this.launch.command, this.launch.args, {
      cwd: this.launch.cwd,
      env: probeEnvironment(this.launch.env),
      stdin: 'pipe',
      signalOnParentExit: 'SIGKILL',
    });
    this.child = child;
    const { stdout, stderr, stdin } = child.process;

    stdout?.on('data', (chunk: Buffer | string) => {
      const buf = typeof chunk === 'string' ? Buffer.from(chunk) : chunk;
      if (!this.admit(buf.length)) return;
      stdout.pause();
      try {
        this.readBuffer.append(buf);
      } catch {
        this.fail(`sent a single message larger than ${formatBytes(this.limits.maxMessageBytes)}`);
        return;
      }
      for (;;) {
        let message: JSONRPCMessage | null;
        try {
          message = this.readBuffer.readMessage();
        } catch (e) {
          // A line that is not JSON-RPC (a banner on stdout): reported, skipped.
          this.onerror?.(e as Error);
          continue;
        }
        if (message === null) break;
        this.messagesIn += 1;
        if (this.messagesIn > this.limits.maxMessages) {
          this.fail(`sent more than ${this.limits.maxMessages} messages (the per-server budget)`);
          return;
        }
        this.onmessage?.(message);
        if (this.closing !== null) return;
      }
      this.resumeLater(stdout);
    });
    stderr?.on('data', (chunk: Buffer | string) => {
      const text = chunk.toString();
      if (!this.admit(Buffer.byteLength(text))) return;
      stderr.pause();
      this.stderr = (this.stderr + text).slice(-STDERR_TAIL_CHARS);
      this.resumeLater(stderr);
    });
    stdin?.on('error', (e: Error) => this.onerror?.(e));

    const spawned = new Promise<'spawned'>((resolve) => child.process.once('spawn', () => resolve('spawned')));
    // Resolves after the process has exited AND its pipes have closed, so
    // stderr is complete by then.
    this.done = child.done.then((exit) => {
      this.exited = {
        exitCode: exit.exitCode,
        signal: exit.signal,
        ...(exit.spawnError !== undefined ? { spawnError: exit.spawnError.message } : {}),
      };
      this.notifyClosed();
    });
    const first = await Promise.race([spawned, this.done.then(() => 'ended' as const)]);
    if (first === 'ended' && this.exited?.spawnError !== undefined) {
      throw new Error(`could not start '${this.launch.command}': ${this.exited.spawnError}`);
    }
  }

  /** Counts `bytes` against the budget and checks the deadline; false (and closing) when either is spent. */
  private admit(bytes: number): boolean {
    if (this.closing !== null) return false;
    this.bytesIn += bytes;
    if (this.bytesIn > this.limits.maxBytes) {
      this.fail(`sent more than ${formatBytes(this.limits.maxBytes)} (the per-server budget)`);
      return false;
    }
    if (Date.now() > this.limits.deadline) {
      this.fail('was still sending when its time budget ran out');
      return false;
    }
    return true;
  }

  /** One chunk per turn of the event loop: timers run before the next one is read. */
  private resumeLater(stream: NodeJS.ReadableStream | null | undefined): void {
    setImmediate(() => {
      if (this.closing === null) stream?.resume();
    });
  }

  private fail(reason: string): void {
    this.selfClosed ??= reason;
    this.onerror?.(new Error(reason));
    void this.close();
  }

  send(message: JSONRPCMessage): Promise<void> {
    return new Promise((resolve, reject) => {
      const stdin = this.child?.process.stdin;
      if (stdin === undefined || stdin === null || this.exited !== null || this.closing !== null) {
        reject(new Error('Not connected'));
        return;
      }
      if (stdin.write(serializeMessage(message))) resolve();
      else stdin.once('drain', () => resolve());
    });
  }

  /** Kill the whole tree, wait for it (bounded), then report closed. Idempotent. */
  close(): Promise<void> {
    this.closing ??= this.killAndWait();
    return this.closing;
  }

  private async killAndWait(): Promise<void> {
    const child = this.child;
    if (child === undefined || this.done === undefined) {
      this.notifyClosed();
      return;
    }
    try {
      child.process.stdin?.end();
    } catch {
      /* already closed */
    }
    // Nothing more is read: drain what the pipes hold so the process can exit.
    child.process.stdout?.resume();
    child.process.stderr?.resume();
    // The whole tree: SIGTERM (POSIX group) or taskkill + MSYS (Windows), the
    // kill after TERM_GRACE_MS, and pipes something outside the tree holds
    // abandoned after KILL_GRACE_MS more.
    await stopTree(child, { graceMs: TERM_GRACE_MS, abandonMs: KILL_GRACE_MS });
    this.readBuffer.clear();
    this.notifyClosed();
  }

  private notifyClosed(): void {
    if (this.closeNotified) return;
    this.closeNotified = true;
    this.onclose?.();
  }
}
