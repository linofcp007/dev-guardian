/**
 * `readSmallJsonFile` / `readSmallTextFile` — how the hook dispatcher (and
 * the install hook's registry-context reader) read a file the project or the
 * user controls. Task 23 fix round 2, N1: `readJsonFile` did `existsSync` and a
 * synchronous read with no check on what the path was, so a FIFO or a link to
 * `/dev/zero` at `.guardian/hooks.config.json` blocked the hook until Claude
 * Code killed it at its 15 s timeout — and the tool call then ran unguarded.
 */

import { spawn, spawnSync } from 'node:child_process';
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, unlinkSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { MAX_HOOK_CONFIG_BYTES, readSmallJsonFile, readSmallTextFile } from '../../../src/hooks/configFile.js';
import { MCP_ROOT, TSX_NODE_ARGS } from '../../helpers/tsxNode.js';

const POSIX = process.platform !== 'win32';
const IS_ROOT = typeof process.getuid === 'function' && process.getuid() === 0;

/**
 * Whether this account can be denied reading a file it owns: not as root,
 * and not as an elevated Windows administrator, whose backup privilege lets
 * libuv's open (FILE_FLAG_BACKUP_SEMANTICS) read past a deny ACE — probed,
 * not assumed.
 */
const CAN_DENY_READ = ((): boolean => {
  if (POSIX) return !IS_ROOT;
  const probe = mkdtempSync(join(tmpdir(), 'hook-config-deny-probe-'));
  const f = join(probe, 'f');
  try {
    writeFileSync(f, 'x');
    if (spawnSync('icacls', [f, '/deny', '*S-1-1-0:(R)']).status !== 0) return false;
    try {
      readFileSync(f);
      return false;
    } catch {
      return true;
    }
  } finally {
    spawnSync('icacls', [f, '/remove:d', '*S-1-1-0']);
    rmSync(probe, { recursive: true, force: true });
  }
})();

/** Whether this account may create symlinks (Windows needs admin or Developer Mode). */
const CAN_SYMLINK = ((): boolean => {
  const probe = mkdtempSync(join(tmpdir(), 'hook-config-symlink-probe-'));
  try {
    writeFileSync(join(probe, 't'), 'x');
    symlinkSync(join(probe, 't'), join(probe, 'l'));
    return true;
  } catch {
    return false;
  } finally {
    rmSync(probe, { recursive: true, force: true });
  }
})();

/**
 * Runs the reader in a CHILD process, `iterations` times on `path`, and
 * resolves with the status counts and the milliseconds the reads themselves
 * took (measured inside the child, so a slow child start under a loaded
 * machine is not mistaken for a slow read) — or `timedOut` when the child had
 * to be killed. A reader that blocks would otherwise hang the test worker
 * itself: a synchronous read cannot be interrupted from inside the process.
 */
function readInChild(
  path: string,
  iterations: number,
  timeoutMs: number,
): Promise<{ timedOut: boolean; code: number | null; counts: Record<string, number>; readMs: number }> {
  const script = join(dir, 'reader.mjs');
  const moduleUrl = pathToFileURL(resolve(MCP_ROOT, 'src', 'hooks', 'configFile.ts')).href;
  writeFileSync(
    script,
    `import { readSmallJsonFile } from ${JSON.stringify(moduleUrl)};\n` +
      'const [path, n] = process.argv.slice(2);\n' +
      'const counts = {};\n' +
      'const t0 = Date.now();\n' +
      'for (let i = 0; i < Number(n); i++) {\n' +
      '  const r = readSmallJsonFile(path);\n' +
      "  const key = r.status === 'refused' ? `refused:${r.reason}` : r.status;\n" +
      '  counts[key] = (counts[key] ?? 0) + 1;\n' +
      '}\n' +
      'process.stdout.write(JSON.stringify({ counts, readMs: Date.now() - t0 }));\n',
  );
  return new Promise((done) => {
    const child = spawn(process.execPath, [...TSX_NODE_ARGS, script, path, String(iterations)], {
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let out = '';
    child.stdout.on('data', (d: Buffer) => {
      out += d.toString('utf8');
    });
    const timer = setTimeout(() => {
      child.kill('SIGKILL');
      done({ timedOut: true, code: null, counts: {}, readMs: Number.NaN });
    }, timeoutMs);
    child.on('exit', (code) => {
      clearTimeout(timer);
      let parsed: { counts: Record<string, number>; readMs: number } = { counts: {}, readMs: Number.NaN };
      try {
        parsed = JSON.parse(out) as typeof parsed;
      } catch {
        /* reported through the assertions below */
      }
      done({ timedOut: false, code, ...parsed });
    });
  });
}

let dir: string;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'hook-config-file-'));
});
afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

describe('readSmallJsonFile', () => {
  it('caps a hook config file at 64 KiB', () => {
    expect(MAX_HOOK_CONFIG_BYTES).toBe(64 * 1024);
  });

  it('reads a small regular JSON file', () => {
    const p = join(dir, 'a.json');
    writeFileSync(p, '{"secrets":{"block":true}}');
    expect(readSmallJsonFile(p)).toEqual({ status: 'ok', value: { secrets: { block: true } } });
  });

  it('strips a leading UTF-8 byte-order mark (PowerShell 5 writes one)', () => {
    const p = join(dir, 'bom.json');
    writeFileSync(p, '\uFEFF{"enabled":true}', 'utf8');
    expect(readSmallJsonFile(p)).toEqual({ status: 'ok', value: { enabled: true } });
  });

  it('a missing path is absent', () => {
    expect(readSmallJsonFile(join(dir, 'nope.json'))).toEqual({ status: 'absent' });
  });

  it('a file of exactly the cap is read; one byte more is refused as too large', () => {
    const exact = join(dir, 'exact.json');
    const body = '{"pad":"' + 'x'.repeat(MAX_HOOK_CONFIG_BYTES - 10) + '"}';
    expect(Buffer.byteLength(body)).toBe(MAX_HOOK_CONFIG_BYTES);
    writeFileSync(exact, body);
    expect(readSmallJsonFile(exact).status).toBe('ok');

    const over = join(dir, 'over.json');
    writeFileSync(over, body + ' ');
    expect(readSmallJsonFile(over)).toMatchObject({ status: 'refused', reason: 'too-large' });
  });

  it('a directory is refused, not read', () => {
    const p = join(dir, 'hooks.config.json');
    mkdirSync(p);
    expect(readSmallJsonFile(p)).toMatchObject({ status: 'refused', reason: 'not-a-regular-file' });
  });

  it('a small regular file that is not JSON is invalid', () => {
    const p = join(dir, 'broken.json');
    writeFileSync(p, '{"enabled": fal');
    expect(readSmallJsonFile(p)).toEqual({ status: 'invalid' });
  });

  it.skipIf(!POSIX)('a FIFO is refused at once, never opened (POSIX only: Windows has no FIFOs)', () => {
    const p = join(dir, 'hooks.config.json');
    const made = spawnSync('mkfifo', [p]);
    expect(made.status).toBe(0);
    const t0 = Date.now();
    expect(readSmallJsonFile(p)).toMatchObject({ status: 'refused', reason: 'not-a-regular-file' });
    expect(Date.now() - t0).toBeLessThan(1000);
  });

  it.skipIf(!POSIX)('a symlink to /dev/zero is refused (POSIX only: Windows has no /dev/zero)', () => {
    const p = join(dir, 'hooks.config.json');
    symlinkSync('/dev/zero', p);
    const t0 = Date.now();
    expect(readSmallJsonFile(p)).toMatchObject({ status: 'refused', reason: 'not-a-regular-file' });
    expect(Date.now() - t0).toBeLessThan(1000);
  });

  it('a symlink to a small regular file is followed and read', () => {
    const target = join(dir, 'real.json');
    writeFileSync(target, '{"a":1}');
    const link = join(dir, 'link.json');
    try {
      symlinkSync(target, link);
    } catch {
      return; // Windows without the symlink privilege: nothing to check here
    }
    expect(readSmallJsonFile(link)).toEqual({ status: 'ok', value: { a: 1 } });
  });
});

// Task 23 fix round 3: the round-2 reader stat'ed the PATH and then read it,
// which left two holes — a Windows symlink to a named pipe (stat says a
// 0-byte regular file; the read blocks for ever) and, on POSIX, the path
// swapped for a FIFO between the stat and the read. The reader now opens
// the path (non-blocking where the OS has O_NONBLOCK), fstat's what it
// OPENED, and reads at most cap + 1 bytes from that descriptor.
describe('readSmallJsonFile — what it opened, not what the path said', () => {
  it.skipIf(!CAN_SYMLINK)('a symlink to a regular file over the cap is refused as too large (skipped: no symlink rights)', () => {
    const big = join(dir, 'big.json');
    writeFileSync(big, `{"pad":"${'x'.repeat(MAX_HOOK_CONFIG_BYTES)}"}`);
    const link = join(dir, 'hooks.config.json');
    symlinkSync(big, link);
    expect(readSmallJsonFile(link)).toMatchObject({ status: 'refused', reason: 'too-large' });
  });

  it.skipIf(!CAN_DENY_READ)('a file this account may not read is refused as unreadable (skipped for root and elevated Windows administrators, who read past the denial)', () => {
    const p = join(dir, 'hooks.config.json');
    writeFileSync(p, '{"enabled":false}');
    if (POSIX) {
      chmodSync(p, 0o000);
    } else {
      // Deny read to Everyone (S-1-1-0) — an explicit deny binds administrators too.
      expect(spawnSync('icacls', [p, '/deny', '*S-1-1-0:(R)']).status).toBe(0);
    }
    try {
      expect(readSmallJsonFile(p)).toMatchObject({ status: 'refused', reason: 'unreadable' });
    } finally {
      if (POSIX) chmodSync(p, 0o600);
      else spawnSync('icacls', [p, '/remove:d', '*S-1-1-0']);
    }
  });

  it.skipIf(POSIX || !CAN_SYMLINK)(
    'a symlink to a Windows named pipe is refused at once, never read (Windows only; skipped without symlink rights)',
    async () => {
      const pipe = `\\\\.\\pipe\\dev-guardian-test-${process.pid}-${Date.now()}`;
      const server = createServer(() => {
        /* accepts, never writes */
      });
      await new Promise<void>((ok) => server.listen(pipe, ok));
      const link = join(dir, 'hooks.config.json');
      symlinkSync(pipe, link);
      try {
        const r = await readInChild(link, 1, 45_000);
        expect(r.timedOut).toBe(false);
        expect(r.code).toBe(0);
        expect(r.counts).toEqual({ 'refused:not-a-regular-file': 1 });
        expect(r.readMs).toBeLessThan(2000);
      } finally {
        unlinkSync(link);
        server.close();
      }
    },
    60_000,
  );

  it.skipIf(!POSIX)(
    'a path swapped between a regular file, a FIFO and /dev/zero while it is read never hangs the reader (POSIX only)',
    async () => {
      const regular = join(dir, 'regular.json');
      const fifo = join(dir, 'fifo');
      const cfg = join(dir, 'hooks.config.json');
      writeFileSync(regular, '{"secrets":{"block":true}}');
      expect(spawnSync('mkfifo', [fifo]).status).toBe(0);
      symlinkSync(regular, cfg);
      const swapper = spawn(
        'sh',
        ['-c', 'while :; do ln -sfn "$1" "$4"; ln -sfn "$2" "$4"; ln -sfn "$3" "$4"; done', 'sh', regular, fifo, '/dev/zero', cfg],
        { stdio: 'ignore' },
      );
      try {
        const r = await readInChild(cfg, 3000, 45_000);
        expect(r.timedOut).toBe(false);
        expect(r.code).toBe(0);
        expect(r.readMs).toBeLessThan(20_000);
        const total = Object.values(r.counts).reduce((a, b) => a + b, 0);
        expect(total).toBe(3000);
        const unexpected = Object.keys(r.counts).filter(
          (k) => !['ok', 'absent', 'refused:not-a-regular-file'].includes(k),
        );
        expect(unexpected).toEqual([]);
      } finally {
        swapper.kill('SIGKILL');
      }
    },
    60_000,
  );
});

describe('readSmallTextFile', () => {
  it('reads a small file, and returns undefined past its cap or for a non-file', () => {
    const p = join(dir, '.npmrc');
    writeFileSync(p, 'registry=https://npm.acme.local/\n');
    expect(readSmallTextFile(p, 1024)).toBe('registry=https://npm.acme.local/\n');
    expect(readSmallTextFile(p, 8)).toBeUndefined();
    expect(readSmallTextFile(dir, 1024)).toBeUndefined();
    expect(readSmallTextFile(join(dir, 'missing'), 1024)).toBeUndefined();
  });
});
