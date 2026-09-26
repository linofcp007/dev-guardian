/**
 * `scan_secrets verify_live` against REAL gitleaks — the part the faked
 * suite (`scanSecretsVerifyLive.test.ts`) cannot prove: that a real gitleaks
 * report, written without `--redact` into the private directory, yields the
 * exact value the provider needs, from the history pass and the files pass
 * alike, and that the value then reaches nothing but the provider's request.
 *
 * Providers are a mocked global `fetch`; no request leaves the machine.
 * gitleaks is found on PATH; without it every test here is SKIPPED (visibly).
 */

import { execa } from 'execa';
import { randomBytes } from 'node:crypto';
import { existsSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

/**
 * Every scanner stderr line reaches the factory's `onLog`, which hands it to
 * `progress.note`; every boundary message goes through `progress.emit`. Both
 * are recorded here, so what onLog saw is asserted, not just what a
 * heartbeat happened to send.
 */
const progressLog = vi.hoisted(() => ({ lines: [] as string[] }));
vi.mock('../../src/progress/progressEmitter.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../src/progress/progressEmitter.js')>();
  return {
    ...actual,
    makeProgressEmitter: (opts: Parameters<typeof actual.makeProgressEmitter>[0]) => {
      const inner = actual.makeProgressEmitter(opts);
      return {
        emit: (input: Parameters<typeof inner.emit>[0]) => {
          progressLog.lines.push(`emit:${input.message ?? ''}`);
          inner.emit(input);
        },
        note: (message: string) => {
          progressLog.lines.push(`note:${message}`);
          inner.note(message);
        },
        dispose: () => inner.dispose(),
      };
    },
  };
});

/**
 * The private directories the scan itself opens — checked by name afterwards
 * (a listing of the temp dir would also see other test files' scans).
 */
const opened = vi.hoisted(() => ({ dirs: [] as string[] }));
vi.mock('../../src/secrets/verify/rawReport.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../src/secrets/verify/rawReport.js')>();
  return {
    ...actual,
    openPrivateReportDir: () => {
      const dir = actual.openPrivateReportDir();
      opened.dirs.push(dir.dir);
      return dir;
    },
  };
});

import type { PluginContext } from '../../src/context.js';
import { GuardianDatabase as Database } from '../../src/storage/db.js';
import { runMigrations } from '../../src/storage/migrations/runner.js';
import { Storage } from '../../src/storage/index.js';
import { TOOLS } from '../../src/tools/index.js';
import { resetScannerCache } from '../../src/tools/scanHelpers.js';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';
import { isInstalled } from '../helpers/toolchain.js';

vi.setConfig({ testTimeout: 120_000 });

const GITLEAKS = await isInstalled('gitleaks');

const ALNUM = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
/** A fresh, high-entropy GitHub-PAT-shaped value gitleaks' `github-pat` rule reports. */
function githubToken(): string {
  return ['ghp', Array.from(randomBytes(36), (b) => ALNUM[b % ALNUM.length]).join('')].join('_');
}

afterAll(cleanupTempDirs);
beforeAll(async () => {
  await import('../../src/tools/scanSecrets.js');
  resetScannerCache();
});

let sent: Array<{ url: string; authorization: string | null }> = [];
beforeEach(() => {
  sent = [];
  vi.stubEnv('GUARDIAN_OFFLINE', '0');
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
      sent.push({ url, authorization: new Headers(init?.headers).get('authorization') });
      return new Response(JSON.stringify({ login: 'octocat' }), { status: 200 });
    }),
  );
});
afterEach(() => {
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
});

function plugin(project: string): { plugin: PluginContext; db: Database } {
  const db = new Database(':memory:');
  runMigrations(db);
  return {
    db,
    plugin: { storage: new Storage(db), shell: null, scriptsDir: project, progressNotifier: { send: () => {} } },
  };
}

async function git(cwd: string, ...args: string[]): Promise<void> {
  await execa('git', args, { cwd });
}

function dumpFiles(dir: string): string {
  if (!existsSync(dir)) return '';
  return readdirSync(dir, { withFileTypes: true, recursive: true })
    .filter((e) => e.isFile())
    .map((e) => readFileSync(join(e.parentPath, e.name), 'utf8'))
    .join('\n');
}

function dumpDb(db: Database): string {
  return db
    .prepare<[], { name: string }>("SELECT name FROM sqlite_master WHERE type = 'table'")
    .all()
    .map((t) => JSON.stringify(db.prepare(`SELECT * FROM "${t.name}"`).all()))
    .join('\n');
}

describe.skipIf(!GITLEAKS)('scan_secrets verify_live with real gitleaks', () => {
  it('verifies a committed and an uncommitted token, and neither value is kept anywhere', async () => {
    const committed = githubToken();
    const uncommitted = githubToken();
    const dir = makeTempDir('verify-real-');
    await git(dir, 'init', '-q');
    await git(dir, 'config', 'user.email', 'guardian-test@example.com');
    await git(dir, 'config', 'user.name', 'Guardian Test');
    await git(dir, 'config', 'commit.gpgsign', 'false');
    writeFileSync(join(dir, 'old.env'), `GITHUB_TOKEN=${committed}\n`);
    await git(dir, 'add', 'old.env');
    await git(dir, 'commit', '-q', '-m', 'add token');
    writeFileSync(join(dir, 'new.env'), `GH=${uncommitted}\n`);

    opened.dirs = [];
    const { plugin: p, db } = plugin(dir);
    progressLog.lines = [];
    const captured: string[] = [];
    const grab =
      (stream: string) =>
      (chunk: unknown): boolean => {
        captured.push(`${stream}:${String(chunk)}`);
        return true;
      };
    const out = vi.spyOn(process.stdout, 'write').mockImplementation(grab('stdout') as typeof process.stdout.write);
    const err = vi.spyOn(process.stderr, 'write').mockImplementation(grab('stderr') as typeof process.stderr.write);
    const consoleSpies = (['log', 'info', 'warn', 'error', 'debug'] as const).map((m) =>
      vi.spyOn(console, m).mockImplementation((...a: unknown[]) => {
        captured.push(`console.${m}:${a.map(String).join(' ')}`);
      }),
    );
    let r: Awaited<ReturnType<ReturnType<typeof tool>['handler']>>;
    try {
      r = await tool().handler({ project_path: dir, force: true, verify_live: true }, p, { progressToken: 'real' });
    } finally {
      out.mockRestore();
      err.mockRestore();
      for (const s of consoleSpies) s.mockRestore();
    }
    expect(r.ok).toBe(true);
    // gitleaks' own stderr went through onLog, and so did the verify step's note.
    expect(progressLog.lines.some((l) => /commits? scanned|scanned ~/.test(l))).toBe(true);
    expect(progressLog.lines.some((l) => l.includes('verify_live'))).toBe(true);
    const res = r as unknown as { scan_id: string; coverage: string; secret_verification: { live: number } };
    expect(res.coverage).toBe('full');

    // gitleaks' raw values were read correctly: each went to api.github.com as a Bearer token.
    expect(sent.map((s) => s.url)).toEqual(['https://api.github.com/user', 'https://api.github.com/user']);
    expect(sent.map((s) => s.authorization).sort()).toEqual([`Bearer ${committed}`, `Bearer ${uncommitted}`].sort());

    const found = p.storage.findings.listByScan(res.scan_id);
    // old.env is committed and unmodified, so only the history pass reports it; new.env only the files pass.
    expect(found.map((f) => [f.file_path, f.severity]).sort()).toEqual([
      ['new.env', 'critical'],
      ['old.env', 'critical'],
    ]);
    expect(res.secret_verification.live).toBe(2);

    expect(opened.dirs).toHaveLength(1);
    for (const d of opened.dirs) expect(existsSync(d), d).toBe(false);
    for (const [where, text] of Object.entries({
      result: JSON.stringify(r),
      database: dumpDb(db),
      reports: dumpFiles(join(dir, '.guardian')),
      'progress/onLog': progressLog.lines.join('\n'),
      'stdout/stderr/console': captured.join('\n'),
    })) {
      for (const token of [committed, uncommitted]) {
        expect(text.includes(token), `${where} holds a token`).toBe(false);
        // Not even a clipped part of one (onLog lines are cut at 200 chars).
        expect(text.includes(token.slice(8, 28)), `${where} holds part of a token`).toBe(false);
      }
    }
  });

  it('verifies in a directory that is not a git repository', async () => {
    const token = githubToken();
    const dir = makeTempDir('verify-real-nogit-');
    writeFileSync(join(dir, 'settings.ini'), `token = ${token}\n`);
    const { plugin: p } = plugin(dir);
    const r = await tool().handler({ project_path: dir, force: true, verify_live: true }, p);
    expect(r.ok).toBe(true);
    expect(sent.map((s) => s.authorization)).toEqual([`Bearer ${token}`]);
    expect(JSON.stringify(r)).not.toContain(token);
    expect(dumpFiles(join(dir, '.guardian'))).not.toContain(token);
  });
});

function tool() {
  const t = TOOLS.find((x) => x.name === 'scan_secrets');
  if (!t) throw new Error('scan_secrets not registered');
  return t;
}
