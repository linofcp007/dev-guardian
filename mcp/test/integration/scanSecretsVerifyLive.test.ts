/**
 * `scan_secrets verify_live` end to end, with gitleaks and every provider
 * faked: gitleaks by a mocked `runProcess` that writes the report it is asked
 * for (raw values unless it was given `--redact`), the providers by a mocked
 * global `fetch`. Nothing here needs gitleaks installed or touches the
 * network; `scanSecretsVerifyLiveGitleaks.test.ts` repeats the core of it
 * against real gitleaks.
 *
 * The central test is the sentinel one (ruling 6): a distinct value per path
 * — live, revoked, unknown, a network error whose text carries the value, a
 * provider that echoes the value back in its error body, and a rule with no
 * verifier — and the value must appear nowhere: not in the tool result, not
 * anywhere in the database once it is read back, not in any report on disk,
 * not on stdout/stderr, the console or a progress notification.
 */

import { existsSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

vi.setConfig({ testTimeout: 60_000 });

vi.mock('../../src/runners/processRunner.js', () => ({ runProcess: vi.fn() }));
vi.mock('../../src/tools/scanHelpers.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../src/tools/scanHelpers.js')>();
  return { ...actual, scannerAvailable: vi.fn() };
});

import type { PluginContext } from '../../src/context.js';
import { runProcess, type ProcessRunOptions, type ProcessRunResult } from '../../src/runners/processRunner.js';
import { GuardianDatabase as Database } from '../../src/storage/db.js';
import { runMigrations } from '../../src/storage/migrations/runner.js';
import { Storage } from '../../src/storage/index.js';
import { TOOLS } from '../../src/tools/index.js';
import { scannerAvailable } from '../../src/tools/scanHelpers.js';
import type { Finding } from '../../src/types.js';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';

afterAll(cleanupTempDirs);
beforeAll(async () => {
  await import('../../src/tools/scanSecrets.js');
});

/** A value no provider, path or message would ever contain by chance. */
function sentinel(prefix: string, sep: string, marker: string): string {
  return [prefix, `QX${marker}SENTINEL${'k'.repeat(24)}`].join(sep);
}
const S = {
  live: sentinel('ghp', '_', 'LIVE'),
  revoked: sentinel('npm', '_', 'REVOKED'),
  unknown: sentinel('sk_live', '_', 'UNKNOWN'),
  network: sentinel('sk-proj', '-', 'NETWORK'),
  echoed: sentinel('sk-ant-api03', '-', 'ECHOED'),
  slackEcho: sentinel(['xoxb', '1234567890', '1234567890123'].join('-'), '-', 'SLACKECHO'),
  unsupported: sentinel('AKIA', '', 'UNSUPPORTED'),
};
const ALL = Object.values(S);

interface ReportItem {
  rule: string;
  secret: string;
  file: string;
}

let reportItems: ReportItem[] = [];
interface GitleaksCall {
  args: string[];
  reportPath: string | undefined;
  redacted: boolean;
  dirMode: number | null;
  fileMode: number | null;
}
let gitleaksCalls: GitleaksCall[] = [];

/** gitleaks: writes one report item per `reportItems` entry, raw unless `--redact`. */
async function fakeGitleaks(opts: ProcessRunOptions): Promise<ProcessRunResult> {
  const args = opts.args ?? [];
  const reportPath = args.find((a) => a.startsWith('--report-path='))?.slice('--report-path='.length);
  const redacted = args.includes('--redact');
  const call: GitleaksCall = { args, reportPath, redacted, dirMode: null, fileMode: null };
  if (reportPath !== undefined) {
    if (existsSync(reportPath)) call.fileMode = statSync(reportPath).mode & 0o777;
    call.dirMode = statSync(dirname(reportPath)).mode & 0o777;
    const items = reportItems.map((i, n) => ({
      RuleID: i.rule,
      Description: `rule ${i.rule}`,
      StartLine: n + 1,
      EndLine: n + 1,
      StartColumn: 1,
      EndColumn: 10,
      Match: `key = "${redacted ? 'REDACTED' : i.secret}"`,
      Secret: redacted ? 'REDACTED' : i.secret,
      File: i.file,
      Commit: '',
      Fingerprint: `${i.file}:${i.rule}:${n + 1}`,
    }));
    writeFileSync(reportPath, JSON.stringify(items));
  }
  gitleaksCalls.push(call);
  return { outcome: 'completed', exitCode: reportItems.length > 0 ? 1 : 0, stdout: '', stderr: 'INF scanned ~120 bytes', truncated: false };
}

interface FetchCall {
  host: string;
  url: string;
  headers: Record<string, string>;
}
let fetchCalls: FetchCall[] = [];

function reply(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
}

/** Each provider answers the way the sentinel's path says. */
async function fakeFetch(input: string | URL | Request, init?: RequestInit): Promise<Response> {
  const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
  const headers: Record<string, string> = {};
  new Headers(init?.headers).forEach((v, k) => {
    headers[k] = v;
  });
  const host = new URL(url).host;
  fetchCalls.push({ host, url, headers });
  const sent = JSON.stringify(headers);
  if (sent.includes(S.live)) return reply(200, { login: 'octocat' });
  if (sent.includes(S.revoked)) return reply(401, { error: 'invalid token' });
  if (sent.includes(S.unknown)) return reply(500, { error: { message: `server error for ${S.unknown}` } });
  if (sent.includes(S.network)) {
    throw Object.assign(new TypeError(`fetch failed: ${S.network}`), {
      cause: Object.assign(new Error(`connect ECONNREFUSED ${S.network}`), { code: 'ECONNREFUSED' }),
    });
  }
  if (sent.includes(S.echoed)) {
    return reply(401, { type: 'error', error: { type: 'authentication_error', message: `invalid x-api-key ${S.echoed}` } });
  }
  if (sent.includes(S.slackEcho)) return reply(200, { ok: false, error: 'invalid_auth', token: S.slackEcho });
  return reply(418, {});
}

function plugin(project: string): { plugin: PluginContext; db: Database; progress: string[] } {
  const db = new Database(':memory:');
  runMigrations(db);
  const progress: string[] = [];
  return {
    db,
    progress,
    plugin: {
      storage: new Storage(db),
      shell: null,
      scriptsDir: project,
      progressNotifier: { send: (p) => progress.push(JSON.stringify(p)) },
    },
  };
}

function tool() {
  const t = TOOLS.find((x) => x.name === 'scan_secrets');
  if (!t) throw new Error('scan_secrets not registered');
  return t;
}

/** Every row of every table, as text. */
function dumpDb(db: Database): string {
  const tables = db
    .prepare<[], { name: string }>("SELECT name FROM sqlite_master WHERE type = 'table'")
    .all()
    .map((r) => r.name);
  return tables.map((t) => JSON.stringify(db.prepare(`SELECT * FROM "${t}"`).all())).join('\n');
}

/** Every file under `dir`, as text. */
function dumpFiles(dir: string): string {
  if (!existsSync(dir)) return '';
  const out: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true, recursive: true })) {
    if (entry.isFile()) out.push(readFileSync(join(entry.parentPath, entry.name), 'utf8'));
  }
  return out.join('\n');
}

function verifyDirs(): Set<string> {
  return new Set(readdirSync(tmpdir()).filter((n) => n.startsWith('guardian-verify-')));
}

beforeEach(() => {
  reportItems = [];
  gitleaksCalls = [];
  fetchCalls = [];
  vi.mocked(scannerAvailable).mockReset();
  vi.mocked(scannerAvailable).mockResolvedValue('/fake/bin/gitleaks');
  vi.mocked(runProcess).mockReset();
  vi.mocked(runProcess).mockImplementation(fakeGitleaks);
  vi.stubGlobal('fetch', vi.fn(fakeFetch));
  vi.stubEnv('GUARDIAN_OFFLINE', '0');
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
});

interface Summary {
  live: number;
  revoked: number;
  unknown: number;
  skipped: number;
  verified: number;
  distinct_secrets_sent: number;
  hosts_contacted: string[];
  findings: Array<{ rule_id: string; verified: string; reason: string; fingerprint: string }>;
}

describe('scan_secrets verify_live', () => {
  it('is off by default: gitleaks keeps --redact, reports stay in the project, nothing is sent', async () => {
    const dir = makeTempDir('verify-off-');
    reportItems = [{ rule: 'github-pat', secret: S.live, file: 'app.env' }];
    const { plugin: p } = plugin(dir);
    const r = await tool().handler({ project_path: dir, force: true }, p);
    expect(r.ok).toBe(true);
    expect(gitleaksCalls.length).toBeGreaterThan(0);
    for (const c of gitleaksCalls) {
      expect(c.redacted).toBe(true);
      expect(c.reportPath?.startsWith(join(dir, '.guardian'))).toBe(true);
    }
    expect(fetchCalls).toHaveLength(0);
    expect((r as Record<string, unknown>)['secret_verification']).toBeUndefined();
  });

  it('sends a live secret to its own provider only, raises it to critical with rotation guidance', async () => {
    const dir = makeTempDir('verify-live-');
    reportItems = [
      { rule: 'github-pat', secret: S.live, file: 'app.env' },
      { rule: 'aws-access-token', secret: S.unsupported, file: 'aws.env' },
    ];
    const { plugin: p } = plugin(dir);
    const before = verifyDirs();
    const r = await tool().handler({ project_path: dir, force: true, verify_live: true }, p);
    expect(r.ok).toBe(true);
    const res = r as unknown as { scan_id: string; secret_verification: Summary; warnings: string[] };

    // gitleaks wrote raw values only into a private temporary directory, now gone.
    expect(gitleaksCalls.length).toBeGreaterThan(0);
    for (const c of gitleaksCalls) {
      expect(c.redacted).toBe(false);
      expect(c.reportPath?.startsWith(dir)).toBe(false);
      expect(c.reportPath === undefined ? '' : dirname(c.reportPath)).toMatch(/guardian-verify-/);
      if (process.platform !== 'win32') {
        expect(c.dirMode).toBe(0o700);
        expect(c.fileMode).toBe(0o600);
      }
      expect(c.reportPath !== undefined && existsSync(dirname(c.reportPath))).toBe(false);
    }
    expect([...verifyDirs()].filter((d) => !before.has(d))).toEqual([]);

    // Exactly one request, to api.github.com, carrying the GitHub token.
    expect(fetchCalls.map((c) => c.url)).toEqual(['https://api.github.com/user']);
    expect(fetchCalls[0]?.headers['authorization']).toBe(`Bearer ${S.live}`);

    const found = p.storage.findings.listByScan(res.scan_id);
    const gh = found.find((f: Finding) => f.rule_id === 'github-pat');
    expect(gh?.severity).toBe('critical');
    expect(gh?.message).toMatch(/verified: live/);
    expect(gh?.message).toMatch(/github\.com\/settings/);
    const aws = found.find((f: Finding) => f.rule_id === 'aws-access-token');
    expect(aws?.severity).toBe('high');

    const s = res.secret_verification;
    expect(s).toMatchObject({ live: 1, revoked: 0, unknown: 0, skipped: 1, verified: 1, distinct_secrets_sent: 1 });
    expect(s.hosts_contacted).toEqual(['api.github.com']);
    expect(s.findings.map((f) => [f.rule_id, f.verified])).toEqual([['github-pat', 'live']]);
    expect(s.findings[0]?.fingerprint).toBe(gh?.fingerprint);
    expect(res.warnings.some((w) => /LIVE/.test(w) && /rotate/i.test(w))).toBe(true);
    expect(res.warnings.some((w) => /sent/.test(w) && /api\.github\.com/.test(w))).toBe(true);
  });

  it('the finding keeps its identity and fingerprint: verified and unverified scans agree', async () => {
    const dir = makeTempDir('verify-identity-');
    reportItems = [{ rule: 'github-pat', secret: S.live, file: 'app.env' }];
    const plain = plugin(dir);
    const a = (await tool().handler({ project_path: dir, force: true }, plain.plugin)) as unknown as { scan_id: string };
    const verified = plugin(dir);
    const b = (await tool().handler({ project_path: dir, force: true, verify_live: true }, verified.plugin)) as unknown as {
      scan_id: string;
    };
    const fa = plain.plugin.storage.findings.listByScan(a.scan_id);
    const fb = verified.plugin.storage.findings.listByScan(b.scan_id);
    expect(fb.map((f) => [f.fingerprint, f.identity, f.content_key])).toEqual(fa.map((f) => [f.fingerprint, f.identity, f.content_key]));
    expect(fb[0]?.severity).toBe('critical');
    expect(fa[0]?.severity).toBe('high');
  });

  it('SENTINEL: no raw value reaches the result, the database, a report, a log or a progress message', async () => {
    const dir = makeTempDir('verify-sentinel-');
    reportItems = [
      { rule: 'github-pat', secret: S.live, file: 'a.env' },
      { rule: 'npm-access-token', secret: S.revoked, file: 'b.env' },
      { rule: 'stripe-access-token', secret: S.unknown, file: 'c.env' },
      { rule: 'openai-api-key', secret: S.network, file: 'd.env' },
      { rule: 'anthropic-api-key', secret: S.echoed, file: 'e.env' },
      { rule: 'slack-bot-token', secret: S.slackEcho, file: 'f.env' },
      { rule: 'aws-access-token', secret: S.unsupported, file: 'g.env' },
      // The same live value twice: verified once.
      { rule: 'github-pat', secret: S.live, file: 'h.env' },
    ];
    const captured: string[] = [];
    const grab =
      (stream: 'stdout' | 'stderr') =>
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
    const { plugin: p, db, progress } = plugin(dir);
    let result: unknown;
    let cached: unknown;
    try {
      result = await tool().handler({ project_path: dir, force: true, verify_live: true }, p, { progressToken: 'sentinel' });
      // A cache hit re-emits what the run stored: it must be as clean.
      cached = await tool().handler({ project_path: dir, verify_live: true }, p, { progressToken: 'sentinel-2' });
    } finally {
      out.mockRestore();
      err.mockRestore();
      for (const s of consoleSpies) s.mockRestore();
    }

    const res = result as { ok: boolean; scan_id: string; secret_verification: Summary };
    expect(res.ok).toBe(true);
    expect((cached as { cached?: boolean }).cached).toBe(true);

    // Every path was taken.
    const verdicts = Object.fromEntries(res.secret_verification.findings.map((f) => [f.rule_id, f.verified]));
    expect(verdicts).toEqual({
      'github-pat': 'live',
      'npm-access-token': 'revoked',
      'stripe-access-token': 'unknown',
      'openai-api-key': 'unknown',
      'anthropic-api-key': 'revoked',
      'slack-bot-token': 'revoked',
    });
    expect(res.secret_verification).toMatchObject({ live: 2, revoked: 3, unknown: 2, skipped: 1, distinct_secrets_sent: 6 });

    // Each value went to its own provider and nowhere else; the unsupported one to nobody.
    const expectedHost: Record<string, string> = {
      [S.live]: 'api.github.com',
      [S.revoked]: 'registry.npmjs.org',
      [S.unknown]: 'api.stripe.com',
      [S.network]: 'api.openai.com',
      [S.echoed]: 'api.anthropic.com',
      [S.slackEcho]: 'slack.com',
    };
    for (const c of fetchCalls) {
      const carried = ALL.filter((v) => JSON.stringify(c.headers).includes(v));
      expect(carried).toHaveLength(1);
      const value = carried[0] ?? '';
      expect(c.host).toBe(expectedHost[value]);
      expect(c.url).not.toContain(value);
    }
    expect(fetchCalls.some((c) => JSON.stringify(c.headers).includes(S.unsupported))).toBe(false);

    const haystacks: Record<string, string> = {
      result: JSON.stringify(result),
      cached: JSON.stringify(cached),
      database: dumpDb(db),
      reports: dumpFiles(join(dir, '.guardian')),
      logs: captured.join('\n'),
      progress: progress.join('\n'),
    };
    // The database really was read back (not an empty dump).
    expect(haystacks['database']).toContain('github-pat');
    expect(haystacks['reports']).toContain('github-pat');
    for (const [where, text] of Object.entries(haystacks)) {
      for (const value of ALL) expect(text.includes(value), `${where} holds ${value.slice(0, 12)}…`).toBe(false);
      // Not even the distinctive middle of one.
      expect(text.includes('SENTINEL'), `${where} holds a sentinel fragment`).toBe(false);
    }
  });

  it('beyond the per-scan limit: unknown "not verified: per-scan limit", never sent', async () => {
    const dir = makeTempDir('verify-cap-');
    reportItems = Array.from({ length: 55 }, (_, i) => ({
      rule: 'npm-access-token',
      secret: `${S.revoked}${String(i).padStart(2, '0')}`,
      file: `f${i}.env`,
    }));
    const { plugin: p } = plugin(dir);
    const r = (await tool().handler({ project_path: dir, force: true, verify_live: true }, p)) as unknown as {
      secret_verification: Summary;
    };
    expect(fetchCalls).toHaveLength(50);
    expect(r.secret_verification).toMatchObject({ revoked: 50, unknown: 5 });
    expect(r.secret_verification.findings.filter((f) => /per-scan limit/.test(f.reason))).toHaveLength(5);
  });

  it('GUARDIAN_OFFLINE=1: gitleaks keeps --redact, nothing is sent, supported findings are unknown', async () => {
    vi.stubEnv('GUARDIAN_OFFLINE', '1');
    const dir = makeTempDir('verify-offline-');
    reportItems = [{ rule: 'github-pat', secret: S.live, file: 'app.env' }];
    const { plugin: p } = plugin(dir);
    const r = (await tool().handler({ project_path: dir, force: true, verify_live: true }, p)) as unknown as {
      secret_verification: Summary;
    };
    for (const c of gitleaksCalls) expect(c.redacted).toBe(true);
    expect(fetchCalls).toHaveLength(0);
    expect(r.secret_verification).toMatchObject({ live: 0, unknown: 1, distinct_secrets_sent: 0 });
    expect(r.secret_verification.findings[0]?.reason).toMatch(/GUARDIAN_OFFLINE/);
  });

  it('does not verify what .guardianignore excludes — an excluded secret is never sent', async () => {
    const dir = makeTempDir('verify-ignore-');
    writeFileSync(join(dir, '.guardianignore'), 'fixtures/\n');
    reportItems = [
      { rule: 'github-pat', secret: S.live, file: 'fixtures/fake.env' },
      { rule: 'npm-access-token', secret: S.revoked, file: 'real.env' },
    ];
    // isProjectPath needs the files to exist for the exclusion to apply.
    mkdirSync(join(dir, 'fixtures'), { recursive: true });
    writeFileSync(join(dir, 'fixtures', 'fake.env'), 'x');
    writeFileSync(join(dir, 'real.env'), 'x');
    const { plugin: p } = plugin(dir);
    await tool().handler({ project_path: dir, force: true, verify_live: true }, p);
    expect(fetchCalls.map((c) => c.host)).toEqual(['registry.npmjs.org']);
  });

  it('verify_live is part of the cache key: a plain scan is never served for a verifying call', async () => {
    const dir = makeTempDir('verify-cache-');
    reportItems = [{ rule: 'github-pat', secret: S.live, file: 'app.env' }];
    const { plugin: p } = plugin(dir);
    await tool().handler({ project_path: dir }, p);
    const r = (await tool().handler({ project_path: dir, verify_live: true }, p)) as { cached?: boolean };
    expect(r.cached).toBeUndefined();
    expect(fetchCalls).toHaveLength(1);
  });
});
