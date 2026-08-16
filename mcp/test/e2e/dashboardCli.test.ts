/**
 * End-to-end test of `cli/dev-guardian.mjs`'s `status` and `dashboard`
 * commands, invoked as a REAL SUBPROCESS (`node cli/dev-guardian.mjs ...`) —
 * same reasoning and pattern as `ciCliFixture.test.ts`'s own `runCli`: the
 * exit-code and stdout-flush behaviour these two commands depend on (design
 * doc §6, item 5's `process.exitCode = ...; return;` discipline) cannot be
 * observed from an in-process call.
 *
 * `runCli` gets an explicit `timeout` (the brief's own template omits one) —
 * `spawnSync` blocks the whole worker's event loop until the child exits, so
 * a bug that leaves the CLI subprocess alive (e.g. a browser-opener handle
 * that is not `unref()`d) would hang forever rather than being caught by
 * vitest's own `testTimeout`, which itself needs a free event loop to fire.
 * A generous, fixed bound converts that failure mode into a fast, legible
 * test failure instead of a stuck test run. It never fires on the happy path
 * — these commands touch only a local SQLite file, no scanner, no network.
 */

import { describe, expect, it, beforeAll, afterAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import {
  mkdtempSync, mkdirSync, rmSync, existsSync, readdirSync, readFileSync, renameSync, writeFileSync,
} from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { join, parse, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

// Seeding-only imports, straight from src (TypeScript), exactly like
// ciCliFixture.test.ts's own `detectOs` import from '../../src/...' — used
// ONLY to populate a fixture database directly through the storage layer
// before the CLI-under-test is invoked as its own subprocess against
// mcp/dist/. This is what lets "status on a project with real findings" be
// tested without semgrep/gitleaks/trivy installed.
import { openDatabase, Storage } from '../../src/storage/index.js';

const REPO_ROOT = resolve(fileURLToPath(new URL('../../..', import.meta.url)));
const CLI = resolve(REPO_ROOT, 'cli', 'dev-guardian.mjs');
const TIMEOUT_MS = 15_000;

let project: string;
beforeAll(() => { project = mkdtempSync(join(tmpdir(), 'guardian-dash-')); });
afterAll(() => { rmSync(project, { recursive: true, force: true }); });

function runCli(args: string[]) {
  const r = spawnSync(process.execPath, [CLI, ...args], {
    encoding: 'utf8',
    env: { ...process.env, NO_COLOR: '1' },
    timeout: TIMEOUT_MS,
  });
  return { status: r.status, stdout: r.stdout ?? '', stderr: r.stderr ?? '' };
}

describe('dev-guardian status / dashboard', () => {
  it('status exits 0 and names the scan command on a project with no data', () => {
    const r = runCli(['status', '--project', project]);
    expect(r.status).toBe(0);
    expect(r.stdout).toMatch(/dev-guardian scan/);
    expect(r.stdout).not.toMatch(/undefined|NaN/);
  });

  it('status exits 0 even with findings — it reports, it does not gate', () => {
    // `scan` gates and has exit codes for it. If `status` ever returns 1 on a
    // dirty project, every pipeline that runs it for a summary breaks.
    const r = runCli(['status', '--project', REPO_ROOT]);
    expect(r.status).toBe(0);
  });

  it('dashboard writes a file that parses, and prints its path', () => {
    const out = join(project, 'dash.html');
    const r = runCli(['dashboard', '--project', project, '--out', out, '--no-open']);
    expect(r.status).toBe(0);
    expect(existsSync(out)).toBe(true);
    const html = readFileSync(out, 'utf8');
    const m = html.match(
      /<script type="application\/json" id="guardian-data">([\s\S]*?)<\/script>/);
    expect(m).toBeTruthy();
    expect(() => JSON.parse(m?.[1] ?? '')).not.toThrow();
    expect(r.stdout).toContain(out);
  });

  it('never launches a browser when stdout is not a TTY', () => {
    // spawnSync gives the child a pipe, so this is the piped case by
    // construction. A render that shells out anyway would leave a browser
    // process behind on every CI run that calls it.
    const out = join(project, 'dash2.html');
    const r = runCli(['dashboard', '--project', project, '--out', out]);
    expect(r.status).toBe(0);
    expect(existsSync(out)).toBe(true);
  });

  it('exits 3 naming the flag when --out has no value', () => {
    const r = runCli(['dashboard', '--project', project, '--out']);
    expect(r.status).toBe(3);
    expect(r.stderr).toMatch(/--out/);
  });

  it('exits 3 when --project points nowhere', () => {
    const r = runCli(['status', '--project', join(project, 'nope')]);
    expect(r.status).toBe(3);
  });
});

/* ------------------------------------------------------------------ */
/* Beyond the brief: usage errors this task's own wiring can introduce */
/* ------------------------------------------------------------------ */

describe('dev-guardian status / dashboard — usage errors at each new call site', () => {
  // Each test below targets ONE specific flag-parsing call site this task
  // adds. `takeOperand`/`resolveProjectOrExit` are already proven correct in
  // general (ciCliFixture.test.ts, against `scan`/`baseline`); what is NOT
  // yet proven is that THIS task's own new parse functions actually call them
  // at every site, rather than, say, handling --out but forgetting --project,
  // or accepting an unrecognised flag silently instead of rejecting it.

  it('exits 3 naming the flag when --project has no value (dashboard)', () => {
    const r = runCli(['dashboard', '--project']);
    expect(r.status).toBe(3);
    expect(r.stderr).toMatch(/--project/);
    expect(r.stderr).toMatch(/requires a value/i);
  });

  it('exits 3 naming the flag when --project has no value (status)', () => {
    const r = runCli(['status', '--project']);
    expect(r.status).toBe(3);
    expect(r.stderr).toMatch(/--project/);
    expect(r.stderr).toMatch(/requires a value/i);
  });

  it('exits 3 on an unknown flag to `status`, naming it', () => {
    const r = runCli(['status', '--bogus']);
    expect(r.status).toBe(3);
    expect(r.stderr).toMatch(/--bogus/);
  });

  it('exits 3 on an unknown flag to `dashboard`, naming it', () => {
    const r = runCli(['dashboard', '--bogus']);
    expect(r.status).toBe(3);
    expect(r.stderr).toMatch(/--bogus/);
  });

  // Confirms both commands inherit `asksForHelp()` by being registered the
  // same way as `scan`/`baseline` — the brief's own explicit checklist item.
  // NOTE: `--project` alone would NOT discriminate this — it already appears
  // in today's usage() text for `mcp-config`/`scan`, so a status/dashboard
  // that is still entirely unregistered would still pass a bare `/--project/`
  // check purely because `asksForHelp()` fires generically for ANY command
  // token followed by a help spelling (even a nonexistent one) and the
  // pre-existing help text happens to already contain that substring. Each
  // assertion below instead targets a string that exists ONLY once this
  // task's own usage() additions land: a "dev-guardian.mjs status"/
  // "dev-guardian.mjs dashboard" example line, and dashboard's `--no-open`
  // flag (confirmed absent from today's usage() text before this task).
  it.each(['-h', '--help', 'help'])('`status %s` prints the help text and exits 0', (flag) => {
    const r = runCli(['status', flag]);
    expect(r.status).toBe(0);
    expect(r.stdout).toMatch(/dev-guardian\.mjs status/);
  });

  it.each(['-h', '--help', 'help'])('`dashboard %s` prints the help text and exits 0', (flag) => {
    const r = runCli(['dashboard', flag]);
    expect(r.status).toBe(0);
    expect(r.stdout).toMatch(/dev-guardian\.mjs dashboard/);
    expect(r.stdout).toMatch(/--no-open/);
  });
});

/* ------------------------------------------------------------------ */
/* fix-round-1, Important 2: the --flag=value spelling                 */
/* ------------------------------------------------------------------ */

describe('dev-guardian status / dashboard — accept --flag=value, the same way every sibling command does', () => {
  // Before this fix, `--project=.` / `--out=x.html` were rejected outright
  // as "Unknown flag" (exit 3) on both commands, even though `scan`,
  // `baseline update` and `mcp-config` all accept exactly this spelling for
  // `--project` already. A user's outcome should not depend on which of two
  // equivalent spellings they happened to type.

  it('status --project=<path> is equivalent to --project <path>, not "Unknown flag"', () => {
    const r = runCli(['status', `--project=${project}`]);
    expect(r.status).toBe(0);
    // The load-bearing half of this assertion: the VALUE after "=" must
    // actually be used, not merely tolerated while silently keeping the
    // default cwd. A wrong implementation that recognises the "--project="
    // prefix but never slices/stores what follows it would still exit 0
    // here (a bare status render always does) but would show the WRONG
    // project path — renderStatus's own first line is
    // `dev-guardian · <project_path>`, so the resolved path is always on
    // stdout when the render succeeds.
    expect(r.stdout).toContain(project);
  });

  it('dashboard --project=<path> --out=<path> both work, and --out=... genuinely controls the destination', () => {
    const out = join(project, 'equals-form.html');
    const r = runCli(['dashboard', `--project=${project}`, `--out=${out}`, '--no-open']);
    expect(r.status).toBe(0);
    // Discriminates "the flag is merely accepted" from "the flag's value is
    // used": if --out= were recognised but its value discarded, this would
    // still exit 0 but write to the DEFAULT location
    // (<project>/.guardian/dashboard.html) instead of `out`, and `out`
    // would not exist.
    expect(existsSync(out)).toBe(true);
    expect(r.stdout).toContain(out);
  });
});

/* ------------------------------------------------------------------ */
/* fix-round-2: an EMPTY --out is a clean usage error, not a crash     */
/* ------------------------------------------------------------------ */

describe('dev-guardian dashboard — an empty --out is refused clearly, not left to crash downstream', () => {
  // A regression fix-round-1 itself introduced: `opts.out ?? defaultPath`
  // does not catch `''` (only `null`/`undefined`), so an empty --out used
  // to sail past that check, resolve to `resolve('')` (the CURRENT WORKING
  // DIRECTORY), and only fail much later when writeFileSync tried to open
  // that directory as a file — "EISDIR: ... open '<cwd>'", naming an
  // unrelated directory instead of the flag the user actually got wrong.
  // Confirmed directly before this fix (both spellings): exit 3 either way,
  // but the message pointed at a directory path, never at "--out".
  //
  // Both the equals form (--out=) AND the two-token form (--out '') are
  // covered — the ORIGINAL report from fix-round-1 only reasoned about the
  // equals form; the two-token form had the identical gap for the identical
  // reason (takeOperand's own requireNonEmpty was not passed for --out's
  // space form either) and was found by re-auditing every --out call site,
  // not just the one named in review.

  it('exits 3 naming --out, not a filesystem path, when --out= is empty', () => {
    const r = runCli(['dashboard', '--project', project, '--out=', '--no-open']);
    expect(r.status).toBe(3);
    expect(r.stdout).toBe('');
    expect(r.stderr).toMatch(/--out/);
    expect(r.stderr).toMatch(/requires a value/i);
    // The specific wrong-implementation this guards against: a message that
    // mentions a filesystem error/path instead of the flag.
    expect(r.stderr).not.toMatch(/EISDIR|ENOENT|cannot find/i);
  });

  it('exits 3 naming --out, not a filesystem path, when --out is given an explicit empty value (space form)', () => {
    const r = runCli(['dashboard', '--project', project, '--out', '', '--no-open']);
    expect(r.status).toBe(3);
    expect(r.stdout).toBe('');
    expect(r.stderr).toMatch(/--out/);
    expect(r.stderr).toMatch(/requires a value/i);
    expect(r.stderr).not.toMatch(/EISDIR|ENOENT|cannot find/i);
  });
});

/* ------------------------------------------------------------------ */
/* Beyond the brief: a write failure must never claim success first    */
/* ------------------------------------------------------------------ */

describe('dev-guardian dashboard — a write failure on --out fails clearly, not after claiming success', () => {
  it('exits 3, prints NOTHING to stdout, and names the underlying fs error, when a path component of --out is a file', () => {
    // Self-review question (task-6-brief.md): "Does --out pointing at an
    // unwritable path fail clearly, or does it fail after having already
    // told the user it succeeded?" This is the direct, automated answer.
    //
    // A directory that cannot be created because a FILE already sits where
    // a directory needs to go — real, deterministic, and (unlike chmod-based
    // permission tricks) identical on Windows and POSIX, so this does not
    // need a platform skip. `dirname(outPath)` needs to create
    // "<dir>/blocker/", but "<dir>/blocker" already exists as a plain file,
    // so `mkdirSync(..., { recursive: true })` must throw EEXIST/ENOTDIR.
    const dir = mkdtempSync(join(tmpdir(), 'guardian-dash-writefail-'));
    try {
      const blockerPath = join(dir, 'blocker');
      writeFileSync(blockerPath, 'not a directory');
      const out = join(dir, 'blocker', 'dashboard.html');

      const r = runCli(['dashboard', '--project', dir, '--out', out, '--no-open']);

      expect(r.status).toBe(3);
      // The load-bearing assertion: a wrong implementation that prints the
      // path BEFORE writing the file (or that writes to stdout for any
      // other reason before the write is confirmed) would satisfy a looser
      // "stdout doesn't say dashboard.html" check but still fail this one.
      expect(r.stdout).toBe('');
      expect(r.stderr).toMatch(/blocker/);
      expect(existsSync(out)).toBe(false);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('exits 3 when --out itself already exists as a directory (not a file)', () => {
    // The other shape of the same failure class: --out naming a path that
    // is ALREADY a directory, so writeFileSync (not mkdirSync) is what
    // throws — EISDIR on POSIX, EPERM/EISDIR on Windows depending on the
    // fs backend. Guards an implementation that only wraps mkdirSync in the
    // "let it throw to fatal()" contract and accidentally swallows a
    // writeFileSync failure some other way (e.g. an errant try/catch that
    // logs and continues rather than propagating).
    const dir = mkdtempSync(join(tmpdir(), 'guardian-dash-writefail-dir-'));
    try {
      const out = join(dir, 'dashboard.html');
      mkdirSync(out); // --out points at a directory, not a writable file path

      const r = runCli(['dashboard', '--project', dir, '--out', out, '--no-open']);

      expect(r.status).toBe(3);
      expect(r.stdout).toBe('');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

/* ------------------------------------------------------------------ */
/* Beyond the brief: real findings, and repeated runs                  */
/* ------------------------------------------------------------------ */

/**
 * Seeds one completed `security_full` scan with three real findings (one
 * each of critical/high/medium severity) directly through the storage layer
 * — no semgrep/gitleaks/trivy required. Mirrors the established pattern in
 * `test/unit/dashboard/snapshot.test.ts`'s own `completedScan`/`insertFinding`
 * helpers (field names/optionality cross-checked against
 * `storage/scansRepo.ts` and `storage/findingsRepo.ts` directly).
 */
function seedCompletedScan(projectPath: string): void {
  const { db } = openDatabase({ projectPath });
  const storage = new Storage(db);
  try {
    const scanId = 'seed-scan-1';
    storage.scans.insert({
      scan_id: scanId,
      scan_type: 'security_full',
      project_path: projectPath,
      tree_hash: 'seed',
    });
    storage.scans.finalize({
      scan_id: scanId,
      status: 'completed',
      tools_run: [{ name: 'semgrep', status: 'ok' }],
      missing_tools: [],
    });
    storage.findings.bulkInsert([
      {
        scan_id: scanId, fingerprint: 'seed-critical', tool: 'semgrep', rule_id: 'seed-rule',
        severity: 'critical', category: 'security', title: 'seed finding critical',
        message: 'seeded for the CLI e2e test', file_path: 'src/seed-0.ts',
        line_start: 1, line_end: 1, fix_available: false, raw: {},
      },
      {
        scan_id: scanId, fingerprint: 'seed-high', tool: 'semgrep', rule_id: 'seed-rule',
        severity: 'high', category: 'security', title: 'seed finding high',
        message: 'seeded for the CLI e2e test', file_path: 'src/seed-1.ts',
        line_start: 1, line_end: 1, fix_available: false, raw: {},
      },
      {
        scan_id: scanId, fingerprint: 'seed-medium', tool: 'semgrep', rule_id: 'seed-rule',
        severity: 'medium', category: 'security', title: 'seed finding medium',
        message: 'seeded for the CLI e2e test', file_path: 'src/seed-2.ts',
        line_start: 1, line_end: 1, fix_available: false, raw: {},
      },
    ]);
  } finally {
    storage.close();
  }
}

describe('dev-guardian status — against a project with real, seeded findings', () => {
  it('renders the actual counts, not the "no scan yet" placeholder', () => {
    const dir = mkdtempSync(join(tmpdir(), 'guardian-dash-findings-'));
    try {
      seedCompletedScan(dir);
      const r = runCli(['status', '--project', dir]);
      expect(r.status).toBe(0);
      expect(r.stderr).toBe('');
      // Discriminates the correct implementation from one that silently
      // swallows a storage read and falls back to the empty/no-scan
      // template — that would also exit 0 and would satisfy a bare status
      // check, but the "no scan yet" pointer line must be ABSENT once a
      // completed scan genuinely exists.
      expect(r.stdout).not.toMatch(/No scan yet/);
      // The real severity counts and scan type must be on the page.
      expect(r.stdout).toMatch(/1 crit/);
      expect(r.stdout).toMatch(/1 high/);
      expect(r.stdout).toMatch(/security_full/);
      expect(r.stdout).not.toMatch(/undefined|NaN/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('the dashboard HTML for the same seeded project inlines the real findings as parseable JSON', () => {
    const dir = mkdtempSync(join(tmpdir(), 'guardian-dash-findings-html-'));
    try {
      seedCompletedScan(dir);
      const out = join(dir, 'dash.html');
      const r = runCli(['dashboard', '--project', dir, '--out', out, '--no-open']);
      expect(r.status).toBe(0);
      expect(r.stderr).toBe('');
      const html = readFileSync(out, 'utf8');
      const m = html.match(
        /<script type="application\/json" id="guardian-data">([\s\S]*?)<\/script>/);
      expect(m).toBeTruthy();
      const payload = JSON.parse(m?.[1] ?? 'null') as { findings?: { total?: number } };
      expect(payload.findings?.total).toBe(3);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('dev-guardian dashboard — repeated runs leave no locked database behind', () => {
  it('dashboard, then status, then dashboard again over the same project all succeed, and the DB file is free afterward', () => {
    // "A user actually hits this" — regenerating the dashboard after a new
    // scan, or checking `status` right after `dashboard`, all against the
    // SAME project's database within moments of each other.
    //
    // Seeded with a real completed scan FIRST (fix-round-3, Important 3: a
    // genuinely read-only open): once `status`/`dashboard` stopped creating
    // `.guardian/guardian.db` for a project that does not already have one
    // (see "genuinely read-only" below), running them against a still-empty
    // `dir` would never produce a database file at all, and this test's own
    // rename-based lock check would have nothing to open. Seeding first makes
    // this test's premise — a database that already exists and is repeatedly
    // reopened — match what it is actually checking (no locked handle left
    // behind), and is the realistic shape anyway: nobody regenerates a
    // dashboard for a project with no data.
    const dir = mkdtempSync(join(tmpdir(), 'guardian-dash-lock-'));
    try {
      seedCompletedScan(dir);
      const out1 = join(dir, 'd1.html');
      const r1 = runCli(['dashboard', '--project', dir, '--out', out1, '--no-open']);
      expect(r1.status).toBe(0);
      expect(existsSync(out1)).toBe(true);

      const r2 = runCli(['status', '--project', dir]);
      expect(r2.status).toBe(0);

      const out2 = join(dir, 'd2.html');
      const r3 = runCli(['dashboard', '--project', dir, '--out', out2, '--no-open']);
      expect(r3.status).toBe(0);
      expect(existsSync(out2)).toBe(true);

      // Each of the three runs above is a SEPARATE subprocess that has fully
      // exited by the time spawnSync returns, so the OS has already reclaimed
      // its file handles regardless of whether this task's own code closes
      // the database explicitly — this assertion cannot, by itself, tell
      // "closed in a finally" apart from "never closed, rescued by process
      // exit". What it DOES catch: a still-alive descendant (e.g. a
      // non-detached/non-unref'd browser-opener child, or any handle that
      // keeps a subprocess from exiting promptly) holding the file open past
      // when this test expects the CLI to be done with it — that shows up
      // here as EBUSY/EPERM renaming the file on Windows, immediately.
      const dbPath = join(dir, '.guardian', 'guardian.db');
      expect(existsSync(dbPath)).toBe(true);
      const moved = `${dbPath}.moved`;
      renameSync(dbPath, moved);
      renameSync(moved, dbPath);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

/* ------------------------------------------------------------------ */
/* fix-round-2: regression test for the Minor fix (Storage inside try) */
/* ------------------------------------------------------------------ */

describe('dev-guardian status — a migrated-but-missing-table database is refused cleanly', () => {
  it('exits 3 with a clear message (not a hang, not exit 0) when a required table is missing, and leaves the database file free afterward', () => {
    // Regression test for the fix-round-1 Minor: `new Storage(db)` used to
    // sit OUTSIDE buildProjectSnapshot's try/finally. This reproduces the
    // exact class of database state that fix was written for: schema_meta
    // says "fully migrated" (so runMigrations() itself sees nothing pending
    // and does nothing — it trusts the recorded version), but a table is
    // actually gone (hand-edited, corrupted, or a prior process crashed
    // mid-migration). That is NOT caught by runMigrations(); it is `new
    // Storage(db)`'s own constructor — which prepares every repo's
    // statements immediately — that surfaces it, confirmed directly against
    // the real dist build: `new Storage(db)` throws
    // `Error: no such table: scans` the moment ScansRepo (the first repo
    // Storage constructs) tries to prepare a statement against it.
    //
    // Built the way the coordinator's own review reproduced it: seed a
    // normally-migrated database via `openDatabase` (same helper this file's
    // `seedCompletedScan` already uses), drop a table directly through the
    // storage layer's own `db.exec()` (a thin wrapper over node:sqlite's
    // `exec`), then invoke the CLI as a real subprocess and apply the same
    // rename-lock check "repeated runs leave no locked database behind"
    // above already uses. That check has the identical, already-documented
    // limitation noted there (a separate subprocess's OS handles are
    // reclaimed on exit regardless of an explicit close() call, so it alone
    // cannot PROVE this specific ordering fix from outside a process
    // boundary) — it is included anyway because it is cheap, it is the
    // exact recipe requested, and it still catches a DIFFERENT real
    // regression class: anything that keeps this specific failure path from
    // exiting promptly and cleanly (a hang, an orphaned descendant).
    const dir = mkdtempSync(join(tmpdir(), 'guardian-dash-missingtable-'));
    try {
      const { db } = openDatabase({ projectPath: dir });
      db.exec('DROP TABLE scans');
      db.close();

      const r = runCli(['status', '--project', dir]);

      expect(r.status).toBe(3);
      expect(r.stdout).toBe('');
      expect(r.stderr).toMatch(/no such table/i);

      const dbPath = join(dir, '.guardian', 'guardian.db');
      expect(existsSync(dbPath)).toBe(true);
      const moved = `${dbPath}.moved`;
      renameSync(dbPath, moved);
      renameSync(moved, dbPath);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

/* ------------------------------------------------------------------ */
/* fix-round-3, Important 3: genuinely read-only — no db file created */
/* ------------------------------------------------------------------ */

describe('dev-guardian status / dashboard — genuinely read-only: no database is created for a project that has none', () => {
  // Before this fix, `buildProjectSnapshot` called `openDatabase({
  // projectPath })` unconditionally, which — on a directory with no
  // `.guardian/guardian.db` yet — creates one (`ensureDir` + `runMigrations`,
  // an empty ~143 KB file). That contradicted the documented promise in
  // three places at once: `commands/guardian-status.md` ("Read-only — no
  // scan runs, no mutation"), `README.md`, and this CLI's own --help text
  // ("Read-only: never runs a scan, never mutates the database"). Reproduced
  // directly before this fix: `before: [] / after: ['.guardian']`.

  it('status creates nothing on a fresh, empty directory — not even .guardian/', () => {
    const dir = mkdtempSync(join(tmpdir(), 'guardian-dash-readonly-status-'));
    try {
      expect(readdirSync(dir)).toEqual([]);

      const r = runCli(['status', '--project', dir]);

      expect(r.status).toBe(0);
      expect(r.stderr).toBe('');
      expect(r.stdout).toMatch(/dev-guardian scan/);
      // The load-bearing assertion: the directory is EXACTLY as empty as it
      // started. Not just "no guardian.db" — nothing at all, so a wrong
      // implementation that creates `.guardian/` but defers the db file
      // itself (e.g. only `ensureDir`, no `runMigrations`) still fails this.
      expect(readdirSync(dir)).toEqual([]);
      expect(existsSync(join(dir, '.guardian'))).toBe(false);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('dashboard creates nothing but the report it was explicitly told to write — no .guardian/guardian.db', () => {
    const dir = mkdtempSync(join(tmpdir(), 'guardian-dash-readonly-dashboard-'));
    try {
      const out = join(dir, 'dash.html');
      const r = runCli(['dashboard', '--project', dir, '--out', out, '--no-open']);

      expect(r.status).toBe(0);
      expect(r.stderr).toBe('');
      // The report itself is the one file the user explicitly asked this
      // command to write via --out — that is not a violation of read-only
      // (design doc §1 is about the DATABASE never being mutated), and this
      // assertion is what discriminates the two: the requested output exists,
      // the database it was never told to create does not.
      expect(existsSync(out)).toBe(true);
      expect(existsSync(join(dir, '.guardian'))).toBe(false);
      expect(readdirSync(dir).sort()).toEqual(['dash.html']);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('still opens the real, existing database (not an in-memory stand-in) once one is already there', () => {
    // The other half of the same fix: the in-memory fallback must trigger
    // ONLY when there is genuinely no database yet — a project that HAS
    // scan history must keep reading it, not silently show "never scanned"
    // because an in-memory database is always empty. Reuses this file's own
    // `seedCompletedScan` (real findings, via `openDatabase` directly) so a
    // regression here — the detection check inverted, or always taking the
    // in-memory branch — would show up as the wrong output, not just a
    // missing file.
    const dir = mkdtempSync(join(tmpdir(), 'guardian-dash-readonly-realdb-'));
    try {
      seedCompletedScan(dir);
      const dbSizeBefore = readFileSync(join(dir, '.guardian', 'guardian.db')).length;

      const r = runCli(['status', '--project', dir]);

      expect(r.status).toBe(0);
      expect(r.stdout).not.toMatch(/No scan yet/);
      expect(r.stdout).toMatch(/1 crit/);
      // The database that was already there is untouched, not replaced —
      // still present, same non-trivial size (a fresh in-memory swap-in
      // would have to have ignored it entirely to show real findings, but
      // this also guards against a subtler bug: opening the real file AND
      // somehow truncating/re-migrating over it).
      const dbSizeAfter = readFileSync(join(dir, '.guardian', 'guardian.db')).length;
      expect(dbSizeAfter).toBeGreaterThan(0);
      expect(dbSizeAfter).toBe(dbSizeBefore);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

/* ------------------------------------------------------------------ */
/* fix-round-3, Minor 6: the root/home guard the MCP tools already have */
/* ------------------------------------------------------------------ */

describe('dev-guardian status / dashboard — the root/home guard every MCP tool already has', () => {
  // mcp/src/platform/projectPath.ts's own resolveProjectPath (every MCP
  // tool's project-path resolver) refuses a filesystem root or the user's
  // home directory outright. cli/dev-guardian.mjs's own resolveProjectOrExit
  // — shared by scan/baseline/status/dashboard — checked existence and
  // directory-ness only, so the identical input that refuses through an MCP
  // host proceeded here (and, before the fix above, could have created
  // `.guardian/` at the filesystem root or straight in $HOME). Same fixture
  // technique as `platform/projectPath.test.ts`'s own "rejects the
  // filesystem root" / "rejects the user-home root" tests, so the two guards
  // are proven to agree, not just independently plausible.

  it('exits 3 naming --project when it is the filesystem root', () => {
    const root = parse(process.cwd()).root;
    const r = runCli(['status', '--project', root]);
    expect(r.status).toBe(3);
    expect(r.stderr).toMatch(/--project/);
  });

  it('exits 3 naming --project when it is the user home directory', () => {
    const r = runCli(['status', '--project', homedir()]);
    expect(r.status).toBe(3);
    expect(r.stderr).toMatch(/--project/);
  });

  it('still accepts a real subdirectory of home — the guard is not over-broad', () => {
    const sub = mkdtempSync(join(homedir(), 'guardian-dash-homesub-'));
    try {
      const r = runCli(['status', '--project', sub]);
      expect(r.status).toBe(0);
      expect(r.stderr).toBe('');
    } finally {
      rmSync(sub, { recursive: true, force: true });
    }
  });
});
