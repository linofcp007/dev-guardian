/**
 * End-to-end test of `cli/dev-guardian.mjs`'s `scan` and `baseline update`
 * commands, invoked as a REAL SUBPROCESS (`node cli/dev-guardian.mjs ...`) —
 * the only test that catches a defect in argument dispatch, because that is
 * how a user (or a CI pipeline) actually runs this tool. Everything in
 * `mcp/test/unit/ci/*` and `mcp/test/integration/ciRunScans.test.ts` proves
 * the TypeScript underneath is right; this file proves the shim wires it up.
 *
 * ---- Two tiers ------------------------------------------------------------
 *
 * "usage and safety" tests never reach a real scanner — they assert on
 * argument parsing and the pwn-request guard, and must return in well under
 * a second. If one of these starts taking real scan time, that is itself a
 * sign the implementation validates too late.
 *
 * "against a real fixture" tests run the actual scan pipeline (real Semgrep,
 * real gitleaks, real Trivy) via a real subprocess, once per `describe`
 * block in a shared `beforeAll`, and assert on facets of that one result —
 * same technique as `dastFixture.test.ts`'s `runA`/`runB`, to keep wall
 * clock down. They follow this project's own established skip discipline
 * (`rulePackFixture.test.ts`'s header comment): SKIPPED, not silently
 * passed, when the toolchain is not on PATH, and `GUARDIAN_REQUIRE_SEMGREP=1`
 * turns that absence into a hard failure instead of a quiet skip.
 *
 * ---- Why `gitleaks detect` forces the fixture to be a real git repo -------
 *
 * `scripts/scan/full-security-scan.sh` runs `gitleaks detect`, which (unlike
 * `gitleaks dir`) scans git history and errors on a non-repository. Without
 * `git init` + a commit, gitleaks would fail to produce `secrets.json`,
 * `security_scan_full` would record it as a missing tool it is NOT, and
 * `coverage` would read 'partial' even with every scanner installed —
 * exactly the kind of false negative this project's own tests exist to
 * catch, not produce. `map_attack_surface`'s `computeTreeHash` does not
 * share this requirement (it falls back to a filesystem walk outside git),
 * but building the fixture as a real repo once covers both.
 */

import { execa } from 'execa';
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { type SpawnSyncReturns, spawnSync } from 'node:child_process';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, describe, expect, it, beforeAll } from 'vitest';

import { detectOs } from '../../src/platform/osDetect.js';

const here = dirname(fileURLToPath(import.meta.url));
// mcp/test/e2e -> mcp/test -> mcp -> repo root
const REPO_ROOT = resolve(here, '..', '..', '..');
const CLI = resolve(REPO_ROOT, 'cli', 'dev-guardian.mjs');

const FAST_TIMEOUT_MS = 10_000;
const SCAN_TIMEOUT_MS = 150_000;

/* ------------------------------------------------------------------ */
/* Toolchain availability — same technique as rulePackFixture.test.ts  */
/* ------------------------------------------------------------------ */

async function isInstalled(bin: string): Promise<boolean> {
  try {
    const r = await execa(detectOs() === 'win32' ? 'where' : 'which', [bin], {
      reject: false,
      timeout: 2_000,
    });
    return r.exitCode === 0;
  } catch {
    return false;
  }
}

// security_scan_full unconditionally expects semgrep, gitleaks and trivy
// (deps) on a project with no Dockerfile/Python — see securityScanFull.ts's
// ROUTES table, where only 'trivy-dockerfile' and 'bandit' are conditional.
// All three genuinely installed is what "coverage: full" requires here.
const SEMGREP_INSTALLED = await isInstalled('semgrep');
const GITLEAKS_INSTALLED = await isInstalled('gitleaks');
const TRIVY_INSTALLED = await isInstalled('trivy');
const TOOLCHAIN_AVAILABLE = SEMGREP_INSTALLED && GITLEAKS_INSTALLED && TRIVY_INSTALLED;
const REQUIRE_SEMGREP = process.env['GUARDIAN_REQUIRE_SEMGREP'] === '1';

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

function runCli(args: string[], timeout = FAST_TIMEOUT_MS): SpawnSyncReturns<string> {
  return spawnSync(process.execPath, [CLI, ...args], {
    cwd: REPO_ROOT,
    encoding: 'utf8',
    timeout,
  });
}

/**
 * A directory that exists but is not scanned — enough for the "usage and
 * safety" tests, which must never reach a real scanner. Kept separate from
 * the real fixture below so a bug that validates too late (falls through to
 * a real scan) turns into a slow/timing-out test rather than a passing one.
 */
function makeBareDir(prefix: string): string {
  return mkdtempSync(join(tmpdir(), prefix));
}

/**
 * A minimal, clean, real git repository: a bare Node package with one
 * inert function, nothing a scanner should ever flag. `git init` + a real
 * commit is load-bearing for gitleaks (see module doc); `map_attack_surface`
 * and `detect_stack` do not require it but are unaffected by it either.
 */
async function makeScannableFixture(prefix: string): Promise<string> {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  writeFileSync(
    join(dir, 'package.json'),
    `${JSON.stringify({ name: 'guardian-ci-cli-fixture', version: '1.0.0', private: true }, null, 2)}\n`,
  );
  writeFileSync(
    join(dir, 'index.js'),
    "'use strict';\n\nfunction add(a, b) {\n  return a + b;\n}\n\nmodule.exports = { add };\n",
  );
  await execa('git', ['init'], { cwd: dir });
  await execa('git', ['config', 'user.email', 'guardian-ci-cli-fixture@example.com'], { cwd: dir });
  await execa('git', ['config', 'user.name', 'Guardian CI CLI Fixture'], { cwd: dir });
  await execa('git', ['add', '-A'], { cwd: dir });
  await execa('git', ['commit', '-m', 'initial'], { cwd: dir });
  return dir;
}

function rmDir(dir: string): void {
  // Best-effort: called from `finally` blocks, so a locked file during
  // teardown (e.g. a scanner subprocess that hadn't fully released its
  // handle yet) must never THROW here and mask the test's own assertion
  // result — an exception raised inside `finally` replaces an in-flight
  // failure from the `try` block above it, which would turn a correctly
  // failing assertion into a confusing, unrelated EPERM instead. A directory
  // left behind because cleanup itself failed is a leak to notice later,
  // not a reason to hide what the test actually found.
  try {
    rmSync(dir, { recursive: true, force: true });
  } catch {
    /* best-effort; see above */
  }
}

/* ------------------------------------------------------------------ */
/* dev-guardian scan — usage and the pwn-request guard (fast)          */
/* ------------------------------------------------------------------ */

describe('dev-guardian scan — usage and safety (no real scanner reached)', () => {
  it('exits 3 on an unknown flag, naming it', () => {
    const r = runCli(['scan', '--nope']);
    expect(r.status).toBe(3);
    expect(r.stderr).toMatch(/--nope/);
  });

  it('exits 3 and refuses when --start-command comes from a repo config file, naming the file and the reason', () => {
    // The pwn-request guard. A fork's pull request can edit a repository
    // file; it must never gain code execution on the runner that way. Write
    // .guardian/ci.json declaring start_command, then run WITHOUT
    // --start-command on argv — the mere presence of the key in the file
    // must be refused on its own, not just when argv also names it.
    const dir = makeBareDir('guardian-ci-cli-repoconfig-');
    try {
      mkdirSync(join(dir, '.guardian'), { recursive: true });
      writeFileSync(
        join(dir, '.guardian', 'ci.json'),
        `${JSON.stringify({ start_command: ['node', 'server.js'] })}\n`,
      );

      const r = runCli(['scan', '--project', dir]);

      expect(r.status).toBe(3);
      // Names the FILE...
      expect(r.stderr).toMatch(/\.guardian[\\/]ci\.json/);
      // ...and the REASON (argv-only), not just a generic usage error. A
      // wrong implementation that exits 3 for "config error" without saying
      // why would satisfy a bare `toBe(3)` and a loose /start.command/i but
      // fail these.
      expect(r.stderr).toMatch(/command line|argv/i);
      expect(r.stderr).toMatch(/fork|pull request/i);
      // And it must never have reached the scan pipeline: no baseline, no
      // reports directory — proof the refusal happened before any work.
      expect(existsSync(join(dir, '.guardian', 'baseline.json'))).toBe(false);
      expect(existsSync(join(dir, '.guardian', 'reports'))).toBe(false);
    } finally {
      rmDir(dir);
    }
  });

  it('applies the same repo-config refusal to `baseline update`, not only `scan`', () => {
    // Guards the wrong implementation that wires the guard into cmdScan
    // only: `baseline update` also runs the pipeline and must not become the
    // unguarded back door.
    const dir = makeBareDir('guardian-ci-cli-repoconfig-baseline-');
    try {
      mkdirSync(join(dir, '.guardian'), { recursive: true });
      writeFileSync(
        join(dir, '.guardian', 'ci.json'),
        `${JSON.stringify({ start_command: ['node', 'server.js'] })}\n`,
      );

      const r = runCli(['baseline', 'update', '--project', dir]);

      expect(r.status).toBe(3);
      expect(r.stderr).toMatch(/\.guardian[\\/]ci\.json/);
      expect(existsSync(join(dir, '.guardian', 'baseline.json'))).toBe(false);
    } finally {
      rmDir(dir);
    }
  });

  it('exits 3 when --start-command is given on argv, with a message distinct from the repo-config refusal', () => {
    // Scope boundary with the (separate) app-runner task: --start-command is
    // parsed and its argv-only rule is enforced here, but nothing in this
    // build may actually start a process — Task 6 owns that. This must be a
    // clearly different message from the repo-config refusal above, or a
    // reader (and a test) cannot tell "you tried a real feature that isn't
    // built yet" apart from "a fork tried to smuggle a command in".
    const dir = makeBareDir('guardian-ci-cli-startcmd-argv-');
    try {
      const r = runCli(['scan', '--project', dir, '--start-command', 'node', 'server.js']);
      expect(r.status).toBe(3);
      expect(r.stderr).toMatch(/start.command/i);
      expect(r.stderr).toMatch(/not.*(implement|support)/i);
      // Must NOT be the repo-config message — different problem, different words.
      expect(r.stderr).not.toMatch(/fork|pull request/i);
      expect(r.stderr).not.toMatch(/\.guardian[\\/]ci\.json/);
    } finally {
      rmDir(dir);
    }
  });

  it('--start-command consumes the rest of argv as the command, not as more flags', () => {
    // Guards an implementation that stops at the next token starting with
    // "--" instead of treating everything after --start-command as the
    // command's own argv. If it mis-parses, "--project" would be consumed as
    // part of the (rejected) command instead of being read as the flag, and
    // this dir would never be resolved/used at all — either way the test
    // below still expects exit 3 for "not yet implemented", so this is
    // really pinned by the companion test above; this one additionally
    // proves passing extra "--looking" tokens after --start-command does not
    // itself produce an "unknown flag" error.
    const dir = makeBareDir('guardian-ci-cli-startcmd-argv2-');
    try {
      const r = runCli(['scan', '--start-command', 'node', 'server.js', '--port', '4000', '--project', dir]);
      expect(r.status).toBe(3);
      // If "--project" had been parsed as a real flag (wrong: it's supposed
      // to be part of the start-command's own argv here), we would still hit
      // the same not-yet-implemented refusal — so the discriminator is that
      // this must NOT be an "Unknown flag" usage error naming --port.
      expect(r.stderr).not.toMatch(/unknown flag/i);
    } finally {
      rmDir(dir);
    }
  });

  it('exits 3 on an invalid --fail-on value, naming it', () => {
    const r = runCli(['scan', '--fail-on', 'urgent']);
    expect(r.status).toBe(3);
    expect(r.stderr).toMatch(/--fail-on/);
    expect(r.stderr).toMatch(/urgent/);
  });

  it('exits 3 on an invalid --format value, naming it', () => {
    const r = runCli(['scan', '--format', 'xml']);
    expect(r.status).toBe(3);
    expect(r.stderr).toMatch(/--format/);
    expect(r.stderr).toMatch(/xml/);
  });

  it('exits 3 when --project does not exist', () => {
    const missing = join(tmpdir(), 'guardian-ci-cli-does-not-exist-xyz');
    const r = runCli(['scan', '--project', missing]);
    expect(r.status).toBe(3);
    expect(r.stderr).toMatch(/--project/);
  });

  it('exits 3 on an unknown baseline subcommand, naming it', () => {
    const r = runCli(['baseline', 'bogus']);
    expect(r.status).toBe(3);
    expect(r.stderr).toMatch(/bogus/);
  });

  it('exits 3 on an unknown flag to `baseline update`, naming it', () => {
    const r = runCli(['baseline', 'update', '--nope']);
    expect(r.status).toBe(3);
    expect(r.stderr).toMatch(/--nope/);
  });
});

/* ------------------------------------------------------------------ */
/* dev-guardian scan — against a real, clean fixture (real scanners)   */
/* ------------------------------------------------------------------ */

describe('dev-guardian scan — against a real, clean fixture', () => {
  let fixture: string;
  let sarifPath: string;
  let baselinePath: string;
  let result: SpawnSyncReturns<string>;

  beforeAll(async () => {
    fixture = await makeScannableFixture('guardian-ci-cli-scan-');
    sarifPath = join(fixture, 'out', 'results.sarif');
    baselinePath = join(fixture, '.guardian', 'baseline.json');
    result = runCli(['scan', '--project', fixture, '--sarif', sarifPath], SCAN_TIMEOUT_MS);
  }, SCAN_TIMEOUT_MS);

  afterAll(() => {
    if (fixture) rmDir(fixture);
  });

  it('does not write .guardian/baseline.json — scan never mutates the baseline', () => {
    // The wrong implementation this guards against: `scan` silently folding
    // current findings into the baseline, which would turn the gate into
    // decoration (design doc §4).
    expect(existsSync(baselinePath)).toBe(false);
  });

  it('emits a SARIF document to the path given by --sarif, and it parses with the expected shape', () => {
    expect(existsSync(sarifPath)).toBe(true);
    const raw = readFileSync(sarifPath, 'utf8');
    const doc = JSON.parse(raw) as { version?: string; runs?: unknown[] };
    expect(doc.version).toBe('2.1.0');
    expect(Array.isArray(doc.runs)).toBe(true);
    expect((doc.runs ?? []).length).toBeGreaterThan(0);
  });

  it('prints nothing to stderr on a normal run', () => {
    // Pristine output: a CI log full of stray warnings trains people to
    // ignore it. This must hold regardless of whether coverage happens to
    // be full in the environment the suite runs in — it is about the
    // ABSENCE of stray console noise, not about the gate's own verdict.
    expect(result.stderr).toBe('');
  });

  it('prints the human report headline and coverage line on stdout', () => {
    expect(result.stdout).toMatch(/^dev-guardian CI: /);
    expect(result.stdout).toMatch(/coverage: (full|partial|none)/);
  });

  it.skipIf(!TOOLCHAIN_AVAILABLE)(
    'exits 0 (PASS) against a clean fixture when semgrep, gitleaks and trivy are all on PATH',
    () => {
      expect(
        result.status,
        `expected exit 0, got ${String(result.status)}. stdout:\n${result.stdout}\nstderr:\n${result.stderr}`,
      ).toBe(0);
      expect(result.stdout).toMatch(/dev-guardian CI: PASS \(exit code 0\)/);
    },
  );

  it.runIf(REQUIRE_SEMGREP)('GUARDIAN_REQUIRE_SEMGREP=1 — this suite must be runnable end to end', () => {
    // Mirrors rulePackFixture.test.ts's own hard-failure companion test:
    // without it, "the toolchain is missing" and "the toolchain ran and
    // disagreed" read identically as a skip.
    expect(
      TOOLCHAIN_AVAILABLE,
      'GUARDIAN_REQUIRE_SEMGREP=1 but semgrep/gitleaks/trivy are not all on PATH.',
    ).toBe(true);
    expect(result.status).toBe(0);
  });
});

/* ------------------------------------------------------------------ */
/* dev-guardian baseline update                                        */
/* ------------------------------------------------------------------ */

describe('dev-guardian baseline update — against a real, clean fixture', () => {
  let fixture: string;
  let baselinePath: string;

  beforeAll(async () => {
    fixture = await makeScannableFixture('guardian-ci-cli-baseline-');
    baselinePath = join(fixture, '.guardian', 'baseline.json');
  }, SCAN_TIMEOUT_MS);

  afterAll(() => {
    if (fixture) rmDir(fixture);
  });

  it('writes .guardian/baseline.json, valid and versioned', () => {
    const r = runCli(['baseline', 'update', '--project', fixture], SCAN_TIMEOUT_MS);
    expect(r.status === 0 || r.status === 2, `unexpected exit ${String(r.status)}: ${r.stderr}`).toBe(true);
    expect(existsSync(baselinePath)).toBe(true);
    const doc = JSON.parse(readFileSync(baselinePath, 'utf8')) as { version?: number; entries?: unknown[] };
    expect(doc.version).toBe(1);
    expect(Array.isArray(doc.entries)).toBe(true);
  }, SCAN_TIMEOUT_MS);

  it.skipIf(!TOOLCHAIN_AVAILABLE)(
    'running `baseline update` again preserves each entry\'s `added` date rather than resetting it',
    () => {
      // Guards the wrong implementation that stamps `now` unconditionally on
      // every regeneration (baseline.ts#buildBaseline's own contract, now
      // proven through the real CLI rather than only against the pure
      // function directly).
      const before = JSON.parse(readFileSync(baselinePath, 'utf8')) as {
        entries: { fingerprint: string; added: string }[];
      };
      const r = runCli(['baseline', 'update', '--project', fixture], SCAN_TIMEOUT_MS);
      expect(r.status === 0 || r.status === 2, `unexpected exit ${String(r.status)}: ${r.stderr}`).toBe(true);
      const after = JSON.parse(readFileSync(baselinePath, 'utf8')) as {
        entries: { fingerprint: string; added: string }[];
      };
      const beforeDates = new Map(before.entries.map((e) => [e.fingerprint, e.added]));
      for (const entry of after.entries) {
        const priorDate = beforeDates.get(entry.fingerprint);
        if (priorDate !== undefined) expect(entry.added).toBe(priorDate);
      }
    },
    SCAN_TIMEOUT_MS,
  );
});
