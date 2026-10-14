/**
 * `.guardian/scan.yml` (review 8, finding 3): Semgrep's per-file timeout and
 * threshold, and the per-file timeouts the CI gate accepts — committed,
 * reviewed, never half-read.
 */
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import {
  DEFAULT_SEMGREP_TIMEOUT_S,
  DEFAULT_SEMGREP_TIMEOUT_THRESHOLD,
  loadScanSettings,
  parseSettings,
  semgrepTimeoutArgs,
} from '../../../src/platform/scanSettings.js';
import { semgrepScanFlags } from '../../../src/runners/semgrepRun.js';
import { cleanupTempDirs, makeTempDir } from '../../helpers/tempDir.js';

afterAll(cleanupTempDirs);

function project(yaml?: string): string {
  const dir = makeTempDir('scan-settings-');
  if (yaml !== undefined) {
    mkdirSync(join(dir, '.guardian'), { recursive: true });
    writeFileSync(join(dir, '.guardian', 'scan.yml'), yaml);
  }
  return dir;
}

describe('loadScanSettings', () => {
  it('no file: the defaults — a larger timeout than Semgrep’s 5 s, and a threshold of 0', () => {
    const r = loadScanSettings(project());
    expect(r.kind).toBe('none');
    expect(DEFAULT_SEMGREP_TIMEOUT_S).toBeGreaterThan(5);
    expect(DEFAULT_SEMGREP_TIMEOUT_THRESHOLD).toBe(0);
    expect(semgrepTimeoutArgs(r.settings)).toEqual(['--timeout', String(DEFAULT_SEMGREP_TIMEOUT_S), '--timeout-threshold', '0']);
  });

  it('reads the timeout, the threshold and the accepted files, normalised', () => {
    const r = loadScanSettings(
      project('semgrep:\n  timeout: 60\n  timeout_threshold: 2\n  accept_timeouts:\n    - ./src/gen/parser.js\n    - "lib\\\\big.js"\n'),
    );
    expect(r.kind).toBe('loaded');
    expect(r.settings.semgrep).toEqual({ timeout: 60, timeoutThreshold: 2, acceptTimeouts: ['src/gen/parser.js', 'lib/big.js'] });
    expect(semgrepTimeoutArgs(r.settings)).toEqual(['--timeout', '60', '--timeout-threshold', '2']);
  });

  it('a name with brackets or braces is a file, read as written (Next.js `pages/[id].js`)', () => {
    const r = loadScanSettings(project('semgrep:\n  accept_timeouts:\n    - "pages/[id].js"\n    - "a/{b}.js"\n'));
    expect(r.kind).toBe('loaded');
    expect(r.settings.semgrep.acceptTimeouts).toEqual(['pages/[id].js', 'a/{b}.js']);
  });

  it('an invalid file is never half-read: the defaults, and why', () => {
    for (const [yaml, why] of [
      ['semgrep: [', /invalid YAML/],
      ['scan:\n  timeout: 1\n', /unrecognised top-level key "scan"/],
      ['semgrep:\n  timeout: fast\n', /semgrep\.timeout must be a whole number of seconds/],
      // Semgrep refuses `--timeout 1.5`: every scan failed on it, scan.yml never named (review 10).
      ['semgrep:\n  timeout: 1.5\n', /semgrep\.timeout must be a whole number of seconds from 0 to 3600, got 1\.5/],
      // An entry is one file, matched exactly: a glob or a directory matched nothing, silently (review 10).
      ['semgrep:\n  accept_timeouts:\n    - src/gen/*.js\n', /'src\/gen\/\*\.js' is a glob; name each file exactly/],
      ['semgrep:\n  accept_timeouts:\n    - "src/**/parser.js"\n', /is a glob/],
      ['semgrep:\n  accept_timeouts:\n    - src/parser?.js\n', /is a glob/],
      ['semgrep:\n  accept_timeouts:\n    - src/gen/\n', /'src\/gen\/' is a directory/],
      ['semgrep:\n  timeout_threshold: 1.5\n', /whole number/],
      ['semgrep:\n  accept_timeouts: src/a.js\n', /must be a list/],
      ['semgrep:\n  accept_timeouts:\n    - /etc/passwd\n', /absolute/],
      ['semgrep:\n  accept_timeouts:\n    - ../outside.js\n', /leaves the project/],
      ['semgrep:\n  acept_timeouts: []\n', /unrecognised semgrep setting "acept_timeouts"/],
      // A key written twice: the reviewer read the first, the scan applied the
      // last (review 11, finding 15e) — refused, the key named.
      ['semgrep:\n  timeout: 30\n  timeout: 1\n', /invalid YAML: the key "timeout" appears twice/],
      ['semgrep:\n  timeout: 30\nsemgrep:\n  timeout: 1\n', /the key "semgrep" appears twice/],
      ['semgrep:\n  accept_timeouts: [a.js]\n  "accept_timeouts": [b.js]\n', /the key "accept_timeouts" appears twice/],
      // …and written again through an alias (review 12, finding 13).
      ['semgrep:\n  &k timeout: 30\n  *k : 1\n', /the key "timeout" appears twice/],
      ['&s semgrep:\n  timeout: 30\n*s :\n  timeout: 1\n', /the key "semgrep" appears twice/],
      ['semgrep:\n  &k accept_timeouts:\n    - a.js\n  *k :\n    - b.js\n', /the key "accept_timeouts" appears twice/],
    ] as const) {
      const r = loadScanSettings(project(yaml));
      expect(r.kind, yaml).toBe('invalid');
      expect(r.kind === 'invalid' ? r.error : '', yaml).toMatch(why);
      expect(r.settings.semgrep.acceptTimeouts).toEqual([]);
      expect(r.settings.semgrep.timeout).toBe(DEFAULT_SEMGREP_TIMEOUT_S);
    }
  });

  it('an empty document is the defaults', () => {
    expect(parseSettings(null)).toEqual(parseSettings({}));
    expect(loadScanSettings(project('')).kind).toBe('loaded');
  });
});

describe('semgrepScanFlags', () => {
  it('passes the timeouts and keeps the root .guardian/ output out of every scan (finding 14)', () => {
    const flags = semgrepScanFlags(project('semgrep:\n  timeout: 45\n'));
    expect(flags.args.slice(0, 4)).toEqual(['--timeout', '45', '--timeout-threshold', '0']);
    expect(flags.args).toContain('--exclude=.guardian/reports');
    expect(flags.args).toContain('--exclude=.guardian/guardian.db');
    expect(flags.warning).toBeNull();
  });

  it('never a .guardian folder below the root: no unanchored --exclude (review 10, finding 1)', () => {
    // `--exclude=.guardian` matched `lib/.guardian/handler.js` too. Every
    // exclusion holds a slash (anchored) and no leading one (which anchors at
    // the git root, not the project — platform/guardianOutput.ts).
    const excludes = semgrepScanFlags(project()).args.filter((a) => a.startsWith('--exclude='));
    expect(excludes.length).toBeGreaterThan(0);
    for (const flag of excludes) {
      const pattern = flag.slice('--exclude='.length);
      expect(pattern, flag).toMatch(/^\.guardian\/[^/*]/);
    }
  });

  it('an invalid file: the defaults, with a warning naming it', () => {
    const flags = semgrepScanFlags(project('semgrep:\n  timeout: -1\n'));
    expect(flags.args).toContain('--exclude=.guardian/reports');
    expect(flags.warning).toMatch(/\.guardian\/scan\.yml was not applied \(semgrep\.timeout must be/);
  });
});
