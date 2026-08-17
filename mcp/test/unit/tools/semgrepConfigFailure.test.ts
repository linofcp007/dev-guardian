import { describe, expect, it } from 'vitest';
import {
  describeConfigFailures,
  findConfigDownloadFailures,
  survivingPacks,
} from '../../../src/tools/semgrepConfigFailure.js';

// Real Semgrep 1.164.0 output, captured against a deliberately-nonexistent
// pack: `semgrep --config=p/does-not-exist --json <dir>` exits 7 with
// `results: []` and `paths: { scanned: [] }` — nothing was scanned, not
// even by other, valid configs run alongside it. This is the exact shape
// `findConfigDownloadFailures` has to parse.
const SINGLE_FAILURE_JSON = JSON.stringify({
  version: '1.164.0',
  results: [],
  errors: [
    {
      code: 2,
      level: 'error',
      type: 'SemgrepError',
      message: 'Failed to download configuration from https://semgrep.dev/c/p/does-not-exist HTTP 404.',
    },
    {
      code: 7,
      level: 'error',
      type: 'SemgrepError',
      message: 'invalid configuration file found (1 configs were invalid)',
    },
  ],
  paths: { scanned: [] },
});

// Also captured live: two simultaneously-bad `--config=` values each get
// their own errors[] entry, plus one trailing summary entry with no
// attributable URL.
const DOUBLE_FAILURE_JSON = JSON.stringify({
  version: '1.164.0',
  results: [],
  errors: [
    {
      code: 2,
      level: 'error',
      type: 'SemgrepError',
      message: 'Failed to download configuration from https://semgrep.dev/c/p/fake-aaa HTTP 404.',
    },
    {
      code: 2,
      level: 'error',
      type: 'SemgrepError',
      message: 'Failed to download configuration from https://semgrep.dev/c/p/fake-bbb HTTP 404.',
    },
    {
      code: 7,
      level: 'error',
      type: 'SemgrepError',
      message: 'invalid configuration file found (2 configs were invalid)',
    },
  ],
  paths: { scanned: [] },
});

const CLEAN_JSON = JSON.stringify({
  version: '1.164.0',
  results: [{ check_id: 'x', path: 'a.js', start: { line: 1 }, end: { line: 1 }, extra: {} }],
  errors: [],
  paths: { scanned: ['a.js'] },
});

describe('findConfigDownloadFailures', () => {
  it('returns [] for null input (file missing / scanner never ran)', () => {
    expect(findConfigDownloadFailures(null)).toEqual([]);
  });

  it('returns [] for unparsable JSON rather than throwing', () => {
    expect(findConfigDownloadFailures('{not json')).toEqual([]);
  });

  it('returns [] when errors[] is empty — the ordinary clean-scan case', () => {
    expect(findConfigDownloadFailures(CLEAN_JSON)).toEqual([]);
  });

  it('extracts the pack name from a single download-failure entry', () => {
    const failures = findConfigDownloadFailures(SINGLE_FAILURE_JSON);
    expect(failures).toHaveLength(1);
    expect(failures[0]?.pack).toBe('p/does-not-exist');
    expect(failures[0]?.message).toContain('HTTP 404');
  });

  it('does NOT report the trailing "N configs were invalid" summary line as its own failure', () => {
    // That line names no pack at all — treating it as a second failure would
    // double-count against a single dead config.
    const failures = findConfigDownloadFailures(SINGLE_FAILURE_JSON);
    expect(failures.some((f) => f.message.includes('configs were invalid'))).toBe(false);
  });

  it('extracts every failed pack when more than one config fails at once', () => {
    const failures = findConfigDownloadFailures(DOUBLE_FAILURE_JSON);
    expect(failures.map((f) => f.pack).sort()).toEqual(['p/fake-aaa', 'p/fake-bbb']);
  });

  it('is not fooled by an unrelated error that happens to be present', () => {
    const withUnrelatedError = JSON.stringify({
      results: [],
      errors: [{ code: 1, level: 'warn', type: 'PartialParsing', message: 'could not parse src/weird.ts' }],
    });
    expect(findConfigDownloadFailures(withUnrelatedError)).toEqual([]);
  });
});

describe('survivingPacks', () => {
  it('drops only the packs named by a failure', () => {
    const failures = findConfigDownloadFailures(SINGLE_FAILURE_JSON);
    expect(survivingPacks(['p/does-not-exist', 'p/security-audit'], failures)).toEqual([
      'p/security-audit',
    ]);
  });

  it('returns [] when every configured pack failed', () => {
    const failures = findConfigDownloadFailures(DOUBLE_FAILURE_JSON);
    expect(survivingPacks(['p/fake-aaa', 'p/fake-bbb'], failures)).toEqual([]);
  });

  it('returns the full list unchanged when nothing failed', () => {
    expect(survivingPacks(['p/a', 'p/b'], [])).toEqual(['p/a', 'p/b']);
  });

  it('does not drop a configured pack merely because an unattributed failure exists', () => {
    // pack: null (message didn't match the URL shape) must not be treated as
    // "matches everything" — only exact pack names get filtered out.
    expect(survivingPacks(['p/a', 'p/b'], [{ pack: null, message: 'mystery' }])).toEqual([
      'p/a',
      'p/b',
    ]);
  });
});

describe('describeConfigFailures', () => {
  it('names the pack and the reason for each failure', () => {
    const failures = findConfigDownloadFailures(SINGLE_FAILURE_JSON);
    const text = describeConfigFailures(failures);
    expect(text).toContain('p/does-not-exist');
    expect(text).toContain('HTTP 404');
  });

  it('falls back to "unknown config" for an unattributed failure', () => {
    expect(describeConfigFailures([{ pack: null, message: 'mystery' }])).toContain(
      'unknown config',
    );
  });
});
