import { describe, expect, it } from 'vitest';
import {
  describeConfigFailures,
  describeRawErrors,
  findConfigDownloadFailures,
  survivingPacks,
  wasAnythingScanned,
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

// Real Semgrep 1.164.0 output, captured against a deliberately corrupted
// copy of configs/semgrep/bugfix-js.yml (an unclosed `languages: [...]`
// flow-sequence bracket — the kind of stray edit a maintainer could
// actually make): `semgrep --config=<corrupted file> --json <dir>` exits 7
// with `results: []` and `paths: { scanned: [] }` — the WHOLE invocation
// aborted, identical in effect to a registry 404, just a different message
// shape (no URL, no HTTP status). The path shown here is a stand-in for the
// real absolute path the live capture produced; only the identifying
// portion changed; the message's own shape (down to the trailing summary
// line) is verbatim.
const LOCAL_YAML_FAILURE_JSON = JSON.stringify({
  version: '1.164.0',
  results: [],
  errors: [
    {
      code: 5,
      level: 'error',
      type: 'SemgrepError',
      message:
        "Invalid YAML file C:\\fake\\dev-guardian\\configs\\semgrep\\bugfix-js.yml:\n" +
        '\twhile parsing a flow sequence\n' +
        '\t  in "<file>", line 28, column 16\n' +
        "\texpected ',' or ']', but got '-'\n" +
        '\t  in "<file>", line 49, column 3',
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

// Also real, live-captured 1.164.0 output — but for a DIFFERENT corruption:
// only ONE rule's `pattern:` broken (a missing closing brace), the rest of
// the (syntactically valid) YAML file untouched. Unlike the YAML-syntax
// failure above, this does NOT abort the invocation: exit 2 (not 7),
// `type: 'Rule parse error'` (not 'SemgrepError'), and — the load-bearing
// difference — `paths.scanned` is NON-empty and `results` contains a REAL
// finding from a different, still-valid rule in the SAME file. Confirmed
// with the exact three-`--config=` shape bug_hunt actually runs (two
// registry packs + the local file): the registry packs' own coverage is
// untouched by the one broken local rule.
const RULE_PARSE_ERROR_JSON = JSON.stringify({
  version: '1.164.0',
  results: [
    {
      check_id:
        'C.fake.dev-guardian.configs.semgrep.bugfix-js-off-by-one-loop-lte-length',
      path: 'app.ts',
      start: { line: 2, col: 3 },
      end: { line: 2, col: 69 },
      extra: {
        message: 'Provável off-by-one.',
        severity: 'ERROR',
        metadata: {},
      },
    },
  ],
  errors: [
    {
      code: 2,
      level: 'error',
      type: 'Rule parse error',
      rule_id: 'C.fake.dev-guardian.configs.semgrep.bugfix-js-error-handling-empty-catch',
      message:
        'Rule parse error in rule C.fake.dev-guardian.configs.semgrep.' +
        'bugfix-js-error-handling-empty-catch:\n Invalid pattern for JavaScript: ' +
        'Failure: no pattern found\n----- pattern -----\ntry { ... } catch ($E) {\n' +
        '----- end pattern -----\n',
    },
  ],
  paths: { scanned: ['app.ts'] },
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

  it('extracts the absolute path from a local "Invalid YAML file" entry', () => {
    // The local-config equivalent of the registry-404 case above — a
    // hand-edited configs/semgrep/bugfix-js.yml with broken YAML aborts the
    // whole invocation the identical way, just with a different message
    // shape (no URL). bugHunt.ts's retry-survivor mechanism needs the exact
    // path back so survivingPacks can match it against configuredPacks.
    const failures = findConfigDownloadFailures(LOCAL_YAML_FAILURE_JSON);
    expect(failures).toHaveLength(1);
    expect(failures[0]?.pack).toBe('C:\\fake\\dev-guardian\\configs\\semgrep\\bugfix-js.yml');
  });

  it('does NOT report the trailing "N configs were invalid" summary line for a local YAML failure either', () => {
    const failures = findConfigDownloadFailures(LOCAL_YAML_FAILURE_JSON);
    expect(failures.some((f) => f.message.includes('configs were invalid'))).toBe(false);
  });

  it('does NOT treat a "Rule parse error" (one bad rule, file otherwise valid) as a whole-config failure', () => {
    // The discriminating case this fix depends on getting right: unlike the
    // YAML-syntax failure above, a single broken RULE inside an otherwise
    // loadable file does not invalidate that --config= value as a whole
    // (see semgrepConfigFailure.ts's header comment — verified live, other
    // rules in the same file and every sibling --config keep working). If
    // this matched here, survivingPacks would wrongly drop bugfix-js.yml
    // and a retry would throw away the OTHER thirteen rules' real coverage
    // for no reason.
    expect(findConfigDownloadFailures(RULE_PARSE_ERROR_JSON)).toEqual([]);
  });
});

describe('survivingPacks', () => {
  it('drops only the packs named by a failure', () => {
    const failures = findConfigDownloadFailures(SINGLE_FAILURE_JSON);
    expect(survivingPacks(['p/does-not-exist', 'p/security-audit'], failures)).toEqual([
      'p/security-audit',
    ]);
  });

  it('drops the local file path when THAT is what failed, alongside registry packs', () => {
    const failures = findConfigDownloadFailures(LOCAL_YAML_FAILURE_JSON);
    const configured = [
      'p/r2c-bug-scan',
      'p/security-audit',
      'C:\\fake\\dev-guardian\\configs\\semgrep\\bugfix-js.yml',
    ];
    expect(survivingPacks(configured, failures)).toEqual(['p/r2c-bug-scan', 'p/security-audit']);
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

describe('wasAnythingScanned', () => {
  it('returns false for null input', () => {
    expect(wasAnythingScanned(null)).toBe(false);
  });

  it('returns false for unparsable JSON rather than throwing', () => {
    expect(wasAnythingScanned('{not json')).toBe(false);
  });

  it('returns false when the whole invocation aborted (YAML-syntax failure, paths.scanned empty)', () => {
    expect(wasAnythingScanned(LOCAL_YAML_FAILURE_JSON)).toBe(false);
  });

  it('returns true for a genuinely clean scan (paths.scanned non-empty, no errors)', () => {
    expect(wasAnythingScanned(CLEAN_JSON)).toBe(true);
  });

  it('returns true when a rule-parse error left one bad rule but Semgrep still scanned with the rest', () => {
    // The exact case a bare exit-code check gets wrong: exit 2, same as a
    // more serious failure could produce, but paths.scanned proves real
    // work happened. A wrong implementation keying off exitCode/outcome
    // instead would fail this the same way bugHunt.ts used to.
    expect(wasAnythingScanned(RULE_PARSE_ERROR_JSON)).toBe(true);
  });
});

describe('describeRawErrors', () => {
  it('returns null for null input', () => {
    expect(describeRawErrors(null)).toBeNull();
  });

  it('returns null for unparsable JSON rather than throwing', () => {
    expect(describeRawErrors('{not json')).toBeNull();
  });

  it('returns null when errors[] is empty', () => {
    expect(describeRawErrors(CLEAN_JSON)).toBeNull();
  });

  it('names the specific broken rule for a "Rule parse error" — not a generic "semgrep failed"', () => {
    const text = describeRawErrors(RULE_PARSE_ERROR_JSON);
    expect(text).not.toBeNull();
    expect(text).toContain('bugfix-js-error-handling-empty-catch');
    expect(text).toContain('Invalid pattern for JavaScript');
  });

  it('still produces a reason for an entry with no rule_id (e.g. the whole-file YAML failure)', () => {
    const text = describeRawErrors(LOCAL_YAML_FAILURE_JSON);
    expect(text).not.toBeNull();
    expect(text).toContain('Invalid YAML file');
  });
});
