/**
 * `hooks/secretScan.ts`.
 *
 * Timing (review round 3, item 8; review 3.0, R7 rounds 1 and 2) — see
 * test/helpers/timing.ts. A line is read in 16 KB windows, so a rule that is
 * quadratic inside a window costs a constant per window and the whole line
 * stays linear: a ratio of two line lengths cannot see it (the JWT finder's
 * defect, ~90 ms a window, read 4.09 for 4x and passed). Each shape therefore
 * gets three measurements: a ratio INSIDE one window (250 against 2 000
 * characters), a ratio across windows (4 KB against 32 KB, for a scan that
 * stopped windowing), and a ceiling at 250 KB — eighteen windows — against
 * the same scan of a benign line of the same length. Each of the three rules
 * that were quadratic inside a window — jwt, generic-assignment-env,
 * uri-credentials — reintroduced in the source fails at least one of them by
 * its assertion. The absolute bounds run only with `GUARDIAN_PERF_STRICT=1`
 * (a quiet machine).
 */

import { describe, expect, it } from 'vitest';
import {
  SECRET_RULES,
  redact,
  scanForSecrets,
  shannonEntropy,
} from '../../../src/hooks/secretScan.js';
import { costOf, expectLinear, expectNearReference, PERF_STRICT } from '../../helpers/timing.js';

/** A line of `length` characters with nothing a rule starts on twice: the reference of the ceilings. */
const benignLine = (length: number): string => 'the quick brown fox. '.repeat(Math.ceil(length / 21)).slice(0, length);
/** The ceiling: a pathological 250 KB line against a benign one. Current code reads 0.6-8.2x at 100% CPU; the defects it catches 308-531x. */
const MAX_REFERENCE_RATIO = 30;

describe('scanForSecrets — high-confidence provider tokens', () => {
  it('detects an AWS access key id', () => {
    const hits = scanForSecrets('const k = "AKIAIOSFODNN7EXAMPLE";');
    expect(hits.map((h) => h.ruleId)).toContain('aws-access-key-id');
    expect(hits[0]?.confidence).toBe('high');
  });

  it('detects a classic GitHub token', () => {
    const token = 'ghp_' + 'a'.repeat(36);
    const hits = scanForSecrets(`GITHUB_TOKEN=${token}`);
    expect(hits.map((h) => h.ruleId)).toContain('github-token');
  });

  it('detects an Anthropic API key', () => {
    const hits = scanForSecrets('ANTHROPIC_API_KEY="sk-ant-api03-abcDEF1234567890abcDEF12"');
    expect(hits.map((h) => h.ruleId)).toContain('anthropic-api-key');
  });

  it('detects a private key header', () => {
    const hits = scanForSecrets('-----BEGIN OPENSSH PRIVATE KEY-----\nMIIE...');
    expect(hits.map((h) => h.ruleId)).toContain('private-key-block');
  });

  it('reports the 1-based line of the hit', () => {
    const text = ['line one', 'line two', 'AKIAIOSFODNN7EXAMPLE'].join('\n');
    const hits = scanForSecrets(text);
    expect(hits.find((h) => h.ruleId === 'aws-access-key-id')?.line).toBe(3);
  });
});

describe('scanForSecrets — redaction', () => {
  it('never returns the raw secret', () => {
    const secret = 'AKIAIOSFODNN7EXAMPLE';
    const hits = scanForSecrets(`key = "${secret}"`);
    for (const h of hits) {
      expect(h.preview).not.toContain(secret);
    }
  });

  it('redact() keeps only a short shape preview', () => {
    expect(redact('AKIAIOSFODNN7EXAMPLE')).toMatch(/^AKIA….* \(\d+\)$/);
  });
});

describe('scanForSecrets — generic heuristic + placeholders', () => {
  it('flags a high-entropy hard-coded password', () => {
    const hits = scanForSecrets('password = "Gx7$kPq2zVw9MtRb"');
    expect(hits.map((h) => h.ruleId)).toContain('generic-assignment');
    expect(hits.find((h) => h.ruleId === 'generic-assignment')?.confidence).toBe('medium');
  });

  it('ignores obvious placeholders', () => {
    expect(scanForSecrets('api_key = "your-api-key-here"')).toHaveLength(0);
    expect(scanForSecrets('password = "changeme123456"')).toHaveLength(0);
    expect(scanForSecrets('token = "${process.env.TOKEN}"')).toHaveLength(0);
  });

  it('ignores low-entropy repetitive values', () => {
    expect(scanForSecrets('secret = "aaaaaaaaaaaaaaaa"')).toHaveLength(0);
  });

  it('does not flag an env-var reference', () => {
    expect(scanForSecrets('const key = process.env.API_KEY')).toHaveLength(0);
  });
});

describe('scanForSecrets — options', () => {
  it('minConfidence=high suppresses heuristic medium hits', () => {
    const hits = scanForSecrets('password = "Gx7$kPq2zVw9MtRb"', { minConfidence: 'high' });
    expect(hits).toHaveLength(0);
  });

  it('still reports high hits when minConfidence=high', () => {
    const hits = scanForSecrets('AKIAIOSFODNN7EXAMPLE', { minConfidence: 'high' });
    expect(hits).toHaveLength(1);
  });

  it('allowlist substring skips a matching line', () => {
    const text = 'AKIAIOSFODNN7EXAMPLE # pragma: allowlist secret';
    expect(scanForSecrets(text, { allowlist: ['allowlist secret'] })).toHaveLength(0);
  });
});

describe('shannonEntropy', () => {
  it('is 0 for an empty string and low for repetition', () => {
    expect(shannonEntropy('')).toBe(0);
    expect(shannonEntropy('aaaaaaaa')).toBe(0);
  });

  it('is higher for mixed characters', () => {
    expect(shannonEntropy('Gx7$kPq2zVw9MtRb')).toBeGreaterThan(3.2);
  });
});

/**
 * task-1, finding 7: the generic rule's key-name matching missed
 * SCREAMING_SNAKE (`DB_PASSWORD`), JSON's quoted key immediately followed by
 * `:` (there is a closing `"` in between that the old pattern did not allow
 * for), camelCase (`stripeSecretKey`), and unquoted `.env`-style assignment.
 * Each row is a positive; the false-positive rows at the bottom must stay silent.
 */
describe('scanForSecrets — task-1: generic credential detection (finding 7)', () => {
  const positive: Array<{ name: string; line: string }> = [
    { name: 'SCREAMING_SNAKE with spaces', line: 'DB_PASSWORD = "Gx7$kPq2zVw9Mt"' },
    { name: 'SCREAMING_SNAKE with colon', line: 'JWT_SECRET: "Gx7$kPq2zVw9Mt"' },
    { name: 'SCREAMING_SNAKE no spaces', line: 'GITHUB_TOKEN = "Gx7$kPq2zVw9Mt"' },
    { name: 'SCREAMING_SNAKE tight equals', line: 'OPENAI_API_KEY="Gx7$kPq2zVw9Mt"' },
    { name: 'camelCase secret key', line: 'const stripeSecretKey = "Gx7$kPq2zVw9Mt";' },
    { name: 'camelCase password', line: 'const dbPassword = "Gx7$kPq2zVw9Mt";' },
    { name: 'camelCase token', line: 'const githubToken = "Gx7$kPq2zVw9Mt";' },
    { name: 'JSON quoted key', line: '"password": "Gx7$kPq2zVw9Mt"' },
    // The exact example from the task brief — a real, human-chosen `.env`
    // password (~2.8 bits/char) that must still be caught despite falling
    // under the entropy floor used for the quoted rules above.
    { name: 'unquoted .env line', line: 'DB_PASSWORD=hunter2hunter2' },
    { name: 'unquoted .env line with export', line: 'export ANTHROPIC_API_KEY=sk-ant-api03-abcDEF1234567890abcDEF12' },
  ];

  for (const { name, line } of positive) {
    it(`flags: ${name}`, () => {
      const hits = scanForSecrets(line);
      expect({ line, hits: hits.length }).toEqual({ line, hits: expect.any(Number) });
      expect(hits.length).toBeGreaterThan(0);
      for (const h of hits) expect(h.preview).not.toMatch(/Gx7\$kPq2zVw9Mt|hunter2hunter2|sk-ant-/);
    });
  }

  const negative: Array<{ name: string; line: string }> = [
    { name: 'assigned from a function call', line: 'const password = getPassword();' },
    { name: 'TypeScript type annotation', line: 'function f(token: string) {}' },
    { name: 'interpolated env var reference', line: 'const token = `${process.env.TOKEN}`;' },
    { name: 'bare ${VAR} unquoted', line: 'PASSWORD=${OTHER_VAR}' },
    { name: 'angle-bracket placeholder', line: 'api_key = "<your-key>"' },
    { name: 'changeme placeholder', line: 'password = "changeme"' },
    { name: 'xxxx placeholder', line: 'token = "xxxx"' },
    { name: 'empty string', line: 'password = ""' },
    { name: 'empty unquoted', line: 'DB_PASSWORD=' },
    { name: 'an ordinary word containing "key" is not a credential name', line: 'const monkeyName = "harambe the gorilla";' },
  ];

  for (const { name, line } of negative) {
    it(`does not flag: ${name}`, () => {
      expect(scanForSecrets(line)).toHaveLength(0);
    });
  }

  it('URI credentials are detected', () => {
    const hits = scanForSecrets('DATABASE_URL = "postgres://svc_user:S0meLongPassw0rd@db.internal/app"');
    expect(hits.length).toBeGreaterThan(0);
    for (const h of hits) expect(h.preview).not.toContain('S0meLongPassw0rd');
  });
});

/** task-1, finding 8: an Anthropic key must not ALSO read as an OpenAI key. */
describe('scanForSecrets — task-1: no double-report of an Anthropic key (finding 8)', () => {
  it('reports sk-ant-… once, as anthropic-api-key only', () => {
    const hits = scanForSecrets('ANTHROPIC_API_KEY="sk-ant-api03-abcDEF1234567890abcDEF12"');
    const ids = hits.map((h) => h.ruleId);
    expect(ids).toContain('anthropic-api-key');
    expect(ids).not.toContain('openai-api-key');
  });

  it('a real OpenAI key is still detected', () => {
    const hits = scanForSecrets(`OPENAI_API_KEY="sk-${'a'.repeat(40)}"`);
    expect(hits.map((h) => h.ruleId)).toContain('openai-api-key');
  });

  it('an sk-proj-… key is still detected as OpenAI', () => {
    const hits = scanForSecrets(`OPENAI_API_KEY="sk-proj-${'a'.repeat(40)}"`);
    expect(hits.map((h) => h.ruleId)).toContain('openai-api-key');
  });
});

/**
 * The timing tests of one line shape, `make(length)` a line of about that many
 * characters (see the file header): a ratio inside one window, a ratio across
 * windows, a ceiling at `ceilingLength` against a benign line, and — with
 * `GUARDIAN_PERF_STRICT=1` only — an absolute bound at that length.
 */
function lineShape(label: string, make: (length: number) => string, ceilingLength: number, strictMs: number): void {
  it(`${label}: inside one window, eight times as long costs well under 22.6 times as much`, () => {
    expectLinear(`${label} (in a window)`, (n) => scanForSecrets(make(n)), 250);
  }, 120_000);
  it(`${label}: across windows, eight times as long costs well under 22.6 times as much`, () => {
    expectLinear(`${label} (across windows)`, (n) => scanForSecrets(make(n)), 4 * 1024);
  }, 120_000);
  it(`${label}: ${String(ceilingLength / 1000)} KB costs at most ${String(MAX_REFERENCE_RATIO)}x a benign line of that length`, () => {
    expectNearReference(label, () => scanForSecrets(make(ceilingLength)), () => scanForSecrets(benignLine(ceilingLength)), {
      maxRatio: MAX_REFERENCE_RATIO,
    });
  }, 120_000);
  it.runIf(PERF_STRICT)(`${label}: ${String(ceilingLength / 1000)} KB in under ${String(strictMs)} ms (GUARDIAN_PERF_STRICT=1)`, () => {
    expect(costOf(() => scanForSecrets(make(ceilingLength)))).toBeLessThan(strictMs);
  }, 60_000);
}

/** task-1, finding 9: ReDoS caps — both inputs must resolve in bounded time (see the header on timing). */
describe('scanForSecrets — task-1: ReDoS caps (finding 9)', () => {
  // Typical, idle, at 50 000 repeats (200 KB): under 20 ms.
  lineShape('a pathological JWT-shaped repeat', (n) => 'eyJ-'.repeat(Math.ceil(n / 4)), 200_000, 500);

  it('a real JWT is still detected after the pattern was bounded', () => {
    const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
    const payload = Buffer.from(JSON.stringify({ sub: '1234567890', name: 'Test' })).toString('base64url');
    const jwt = `${header}.${payload}.abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG`;
    const hits = scanForSecrets(`Authorization: Bearer ${jwt}`);
    expect(hits.map((h) => h.ruleId)).toContain('jwt');
  });

  // Typical, idle, at 100 KB: under 5 ms.
  lineShape('a single long unquoted line', (n) => `password = "${'a'.repeat(n)}"`, 100_000, 500);
});

/**
 * Review of 3.0.0, I3: only the first 16 KB of a line was read, so a token at
 * column ~16.4K of a one-line JSON file or a minified bundle passed the opt-in
 * block, the PostToolUse warning and `check --file`. A long line is now read
 * in overlapping 16 KB windows — each bounded, the total linear.
 */
describe('scanForSecrets — a long line is read to its end (review I3)', () => {
  const TOKEN = `ghp_${'A1b2C3d4E5'.repeat(3)}xY9zQ8`;
  const at = (column: number, filler = 'a'): string => `{"k":"${filler.repeat(column - 6)}", "t": "${TOKEN}"}`;

  it.each([16_300, 16_350, 16_374, 16_384, 16_400, 30_000, 1_000_000])('finds a token at column %i', (column) => {
    const line = at(column);
    expect(line.indexOf(TOKEN)).toBeGreaterThanOrEqual(column);
    for (const minConfidence of ['high', 'medium'] as const) {
      const hits = scanForSecrets(line, { minConfidence });
      expect(hits.map((h) => h.ruleId)).toContain('github-token');
      expect(hits.find((h) => h.ruleId === 'github-token')?.line).toBe(1);
    }
  });

  it('finds a token on a later long line, with its line number', () => {
    const text = `short\n${at(40_000)}\nafter`;
    expect(scanForSecrets(text).find((h) => h.ruleId === 'github-token')?.line).toBe(2);
  });

  it('reports a token once, even where two windows overlap', () => {
    const hits = scanForSecrets(at(15_000));
    expect(hits.filter((h) => h.ruleId === 'github-token')).toHaveLength(1);
  });

  it('a window edge never makes a token of a longer run: no hit where the whole line has none', () => {
    // A 60-character run after `ghp_` is no GitHub token (`{36}\b`), wherever
    // a window happens to cut it; nor is `xghp_…`, whose `\b` is missing.
    for (let column = 16_300; column <= 16_400; column += 1) {
      const run = `ghp_${'b'.repeat(60)}`;
      const line = `${'a '.repeat(column / 2)}${run} tail`;
      expect(scanForSecrets(line, { minConfidence: 'high' }).map((h) => h.ruleId)).not.toContain('github-token');
    }
    for (let column = 14_300; column <= 14_400; column += 1) {
      const line = `${'a '.repeat(column / 2)}xghp_${'c'.repeat(36)} tail`;
      expect(scanForSecrets(line, { minConfidence: 'high' }).map((h) => h.ruleId)).not.toContain('github-token');
    }
  });

  // Review round 3, item 6: a JWT longer than the 2 KB overlap that crossed a
  // window edge was in no window whole. The JWT finder has its own 8 KB
  // overlap: every JWT the pattern can match (at most 2000 characters a
  // segment, ~6 KB in all) lies whole in some window.
  it('a JWT up to ~6 KB is found wherever it crosses a window edge', () => {
    const seg = (n: number, c: string): string => `${c.repeat(n - 1)}Q`;
    const jwt = `eyJ${seg(1990, 'a')}.eyJ${seg(1990, 'b')}.${seg(1990, 'c')}`;
    expect(jwt.length).toBeGreaterThan(5900);
    for (let column = 10_000; column <= 16_400; column += 400) {
      const line = `${'z '.repeat(column / 2)}${jwt} tail`;
      const hits = scanForSecrets(line);
      expect({ column, found: hits.some((h) => h.ruleId === 'jwt') }).toEqual({ column, found: true });
    }
  });

  it('the allowlist still silences what it names', () => {
    expect(scanForSecrets(at(20_000), { allowlist: [TOKEN] })).toEqual([]);
  });

  // The linear finders must agree with the patterns they replace: a seeded
  // random walk over the pieces those patterns are made of.
  it('every linear finder agrees with its pattern on 6000 random texts', () => {
    const pieces = [
      'eyJ', '.', 'eyJhbGciOi', 'abcdefgh', 'ABCDEFGHIJ', '-', '_', ' ', '"', '=', 'token', 'password', 'api_key',
      'secret_key', 'Token', 'access_token', '12345678', 'x', '\t', '$', '(', ')', 'a'.repeat(40), 'b'.repeat(900),
      'c'.repeat(1990), 'Q'.repeat(2005),
    ];
    let seed = 7;
    const rnd = (n: number): number => {
      seed = (seed * 1103515245 + 12345) % 2147483648;
      return seed % n;
    };
    const withFind = SECRET_RULES.filter((r) => r.find !== undefined);
    expect(withFind.map((r) => r.id).sort()).toEqual(['generic-assignment-env', 'jwt']);
    for (let k = 0; k < 6000; k += 1) {
      const text = Array.from({ length: 1 + rnd(14) }, () => pieces[rnd(pieces.length)] ?? '').join('');
      const from = rnd(3) === 0 ? rnd(Math.max(1, text.length)) : 0;
      for (const rule of withFind) {
        const re = new RegExp(rule.pattern.source, `${rule.pattern.flags}g`);
        re.lastIndex = from;
        const want = re.exec(text);
        const got = rule.find?.(text, from) ?? null;
        const same =
          want === null
            ? got === null
            : got !== null && got.index === want.index && got.text === want[0] && (got.value ?? undefined) === (want[1] ?? undefined);
        if (!same) throw new Error(`${rule.id} disagrees from ${from} on ${JSON.stringify(text.slice(0, 200))}…`);
      }
    }
  });

  // The windows are bounded, and so is every rule within one: the three
  // medium rules that were quadratic inside a 16 KB window (≈0.1-0.5 s each)
  // would have made a 1 MB line cost tens of seconds.
  describe('the cost is linear in the length of the line', () => {
    const shapes: Array<[string, (n: number) => string]> = [
      ['eyJ-', (n) => 'eyJ-'.repeat(Math.ceil(n / 4))],
      ['a-', (n) => 'a-'.repeat(Math.ceil(n / 2))],
      ['sk-', (n) => 'sk-'.repeat(Math.ceil(n / 3))],
      ['token= … "', (n) => `${'token='.repeat(Math.ceil(n / 6))}"`],
      ['Token= … "', (n) => `${'xToken='.repeat(Math.ceil(n / 7))}"`],
      ['a://b:', (n) => 'a://b:'.repeat(Math.ceil(n / 6))],
      ['password=" … (unclosed)', (n) => `password="${'q'.repeat(n)}`],
      ['one minified line', (n) => 'var a=function(b){return b+1};'.repeat(Math.ceil(n / 30))],
    ];
    // Typical, idle: 30-140 ms for a 1 MB line of each shape; the ceiling and
    // the strict bound (400 ms) are at 250 KB.
    for (const [label, make] of shapes) lineShape(label, make, 250_000, 400);
  });
});

/**
 * task-1, finding 11: redact() must show at most 4 characters total for any
 * secret shorter than 16 characters — today's `length > 12` threshold still
 * reveals 6 of a 13-15 char secret.
 */
describe('redact — task-1: short secrets reveal at most 4 characters (finding 11)', () => {
  it('a 13-character secret reveals only the 4-character head', () => {
    const secret = 'abcdefghijklm'; // 13 chars
    expect(redact(secret)).toBe(`abcd… (${secret.length})`);
  });

  it('a 15-character secret reveals only the 4-character head', () => {
    const secret = 'abcdefghijklmno'; // 15 chars
    expect(redact(secret)).toBe(`abcd… (${secret.length})`);
  });

  it('a 16-character-or-longer secret still reveals a head and tail', () => {
    const secret = 'abcdefghijklmnop'; // 16 chars
    expect(redact(secret)).toBe(`abcd…op (${secret.length})`);
  });
});
