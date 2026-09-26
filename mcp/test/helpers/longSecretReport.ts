/**
 * An unredacted gitleaks report of `k` findings that overlap NOTHING, each
 * carrying a long value — a ~1700-character private-key-shaped block, the
 * longest value gitleaks' default rules report. The common case for
 * `sanitizeGitleaksReport`, and the one a per-run matcher made 30x slower and
 * ~110 KB per finding heavier (fix round 1 of the follow-up review).
 *
 * The blocks are pseudo-random base64-alphabet text, not keys: nothing here
 * is a credential. Each finding sits on its own lines of one of 50 files.
 */

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

/**
 * The value of finding `n`: deterministic, distinct per `n`. Built with one
 * `join`, never `+=` per character: 1700 concatenations per value left 4000
 * values holding ~7 million intermediate string nodes, and the heap check
 * below measured THAT instead of the sanitizer.
 */
export function longValue(n: number): string {
  const chars: string[] = [];
  let x = (n * 2_654_435_761 + 1) >>> 0;
  while (chars.length < 1_700) {
    x = (Math.imul(x, 1_103_515_245) + 12_345) >>> 0;
    chars.push(ALPHABET[x % 64] ?? 'A');
    if (chars.length % 65 === 64) chars.push('\n');
  }
  return [['-----BEGIN', 'PRIVATE KEY-----'].join(' '), chars.join(''), ['-----END', 'PRIVATE KEY-----'].join(' ')].join('\n');
}

/** The report, as gitleaks writes it without `--redact`. */
export function longSecretReport(k: number): string {
  const items = Array.from({ length: k }, (_, n) => {
    const value = longValue(n);
    return {
      RuleID: 'private-key',
      Description: 'Private Key',
      StartLine: 1 + n * 40,
      EndLine: 1 + n * 40 + 28,
      StartColumn: 1,
      EndColumn: 26,
      Match: value,
      Secret: value,
      File: `keys/k${n % 50}.pem`,
      SymlinkFile: '',
      Commit: 'c0ffee',
      Entropy: 6,
      Author: '',
      Email: '',
      Date: '',
      Message: 'add keys',
      Tags: [],
      Fingerprint: `c0ffee:keys/k${n % 50}.pem:private-key:${1 + n * 40}`,
    };
  });
  return JSON.stringify(items);
}
