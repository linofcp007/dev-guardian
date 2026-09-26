/**
 * Runs `configs/semgrep/rgpd.yml` against the fixture pairs in
 * `mcp/test/fixtures/rgpd/{hits,misses}/` and asserts, per file, the EXACT
 * count of every rule, the number of files Semgrep actually scanned, and —
 * for the personal-data-in-log fixtures — the exact LINES that fire.
 *
 * The pack has two halves with nothing in common but the regulation:
 *
 *  - `rgpd-pii-in-log-{js,php,py,cs}`: an identifier NAMED like a Portuguese
 *    personal identifier (NIF, NISS, Cartão de Cidadão, IBAN, telefone, email)
 *    inside a logging call. Syntax, not dataflow: the name is the evidence.
 *  - `rgpd-tracker-*` / `rgpd-youtube-*`: a tracker loaded by markup (HTML,
 *    PHP templates, JSX/TSX, Vue, Twig) with none of the consent guards the
 *    pack recognises. Regex rules in `generic` mode, restricted by
 *    `paths.include`.
 *
 * The in-repo fixture path contains a `test/` segment, which Semgrep's
 * default ignore list skips wholesale — which is why fixtures are copied to a
 * temp dir first, and why the scanned count is asserted every time.
 *
 * SKIPPED, not silently passed, when Semgrep is absent;
 * `GUARDIAN_REQUIRE_SEMGREP=1` turns that absence into a hard failure.
 */

import { afterAll, describe, expect, it, vi } from 'vitest';

// Real, synchronous `semgrep` calls are not bounded by vitest's default
// testTimeout; see baseRules.test.ts.
vi.setConfig({ testTimeout: 180_000 });
import { execFileSync } from 'node:child_process';
import { cpSync, existsSync, readdirSync, readFileSync } from 'node:fs';
import { basename, extname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parse } from 'yaml';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';

afterAll(cleanupTempDirs);

const REPO_ROOT = resolve(fileURLToPath(new URL('../../..', import.meta.url)));
const RULES = resolve(REPO_ROOT, 'configs', 'semgrep', 'rgpd.yml');
const FIXTURES = resolve(REPO_ROOT, 'mcp', 'test', 'fixtures', 'rgpd');
const TEMPLATES = resolve(REPO_ROOT, 'configs', 'compliance', 'cookie-banner');
const REQUIRE_SEMGREP = process.env['GUARDIAN_REQUIRE_SEMGREP'] === '1';

function semgrepAvailable(): boolean {
  try { execFileSync('semgrep', ['--version'], { stdio: 'ignore' }); return true; }
  catch { return false; }
}
const AVAILABLE = semgrepAvailable();

interface SemgrepResult {
  check_id: string;
  path: string;
  start: { line: number };
  extra?: { severity?: string };
}

interface SemgrepRun {
  readonly rows: SemgrepResult[];
  readonly scanned: number;
  readonly errors: number;
}

function run(config: string, dir: string): SemgrepRun {
  const work = makeTempDir('guardian-rgpd-');
  cpSync(dir, work, { recursive: true });
  const out = execFileSync(
    'semgrep',
    ['--config', config, '--json', '--quiet', '--no-git-ignore', '--metrics=off', work],
    { encoding: 'utf8', maxBuffer: 32 * 1024 * 1024 },
  );
  const parsed = JSON.parse(out) as { results?: unknown[]; errors?: unknown[]; paths?: { scanned?: unknown[] } };
  return {
    rows: (parsed.results ?? []) as SemgrepResult[],
    scanned: (parsed.paths?.scanned ?? []).length,
    errors: (parsed.errors ?? []).length,
  };
}

/** Last dot-separated segment — semgrep prefixes the config path onto ids. */
function ruleOf(row: SemgrepResult): string {
  return row.check_id.split('.').pop() ?? row.check_id;
}

/** `{ ruleId: count }` per basename, from RAW rows (no dedup). */
function countsByFile(rows: readonly SemgrepResult[]): Record<string, Record<string, number>> {
  const out: Record<string, Record<string, number>> = {};
  for (const row of rows) {
    const file = basename(row.path);
    const byRule = out[file] ?? {};
    byRule[ruleOf(row)] = (byRule[ruleOf(row)] ?? 0) + 1;
    out[file] = byRule;
  }
  return out;
}

function filesIn(dir: string): string[] {
  return readdirSync(dir).sort();
}

const PII_JS = 'rgpd-pii-in-log-js';
const PII_PHP = 'rgpd-pii-in-log-php';
const PII_PY = 'rgpd-pii-in-log-py';
const PII_CS = 'rgpd-pii-in-log-cs';
const GA4 = 'rgpd-tracker-ga4-without-consent';
const META = 'rgpd-tracker-meta-pixel-without-consent';
const HOTJAR = 'rgpd-tracker-hotjar-without-consent';
const YOUTUBE = 'rgpd-youtube-embed-without-nocookie';

/**
 * The exact count of every rule in every `hits/` fixture. A fixture on disk
 * with no entry here fails Step 0 rather than being silently unmeasured.
 */
const EXPECTED_HITS: Readonly<Record<string, Readonly<Record<string, number>>>> = {
  // Fifteen: thirteen single-finding lines and one line holding two names.
  // The last two lines are bugs BESIDE a guard shape (a masked email, the
  // last four digits of an IBAN): an exclusion keyed one notch too wide
  // would swallow the bug next to it, and the count would drop.
  'pii_log.js': { [PII_JS]: 15 },
  // The same rule through the TypeScript parser: a typed member, a type
  // assertion, a typed parameter, a subscript.
  'pii_log.ts': { [PII_JS]: 4 },
  // WordPress/WooCommerce shapes (`$user->user_email`,
  // `$order->get_billing_email()`), interpolation, PSR-3, the Laravel facade,
  // syslog, and two bugs beside a hashed/truncated neighbour. Thirteen, not
  // ten: the first ablation run read the name branch's `->`, `::` and
  // `syslog(...)` alternatives DEAD because every plain variable here sat in
  // an `error_log`, and the facade's method filter DEAD because nothing but a
  // PSR-3 level was ever called on it. One line per alternative now, and the
  // method filter is gone (`Log::withContext` is a log sink too).
  'pii_log.php': { [PII_PHP]: 13 },
  'pii_log.py': { [PII_PY]: 9 },
  'PiiLog.cs': { [PII_CS]: 10 },
  // Two GA4 loaders (the stock snippet, and `type="text/javascript"`, which
  // still executes), the Meta pixel AFTER a consent function that has
  // already closed, Hotjar, and a youtube.com embed.
  'trackers.html': { [GA4]: 2, [META]: 1, [HOTJAR]: 1, [YOUTUBE]: 1 },
  // Consent Mode with GRANTED defaults is not a guard.
  'consent_granted.html': { [GA4]: 1 },
  // WordPress: `wp_enqueue_script` and the inline tag, a pixel, an embed.
  'header.php': { [GA4]: 2, [META]: 1, [YOUTUBE]: 1 },
  // Next.js: `<Script>`, `@next/third-parties`' `<GoogleAnalytics>`, a
  // NON-consent condition (`NODE_ENV === 'production' &&`), an embed.
  'Analytics.jsx': { [GA4]: 3, [YOUTUBE]: 1 },
  'layout.tsx': { [HOTJAR]: 1 },
  'Video.vue': { [YOUTUBE]: 1 },
  'base.twig': { [GA4]: 1 },
  'pixel.htm': { [META]: 1 },
};

/**
 * The files whose `// BUG:` / `# BUG:` markers sit on the very line that
 * fires (the log calls). For these the LINE set is asserted, not only the
 * count: a count can survive one finding moving to the wrong line. The colon
 * is part of the marker, so a header that merely talks about markers is not
 * one.
 */
const LINE_CHECKED = ['pii_log.js', 'pii_log.ts', 'pii_log.php', 'pii_log.py', 'PiiLog.cs'];

function expectedLines(file: string): number[] {
  const lines: number[] = [];
  readFileSync(resolve(FIXTURES, 'hits', file), 'utf8')
    .split('\n')
    .forEach((text, i) => {
      if (!/(?:\/\/|#) BUG(?: x\d+)?:/.test(text)) return;
      const times = /BUG x(\d+):/.exec(text)?.[1];
      for (let n = 0; n < (times === undefined ? 1 : Number(times)); n += 1) lines.push(i + 1);
    });
  return lines;
}

/** The designed tier of every rule — see the pack's header for the criterion. */
const EXPECTED_SEVERITY: Readonly<Record<string, string>> = {
  [PII_JS]: 'WARNING',
  [PII_PHP]: 'WARNING',
  [PII_PY]: 'WARNING',
  [PII_CS]: 'WARNING',
  [GA4]: 'WARNING',
  [META]: 'WARNING',
  [HOTJAR]: 'WARNING',
  [YOUTUBE]: 'WARNING',
};

interface RuleDoc {
  id: string;
  languages?: string[];
  paths?: { include?: string[] };
}

function packRules(): RuleDoc[] {
  const doc = parse(readFileSync(RULES, 'utf8')) as { rules?: RuleDoc[] };
  return doc.rules ?? [];
}

describe('rgpd rules', () => {
  it.runIf(REQUIRE_SEMGREP)('the toolchain must be usable when the flag is set', () => {
    expect(AVAILABLE).toBe(true);
  });

  it('the rule file exists where compliance_check will look for it', () => {
    expect(existsSync(RULES)).toBe(true);
  });

  it('Step 0: every hits/ fixture on disk has a registered expectation, and vice versa', () => {
    expect(filesIn(resolve(FIXTURES, 'hits'))).toEqual(Object.keys(EXPECTED_HITS).sort());
  });

  it('declares exactly the rules the fixtures are written for', () => {
    expect(packRules().map((r) => r.id).sort()).toEqual(Object.keys(EXPECTED_SEVERITY).sort());
  });

  it.skipIf(!AVAILABLE)('fires exactly the expected rules, exactly the expected number of times, in EACH hit fixture', () => {
    const hitsDir = resolve(FIXTURES, 'hits');
    const { rows, scanned, errors } = run(RULES, hitsDir);
    expect(errors).toBe(0);
    expect(scanned).toBe(filesIn(hitsDir).length);
    expect(countsByFile(rows)).toEqual(EXPECTED_HITS);
  });

  it.skipIf(!AVAILABLE)('fires on exactly the marked lines of the personal-data-in-log fixtures', () => {
    const { rows } = run(RULES, resolve(FIXTURES, 'hits'));
    for (const file of LINE_CHECKED) {
      const got = rows.filter((r) => basename(r.path) === file).map((r) => r.start.line).sort((a, b) => a - b);
      expect([file, got]).toEqual([file, expectedLines(file)]);
    }
  });

  it.skipIf(!AVAILABLE)('fires NOTHING in EACH near-miss fixture', () => {
    const missesDir = resolve(FIXTURES, 'misses');
    const { rows, scanned, errors } = run(RULES, missesDir);
    expect(errors).toBe(0);
    // Every misses/ file must actually have been looked at, or "nothing" is
    // "never read".
    expect(scanned).toBe(filesIn(missesDir).length);
    expect(rows.map((r) => `${basename(r.path)}:${r.start.line}: ${ruleOf(r)}`)).toEqual([]);
  });

  /**
   * The pack's own prescribed fix is `configs/compliance/cookie-banner/`: the
   * messages point there. A pack that fires on the template it tells people
   * to copy is telling them to make a change it will then complain about —
   * the same whole-pack check `bugfixRulesPhp.test.ts` runs on `fixed/`.
   */
  it.skipIf(!AVAILABLE)('finds NOTHING in the cookie-banner template it prescribes', () => {
    const { rows, scanned, errors } = run(RULES, TEMPLATES);
    expect(errors).toBe(0);
    const scannable = filesIn(TEMPLATES).filter((f) => ['.html', '.js'].includes(extname(f)));
    expect(scanned).toBe(scannable.length);
    expect(scanned).toBeGreaterThan(0);
    expect(rows.map((r) => `${basename(r.path)}:${r.start.line}: ${ruleOf(r)}`)).toEqual([]);
  });

  it.skipIf(!AVAILABLE)('reports each rule at its DESIGNED severity tier', () => {
    const { rows } = run(RULES, resolve(FIXTURES, 'hits'));
    const seen = new Map<string, Set<string>>();
    for (const row of rows) {
      const severity = row.extra?.severity;
      if (severity === undefined) throw new Error(`no severity on ${ruleOf(row)}`);
      const set = seen.get(ruleOf(row)) ?? new Set<string>();
      set.add(severity);
      seen.set(ruleOf(row), set);
    }
    for (const [id, tier] of Object.entries(EXPECTED_SEVERITY)) {
      expect([id, [...(seen.get(id) ?? [])]]).toEqual([id, [tier]]);
    }
  });
});

/**
 * The name regex is the whole precision of the four log rules, and it is
 * written out TWELVE times — three metavariables (`$FIELD`, `$NAME`, `$KEY`)
 * in four languages — because a YAML anchor would not survive the ablation
 * harness's round-trip. Twelve copies drift. So every copy is reduced to its
 * shared body and the bodies must be identical; then the body is exercised as
 * a JavaScript RegExp (it uses nothing PCRE-only — no inline modifiers — so
 * Node 22 evaluates it the way Semgrep does).
 */
describe('the personal-data name regex', () => {
  function nameRegexes(): { rule: string; metavariable: string; regex: string }[] {
    const found: { rule: string; metavariable: string; regex: string }[] = [];
    const walk = (rule: string, node: unknown): void => {
      if (Array.isArray(node)) {
        for (const child of node) walk(rule, child);
        return;
      }
      if (node === null || typeof node !== 'object') return;
      const mr = (node as Record<string, unknown>)['metavariable-regex'];
      if (mr !== null && typeof mr === 'object') {
        const { metavariable, regex } = mr as { metavariable?: unknown; regex?: unknown };
        if (typeof metavariable === 'string' && typeof regex === 'string' && ['$FIELD', '$NAME', '$KEY'].includes(metavariable)) {
          found.push({ rule, metavariable, regex });
        }
      }
      for (const value of Object.values(node)) walk(rule, value);
    };
    for (const r of packRules()) if (r.id.startsWith('rgpd-pii-in-log-')) walk(r.id, r);
    return found;
  }

  /** `^BODY$`, `^\$BODY$` (a PHP variable) or `^['"]BODY['"]$` (a string key). */
  function bodyOf(regex: string): string {
    for (const [open, close] of [['^[\'"]', '[\'"]$'], ['^\\$', '$'], ['^', '$']] as const) {
      if (regex.startsWith(open) && regex.endsWith(close)) return regex.slice(open.length, regex.length - close.length);
    }
    throw new Error(`not a recognised name-regex wrapper: ${regex}`);
  }

  it('is written out for every metavariable of every log rule, with one shared body', () => {
    const regexes = nameRegexes();
    // 4 rules x ($FIELD, $NAME, $KEY), plus a `.get('key')` branch in JS and Python.
    expect(regexes.length).toBe(14);
    expect(new Set(regexes.map((r) => bodyOf(r.regex))).size).toBe(1);
  });

  const body = (): RegExp => {
    const first = nameRegexes()[0];
    if (first === undefined) throw new Error('no name regex in the pack');
    return new RegExp(`^${bodyOf(first.regex)}$`);
  };

  it.each([
    'email', 'userEmail', 'user_email', 'UserEmail', '_email', 'emails', 'emailAddress', 'email_address',
    'nif', 'nifCliente', 'nif_cliente', 'clienteNif', 'customerNIF', 'niss', 'iban', 'customerIban',
    'telefone', 'telemovel', 'phone', 'phoneNumber', 'phone_number', 'PhoneNumber', 'billingPhone',
    'get_billing_email', 'getEmail', 'cartao_cidadao', 'cartaoCidadao', 'cartao_de_cidadao', 'cc_number',
    'ccNumber', 'contribuinte', 'numeroContribuinte', 'numero_seguranca_social', 'NormalizedEmail',
    'formattedPhone', 'sender_email', 'mobilePhone', 'validatedEmail',
  ])('names personal data: %s', (name) => {
    expect(body().test(name)).toBe(true);
  });

  it.each([
    // SCREAMING_CASE is a constant or a setting (`DEFAULT_FROM_EMAIL`), not a data subject's value.
    'EMAIL', 'ADMIN_EMAIL', 'DEFAULT_FROM_EMAIL', 'NIF',
    // A masked, hashed or derived value, or a flag about the value.
    'maskedEmail', 'masked_email', 'emailHash', 'hashedEmail', 'ibanMasked', 'encryptedIban', 'redactedEmail',
    'emailSent', 'email_verified', 'EmailConfirmed', 'PhoneNumberConfirmed', 'isValidEmail', 'hasEmail',
    // A function or a service named after the value, not the value.
    'emailService', 'sendEmail', 'validateEmail', 'normalizeEmail', 'formatPhone', 'setEmail', 'findByEmail',
    'emailTemplate', 'defaultEmail',
    // Words that merely contain one of the stems.
    'iPhone', 'phonebook', 'emailer', 'nifty', 'ibanez', 'phoneType', 'username', 'mail', 'cc',
  ])('does not name personal data: %s', (name) => {
    expect(body().test(name)).toBe(false);
  });
});

describe('the tracker rules are restricted to markup', () => {
  it('every generic-mode rule names the file types it reads, and has a hit fixture of each', () => {
    const hitExts = new Set(filesIn(resolve(FIXTURES, 'hits')).map((f) => extname(f)));
    for (const rule of packRules()) {
      if (!(rule.languages ?? []).includes('generic')) continue;
      const include = rule.paths?.include ?? [];
      // A generic rule with no include list reads EVERY file — .js bundles,
      // .md docs, lock files — and a tracker URL in a README is not a tracker.
      expect([rule.id, include.length > 0]).toEqual([rule.id, true]);
      for (const glob of include) {
        expect([rule.id, glob, hitExts.has(extname(glob))]).toEqual([rule.id, glob, true]);
      }
    }
  });
});
