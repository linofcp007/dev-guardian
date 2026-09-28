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
import { semgrepAvailable, semgrepStdout } from '../helpers/semgrep.js';
import { cpSync, existsSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { basename, extname, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parse, stringify } from 'yaml';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';

afterAll(cleanupTempDirs);

const REPO_ROOT = resolve(fileURLToPath(new URL('../../..', import.meta.url)));
const RULES = resolve(REPO_ROOT, 'configs', 'semgrep', 'rgpd.yml');
const FIXTURES = resolve(REPO_ROOT, 'mcp', 'test', 'fixtures', 'rgpd');
const TEMPLATES = resolve(REPO_ROOT, 'configs', 'compliance', 'cookie-banner');
const REQUIRE_SEMGREP = process.env['GUARDIAN_REQUIRE_SEMGREP'] === '1';

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
  /** The temp copy that was scanned: `relative(work, row.path)` is the fixture's own path. */
  readonly work: string;
}

function run(config: string, dir: string): SemgrepRun {
  const work = makeTempDir('guardian-rgpd-');
  cpSync(dir, work, { recursive: true });
  const out = semgrepStdout(['--config', config, '--json', '--quiet', '--no-git-ignore', '--metrics=off', work]);
  const parsed = JSON.parse(out) as { results?: unknown[]; errors?: unknown[]; paths?: { scanned?: unknown[] } };
  return {
    rows: (parsed.results ?? []) as SemgrepResult[],
    scanned: (parsed.paths?.scanned ?? []).length,
    errors: (parsed.errors ?? []).length,
    work,
  };
}

/** A row's path relative to the scanned copy, with `/` separators. */
function fixturePath(result: SemgrepRun, row: SemgrepResult): string {
  return relative(result.work, row.path).split(sep).join('/');
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

/**
 * Every FILE under `dir`, recursively, as `/`-separated relative paths.
 * `misses/` has subdirectories (`__tests__/`, `__mocks__/`, ...: the
 * test-code directories the tracker rules exclude), so a top-level listing
 * would count a directory as a file.
 */
function allFilesIn(dir: string): string[] {
  return readdirSync(dir, { recursive: true, withFileTypes: true })
    .filter((d) => d.isFile())
    .map((d) => relative(dir, resolve(d.parentPath, d.name)).split(sep).join('/'))
    .sort();
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
  // Twenty: seventeen single-finding lines and three holding two names. The
  // last two lines are bugs BESIDE a guard shape (a masked email, the last
  // four digits of an IBAN): an exclusion keyed one notch too wide would
  // swallow the bug next to it, and the count would drop. Fix round 1 added
  // an all-caps member pair (`cliente.NIF`, `cliente.IBAN` — the constant
  // exclusion used to drop both), `truncate(...)` (truncating is not
  // masking), NestJS's static `Logger.log` and pino's `logger.child({...})`.
  // Fix round 2 added `this.hashing.logger.info(..., user.email)`: "hash" in
  // the RECEIVER path used to count as a masking call and hide the line.
  // Twenty-three after the round measured on application code, two lines the
  // attribute-read guard must leave alone: `email.toLowerCase()` (a METHOD
  // call still returns the address) and `user.phone.number` (an attribute
  // whose name is not an id, a date or a size still holds the value).
  // Twenty-four after its review: a log call INSIDE a callback whose result's
  // `.length` is read — the guard's `$V` was the whole `users.filter(...)`
  // call, callback and log call included, and swallowed it.
  'pii_log.js': { [PII_JS]: 24 },
  // The same rule through the TypeScript parser: a typed member, a type
  // assertion, a typed parameter, a subscript.
  'pii_log.ts': { [PII_JS]: 4 },
  // WordPress/WooCommerce shapes (`$user->user_email`,
  // `$order->get_billing_email()`), interpolation, PSR-3, the Laravel facade,
  // syslog, and two bugs beside a hashed/truncated neighbour. Thirteen after
  // the first ablation run (the name branch's `->` and `syslog(...)`
  // alternatives read DEAD until a plain variable sat in each); eighteen
  // after fix round 1: `$cliente->NIF`, the fully-qualified
  // `\Illuminate\Support\Facades\Log::`, `Log::channel(...)->`,
  // `logger()->` and `logger(...)`. Twenty after the application-code round:
  // `$email->toString()` and `$cliente->telefone->numero` (see pii_log.js);
  // twenty-one after its review: a log call inside an arrow `fn` whose
  // result's `->id` is read (see pii_log.js).
  'pii_log.php': { [PII_PHP]: 21 },
  // Thirteen: fix round 1 added keyword arguments whose value is a plain
  // name (`extra={"email": email}`, structlog's `nif=nif_cliente`),
  // structlog's `bind(...)` and an all-caps attribute. Eighteen after the
  // application-code round: `email.lower()`, `user.phone.as_e164`
  // (django-phonenumber-field), a LOGGER inside a Django management command,
  // and `print()` in two classes that are not management commands — one of
  // them a model that merely happens to be named `Command`. Twenty after its
  // review: a log call inside a `lambda` whose result's `.id` is read (see
  // pii_log.js), and `print()` in `class Command(ProcessoCommand)` — a base
  // that merely ends in `Command` is not one of Django's.
  'pii_log.py': { [PII_PY]: 20 },
  // Thirteen: fix round 2 added `Cliente.Email` — a PascalCase PROPERTY, which
  // the type-constant exclusion (`Campos.EMAIL`) must not take for a type.
  // Fifteen after the application-code round: `email.ToLowerInvariant()` and
  // `mensagem.Email.Address` (see pii_log.js). Seventeen after its review:
  // `emails.ElementAt(0)` (LINQ's `ElementAt` returns the element, it is not
  // a date ending in `At`) and a log call inside a LINQ lambda whose
  // `.Count()` is read (see pii_log.js).
  'PiiLog.cs': { [PII_CS]: 17 },
  // Two GA4 loaders (the stock snippet, and `type="text/javascript"`, which
  // still executes); three Meta pixels — AFTER a consent function that has
  // already closed, inside a function merely NAMED after consent, inside a
  // NEGATED consent check; Hotjar; a youtube.com embed.
  'trackers.html': { [GA4]: 2, [META]: 3, [HOTJAR]: 1, [YOUTUBE]: 1 },
  // Consent Mode with GRANTED defaults is not a guard.
  'consent_granted.html': { [GA4]: 1 },
  // Consent Mode denying only the AD signals is not a guard for Analytics.
  'consent_ads_only.html': { [GA4]: 1 },
  // A Consent Mode default and a Meta revoke that are commented out: with
  // `//` and `<!-- -->` here, and inside `/* */` in the next file (fix
  // round 2 — the file-level guards used to read a block comment as code).
  'commented_guards.html': { [GA4]: 1, [META]: 1 },
  'commented_block.html': { [GA4]: 1, [META]: 1 },
  // WordPress: `wp_enqueue_script` and the inline tag, a pixel, an embed, and
  // two embeds inside alternative-syntax conditions that are NOT consent
  // checks (`is_front_page()`, and a negated `! wp_has_consent(...)`), and
  // one in the ELSE arm of a real consent condition (fix round 2: the guard
  // used to run on to `endif` and swallow the `else :` arm).
  'header.php': { [GA4]: 2, [META]: 1, [YOUTUBE]: 4 },
  // Next.js: `<Script>`, `@next/third-parties`' `<GoogleAnalytics>`, a
  // NON-consent condition (`NODE_ENV === 'production' &&`), a NEGATED
  // consent condition around a fragment, the ELSE branch of a consent
  // ternary, an embed.
  'Analytics.jsx': { [GA4]: 5, [YOUTUBE]: 1 },
  'layout.tsx': { [HOTJAR]: 1 },
  // An unconditional embed and one under a `v-if` that is not about consent.
  'Video.vue': { [YOUTUBE]: 2 },
  // Unconditional, under a non-consent `{% if %}`, under `{% if not consent %}`;
  // fix round 2: under `{% if consent.analytics != true %}` (the `!=` twin of
  // `not`), in the `{% else %}` arm of a consent condition, and the review's
  // opt-out template — `{% if cookie_consent == 'rejected' %}{% else %}` with the
  // Meta pixel in the else arm.
  'base.twig': { [GA4]: 5, [META]: 1 },
  'pixel.htm': { [META]: 1 },
  // Blade: a non-consent `@if` and a negated consent `@if`; fix round 2: the
  // `@elseif` and `@else` arms of a consent `@if`.
  'app.blade.php': { [GA4]: 4 },
  // One per extension fix round 1 added to `paths.include`.
  'layout.js': { [GA4]: 1 },
  '_Layout.cshtml': { [GA4]: 1 },
  'Video.razor': { [YOUTUBE]: 1 },
  'layout.ejs': { [META]: 1 },
  // Unconditional, and (fix round 2) in the `{{else}}` arm of a consent `{{#if}}`.
  'analytics.hbs': { [HOTJAR]: 2 },
  // A page NAMED "stories" is served to visitors: the `*.stories.*` exclusion
  // (Storybook) needs the dot on each side and must not swallow it.
  'stories.html': { [YOUTUBE]: 1 },
};

/**
 * The test-code paths every tracker rule excludes (`paths.exclude`), added
 * after the pack was measured on application code: every tracker finding in
 * a test, spec, story or test-support directory was markup that is input to a
 * test, never served to a visitor. Each has a fixture in `misses/` that fires
 * once the exclusion is removed — see the test that proves it.
 */
const TRACKER_EXCLUDES = ['*.test.*', '*.spec.*', '*.stories.*', '__tests__', '__mocks__', '__fixtures__', '__factories__'];

/**
 * Whether a `/`-separated fixture path is excluded by one `paths.exclude`
 * glob. Only the two shapes the pack uses are understood — `*.x.*` on the
 * file name, and a bare name matching a DIRECTORY segment — and anything else
 * throws, so a new glob cannot be silently mis-modelled here.
 */
function excludedBy(path: string, glob: string): boolean {
  const segments = path.split('/');
  const onName = /^\*\.([A-Za-z]+)\.\*$/.exec(glob)?.[1];
  if (onName !== undefined) return (segments[segments.length - 1] ?? '').includes(`.${onName}.`);
  if (/^[A-Za-z_]+$/.test(glob)) return segments.slice(0, -1).includes(glob);
  throw new Error(`a paths.exclude glob this test does not model: ${glob}`);
}

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
  paths?: { include?: string[]; exclude?: string[] };
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
    // "never read". The files under the test-code directories the tracker
    // rules exclude are JavaScript, so the JS log rule still reads them and
    // the count stays exact.
    expect(scanned).toBe(allFilesIn(missesDir).length);
    expect(rows.map((r) => `${basename(r.path)}:${r.start.line}: ${ruleOf(r)}`)).toEqual([]);
  });

  /**
   * `paths.exclude` is not a clause, so the ablation harness never removes it
   * and could not say whether any of the seven globs is load-bearing. This
   * does it by hand, for all of them at once: with the exclusions stripped
   * from the pack, a tracker fires in EXACTLY the misses/ files the globs
   * exclude, and every glob excludes at least one of them. A glob with no
   * fixture, or a fixture that no glob covers, fails here.
   */
  it.skipIf(!AVAILABLE)('every test-code exclusion of the tracker rules has a misses fixture that fires without it', () => {
    const doc = parse(readFileSync(RULES, 'utf8')) as { rules: RuleDoc[] };
    for (const rule of doc.rules) {
      if (!(rule.languages ?? []).includes('generic')) continue;
      expect([rule.id, rule.paths?.exclude]).toEqual([rule.id, TRACKER_EXCLUDES]);
      delete rule.paths?.exclude;
    }
    const unexcluded = resolve(makeTempDir('guardian-rgpd-noexclude-'), 'rgpd.yml');
    writeFileSync(unexcluded, stringify(doc));

    const result = run(unexcluded, resolve(FIXTURES, 'misses'));
    expect(result.errors).toBe(0);
    const fired = [...new Set(result.rows.map((r) => fixturePath(result, r)))].sort();
    const excluded = allFilesIn(resolve(FIXTURES, 'misses')).filter((f) =>
      TRACKER_EXCLUDES.some((g) => excludedBy(f, g)),
    );
    expect(fired).toEqual(excluded);
    for (const glob of TRACKER_EXCLUDES) {
      expect([glob, excluded.filter((f) => excludedBy(f, glob)).length > 0]).toEqual([glob, true]);
    }
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
 * written out FOURTEEN times — three metavariables (`$FIELD`, `$NAME`,
 * `$KEY`) in four languages, plus a `.get('key')` branch in JS and Python —
 * because a YAML anchor would not survive the ablation harness's round-trip.
 * Fourteen copies drift. So every copy is reduced to its shared CORE and the
 * cores must be identical; then the core is exercised as a JavaScript RegExp
 * (it uses nothing PCRE-only — no inline modifiers — so Node 22 evaluates it
 * the way Semgrep does).
 *
 * What differs by metavariable is the leading constant guard, and fix round 1
 * is why: the old single guard `(?![A-Z][A-Z0-9_]*$)` dropped `cliente.NIF`
 * and `cliente.IBAN` in all four languages. An all-caps IDENTIFIER is a
 * constant or a setting (`EMAIL`, `ADMIN_EMAIL`); an all-caps MEMBER is a
 * column or a property holding the value, unless it has an underscore
 * (`settings.DEFAULT_FROM_EMAIL`). A quoted key has no guard: `row['EMAIL']`
 * is data.
 */
describe('the personal-data name regex', () => {
  const GUARD: Readonly<Record<string, string>> = {
    $NAME: '(?![A-Z][A-Z0-9_]*$)',
    $FIELD: '(?![A-Z][A-Z0-9]*_[A-Z0-9_]*$)',
    $KEY: '',
  };

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
        if (typeof metavariable === 'string' && typeof regex === 'string' && metavariable in GUARD) {
          found.push({ rule, metavariable, regex });
        }
      }
      for (const value of Object.values(node)) walk(rule, value);
    };
    for (const r of packRules()) if (r.id.startsWith('rgpd-pii-in-log-')) walk(r.id, r);
    return found;
  }

  /**
   * The core: the wrapper (`^…$`, `^\$…$` for a PHP variable, `^['"]…['"]$`
   * for a string key) and then the metavariable's own guard stripped off —
   * throwing if either is not the one expected, so a copy with the wrong
   * guard cannot pass as merely "a different body".
   */
  function coreOf(metavariable: string, regex: string): string {
    const guard = GUARD[metavariable] ?? '';
    for (const [open, close] of [['^[\'"]', '[\'"]$'], ['^\\$', '$'], ['^', '$']] as const) {
      if (!regex.startsWith(open) || !regex.endsWith(close)) continue;
      const inner = regex.slice(open.length, regex.length - close.length);
      if (!inner.startsWith(guard)) throw new Error(`${metavariable} without its guard ${guard}: ${regex}`);
      return inner.slice(guard.length);
    }
    throw new Error(`not a recognised name-regex wrapper: ${regex}`);
  }

  it('is written out for every metavariable of every log rule, with one shared core and the right guard', () => {
    const regexes = nameRegexes();
    // 4 rules x ($FIELD, $NAME, $KEY), plus a `.get('key')` branch in JS and Python.
    expect(regexes.length).toBe(14);
    expect(new Set(regexes.map((r) => coreOf(r.metavariable, r.regex))).size).toBe(1);
  });

  const core = (): string => {
    const first = nameRegexes()[0];
    if (first === undefined) throw new Error('no name regex in the pack');
    return coreOf(first.metavariable, first.regex);
  };
  const asIdentifier = (name: string): boolean => new RegExp(`^${GUARD['$NAME'] ?? ''}${core()}$`).test(name);
  const asMember = (name: string): boolean => new RegExp(`^${GUARD['$FIELD'] ?? ''}${core()}$`).test(name);

  it.each([
    'email', 'userEmail', 'user_email', 'UserEmail', '_email', 'emails', 'emailAddress', 'email_address',
    'nif', 'nifCliente', 'nif_cliente', 'clienteNif', 'customerNIF', 'niss', 'iban', 'customerIban',
    'telefone', 'telemovel', 'phone', 'phoneNumber', 'phone_number', 'PhoneNumber', 'billingPhone',
    'get_billing_email', 'getEmail', 'cartao_cidadao', 'cartaoCidadao', 'cartao_de_cidadao', 'cc_number',
    'ccNumber', 'contribuinte', 'numeroContribuinte', 'numero_seguranca_social', 'NormalizedEmail',
    'formattedPhone', 'sender_email', 'mobilePhone', 'validatedEmail',
  ])('names personal data, as an identifier and as a member: %s', (name) => {
    expect([asIdentifier(name), asMember(name)]).toEqual([true, true]);
  });

  it.each(['NIF', 'IBAN', 'EMAIL', 'NISS', 'TELEFONE'])(
    'an all-caps MEMBER is the value (cliente.%s); the same bare identifier is a constant',
    (name) => {
      expect([asIdentifier(name), asMember(name)]).toEqual([false, true]);
    },
  );

  it.each(['ADMIN_EMAIL', 'DEFAULT_FROM_EMAIL', 'USER_EMAIL'])(
    'an all-caps name with an underscore is a setting, bare or as a member: %s',
    (name) => {
      expect([asIdentifier(name), asMember(name)]).toEqual([false, false]);
    },
  );

  it.each([
    // A masked, hashed or derived value, or a flag about the value.
    'maskedEmail', 'masked_email', 'emailHash', 'hashedEmail', 'ibanMasked', 'encryptedIban', 'redactedEmail',
    'emailSent', 'email_verified', 'EmailConfirmed', 'PhoneNumberConfirmed', 'isValidEmail', 'hasEmail',
    // A function or a service named after the value, not the value.
    'emailService', 'sendEmail', 'validateEmail', 'normalizeEmail', 'formatPhone', 'setEmail', 'findByEmail',
    'emailTemplate', 'defaultEmail',
    // Words that merely contain one of the stems.
    'iPhone', 'phonebook', 'emailer', 'nifty', 'ibanez', 'phoneType', 'username', 'mail', 'cc',
  ])('does not name personal data, as an identifier or as a member: %s', (name) => {
    expect([asIdentifier(name), asMember(name)]).toEqual([false, false]);
  });
});

/**
 * The attribute-read guard, added after measuring the pack on application
 * code: a value that only appears as the OBJECT of an attribute read is not
 * what reaches the log when the attribute's NAME says it is an id, a date or
 * a size (`email.id`, `email.scheduled_timestamp`, `lookup(email).id`,
 * `user.email.length`). The guard is keyed on that name list rather than on
 * "any attribute that is not called", because the broad form dropped values
 * held under neutral names — `user.phone.as_e164`, `email.address` — which
 * the member branch cannot see. Four copies, one per log rule; they must not
 * drift, and the list is exercised here the way the name regex is above.
 */
describe('the attribute-read guard name list', () => {
  function attrRegexes(): string[] {
    const found: string[] = [];
    const walk = (node: unknown): void => {
      if (Array.isArray(node)) {
        for (const child of node) walk(child);
        return;
      }
      if (node === null || typeof node !== 'object') return;
      const mr = (node as Record<string, unknown>)['metavariable-regex'];
      if (mr !== null && typeof mr === 'object') {
        const { metavariable, regex } = mr as { metavariable?: unknown; regex?: unknown };
        if (metavariable === '$ATTR' && typeof regex === 'string') found.push(regex);
      }
      for (const value of Object.values(node)) walk(value);
    };
    for (const r of packRules()) if (r.id.startsWith('rgpd-pii-in-log-')) walk(r);
    return found;
  }

  it('is written once per log rule, identically', () => {
    const regexes = attrRegexes();
    expect(regexes.length).toBe(4);
    expect(new Set(regexes).size).toBe(1);
  });

  const isMetadata = (name: string): boolean => {
    const first = attrRegexes()[0];
    if (first === undefined) throw new Error('no $ATTR regex in the pack');
    return new RegExp(first).test(name);
  };

  it.each([
    'id', 'Id', 'ID', 'pk', 'uuid', 'guid', '_id', 'message_id', 'recipient_ids', 'userId', 'MessageId', 'ExternalID',
    'scheduled_at', 'sentAt', 'enviar_em', 'EnviarEm', 'send_date', 'SendDate', 'send_time', 'SentTime',
    'timestamp', 'scheduled_timestamp', 'length', 'Length', 'size', 'count', 'Count',
  ])('names metadata, not the value: %s', (name) => {
    expect(isMetadata(name)).toBe(true);
  });

  it.each([
    'address', 'Address', 'number', 'numero', 'as_e164', 'national_number', 'value', 'Value', 'to', 'subject',
    'domain', 'lower', 'toLowerCase', 'ToLowerInvariant', 'format', 'Format', 'update', 'data', 'identity', 'item',
    // LINQ's `ElementAt` returns the element itself; it only LOOKS like a
    // date ending in `At` (review of the application-code round).
    'ElementAt',
  ])('does not name metadata, so the value is still judged: %s', (name) => {
    expect(isMetadata(name)).toBe(false);
  });

  /**
   * The guard's `$V` must not hold a function body. `$V` is whatever the
   * attribute is read on, of any size: in
   * `users.filter((u) => { logger.warn(u.email) }).length` it is the whole
   * `users.filter(...)` call, log call included, and the guard excluded the
   * finding inside it (review of the application-code round: four true
   * positives lost, one per language). A `$V` whose text holds a lambda,
   * an arrow, a `function` or a `delegate` is not a value whose metadata is
   * read. PHP gets its own copy: `=>` is PHP's array-pair separator, so there
   * the body marker is `fn`/`function`, never `=>`.
   */
  function valueRegexes(): Map<string, string> {
    const found = new Map<string, string>();
    const walk = (rule: string, node: unknown): void => {
      if (Array.isArray(node)) {
        for (const child of node) walk(rule, child);
        return;
      }
      if (node === null || typeof node !== 'object') return;
      const mr = (node as Record<string, unknown>)['metavariable-regex'];
      if (mr !== null && typeof mr === 'object') {
        const { metavariable, regex } = mr as { metavariable?: unknown; regex?: unknown };
        if (metavariable === '$V' && typeof regex === 'string') {
          if (found.has(rule)) throw new Error(`two $V regexes in ${rule}`);
          found.set(rule, regex);
        }
      }
      for (const value of Object.values(node)) walk(rule, value);
    };
    for (const r of packRules()) if (r.id.startsWith('rgpd-pii-in-log-')) walk(r.id, r);
    return found;
  }

  const valueRegex = (rule: string): RegExp => {
    const re = valueRegexes().get(rule);
    if (re === undefined) throw new Error(`no $V regex in ${rule}`);
    return new RegExp(re);
  };

  it('limits $V in every log rule: one body-marker regex for JS, Python and C#, its own for PHP', () => {
    const regexes = valueRegexes();
    expect([...regexes.keys()].sort()).toEqual([PII_CS, PII_JS, PII_PHP, PII_PY].sort());
    expect(new Set([regexes.get(PII_JS), regexes.get(PII_PY), regexes.get(PII_CS)]).size).toBe(1);
    expect(regexes.get(PII_PHP)).not.toBe(regexes.get(PII_JS));
  });

  it.each([
    'email', 'user.email', 'get_bot(item["email"], 3)', 'lookup(email)', 'findBot(req.body[\'email\'])',
    'obter_function_id(email)', 'lambda_client.get(email)', 'functionality(email)',
  ])('JS/Python/C#: keeps the guard for a plain value: %s', (text) => {
    expect(valueRegex(PII_JS).test(text)).toBe(true);
  });

  it.each([
    'users.filter((u) => { console.warn(u.email); return true; })',
    'queue.add(function () { logger.info(user.email); })',
    'scheduler.add_job(lambda: logger.info("%s", user.email))',
    'users.Where(u => { _logger.LogInformation("{E}", u.Email); return true; })',
    'users.Where(delegate (User u) { _logger.LogInformation("{E}", u.Email); return true; })',
    'users.filter((u) => {\n  logger.warn(u.email);\n})',
  ])('JS/Python/C#: drops the guard when $V holds a function body: %s', (text) => {
    expect(valueRegex(PII_JS).test(text)).toBe(false);
  });

  it.each(['$email', 'obter_bot($data[\'email\'])', 'f([\'e\' => $email])', '$this->bots[$email]'])(
    'PHP: keeps the guard for a plain value, array pairs included: %s',
    (text) => {
      expect(valueRegex(PII_PHP).test(text)).toBe(true);
    },
  );

  it.each([
    '$fila->adicionar(fn () => $this->logger->info(\'x\', [\'e\' => $user->email]))',
    '$fila->adicionar(function () use ($user) { error_log($user->email); })',
  ])('PHP: drops the guard when $V holds a function body: %s', (text) => {
    expect(valueRegex(PII_PHP).test(text)).toBe(false);
  });
});

/**
 * The Python print sink skips a Django management command: `class Command`
 * whose base is one of Django's (`BaseCommand`, `AppCommand`, `LabelCommand`,
 * `TemplateCommand`, the pre-1.10 `NoArgsCommand`, a project's
 * `...BaseCommand`), or `module.Command` — a command extending a built-in
 * one. The first version accepted any base ending in `Command`
 * (`ProcessCommand`, `ICommand`), which are not Django's (review of the
 * application-code round).
 */
describe('the Django management command base regex', () => {
  const baseRegex = (): RegExp => {
    const found: string[] = [];
    const walk = (node: unknown): void => {
      if (Array.isArray(node)) {
        for (const child of node) walk(child);
        return;
      }
      if (node === null || typeof node !== 'object') return;
      const mr = (node as Record<string, unknown>)['metavariable-regex'];
      if (mr !== null && typeof mr === 'object') {
        const { metavariable, regex } = mr as { metavariable?: unknown; regex?: unknown };
        if (metavariable === '$BASE' && typeof regex === 'string') found.push(regex);
      }
      for (const value of Object.values(node)) walk(value);
    };
    for (const r of packRules()) if (r.id === PII_PY) walk(r);
    const [only, ...rest] = found;
    if (only === undefined || rest.length > 0) throw new Error(`expected one $BASE regex, found ${String(found.length)}`);
    return new RegExp(only);
  };

  it.each([
    'BaseCommand', 'AppCommand', 'LabelCommand', 'TemplateCommand', 'NoArgsCommand', 'ZulipBaseCommand',
    'base.BaseCommand', 'templates.TemplateCommand', 'django.core.management.base.BaseCommand',
    'sendtestemail.Command', 'email_de_teste.Command',
  ])('is a Django command base: %s', (base) => {
    expect(baseRegex().test(base)).toBe(true);
  });

  it.each(['ProcessCommand', 'ProcessoCommand', 'ICommand', 'Command', 'BaseModel', 'CommandBase', 'RunserverCommand'])(
    'is not: %s',
    (base) => {
      expect(baseRegex().test(base)).toBe(false);
    },
  );
});

/**
 * What the messages PRESCRIBE — fix round 1, item 6. Google Consent Mode v2
 * with `analytics_storage` denied ("advanced mode": the tag loads and pings
 * before consent) and Meta's `fbq('consent', 'revoke')` (fbevents.js still
 * loads) stay recognised as guards — a documented judgement — but under EDPB
 * Guidelines 2/2023 the pre-consent requests remain within art. 5(3) of the
 * ePrivacy Directive, so no message may offer them as the fix. The fix is
 * basic mode: nothing loads before consent.
 */
describe('the tracker messages prescribe loading nothing before consent', () => {
  const message = (id: string): string => {
    const doc = parse(readFileSync(RULES, 'utf8')) as { rules?: { id: string; message?: string }[] };
    const found = (doc.rules ?? []).find((r) => r.id === id)?.message;
    if (found === undefined) throw new Error(`no message for ${id}`);
    return found;
  };

  it.each([GA4, META])('%s: prescribes basic mode, and calls the accepted guard a legal judgement, not a fix', (id) => {
    const text = message(id);
    expect(text).toMatch(/modo b[aá]sico/i);
    expect(text).toMatch(/Diretrizes 2\/2023/);
    expect(text).toMatch(/decis[aã]o jur[ií]dica/i);
    expect(text).toMatch(/n[aã]o [eé] tratad[oa] como (?:achado|finding)/i);
  });

  it('GA: does not offer Consent Mode as an equivalent fix', () => {
    expect(message(GA4)).not.toMatch(/ou declare o Google Consent Mode/i);
  });

  it('YouTube: does not promise youtube-nocookie stores nothing until play', () => {
    const text = message(YOUTUBE);
    expect(text).not.toMatch(/sem cookies/i);
    expect(text).toMatch(/localStorage|armazenamento local/i);
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

  it('every generic-mode rule skips the same test-code paths, and no hits/ fixture is one of them', () => {
    for (const rule of packRules()) {
      if (!(rule.languages ?? []).includes('generic')) continue;
      expect([rule.id, rule.paths?.exclude]).toEqual([rule.id, TRACKER_EXCLUDES]);
    }
    const swallowed = filesIn(resolve(FIXTURES, 'hits')).filter((f) => TRACKER_EXCLUDES.some((g) => excludedBy(f, g)));
    expect(swallowed).toEqual([]);
  });
});
