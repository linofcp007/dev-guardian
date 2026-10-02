/**
 * Blinding — pure text transforms that take the tell-tale names out of a
 * public, deliberately vulnerable corpus WITHOUT moving a single line, so a
 * key's `file:line` in the original is the same `file:line` in the copy.
 *
 * A faithful port of the spike's `tools/blind.cjs` (2026-10-02): the same
 * file lists, the same regular expressions in the same order, and the same
 * app-d layout (recorded in the spike's `answer-keys/blind-map.tsv` and
 * fixed here, because the C-items of the verification set name those
 * paths). Only the I/O lives elsewhere (`corpora.ts`); everything here is
 * unit-tested for line preservation (`test/unit/evals/llmScanBlind.test.ts`).
 */

/** Throws when a transform changed the number of lines — every key line would be off. */
export function assertSameLineCount(before: string, after: string, where: string): void {
  const n = (s: string): number => s.split('\n').length;
  if (n(before) !== n(after)) {
    throw new Error(`blinding changed the line count of ${where} (${n(before)} -> ${n(after)}): every key line would be wrong`);
  }
}

// ---------- app-v: VAmPI (Python/Flask), commit f16052d ----------

/** The files the spike copied into app-v — nothing else of the repository (no README, Dockerfile, LICENSE). */
export const VAMPI_FILES: readonly string[] = [
  'app.py',
  'config.py',
  'database/__init__.py',
  'api_views/__init__.py',
  'api_views/books.py',
  'api_views/json_schemas.py',
  'api_views/main.py',
  'api_views/users.py',
  'models/__init__.py',
  'models/books_model.py',
  'models/user_model.py',
  'openapi_specs/openapi3.yml',
  'requirements.txt',
];

export function blindVampiText(rel: string, orig: string): string {
  let t = orig;
  if (rel.endsWith('.py')) {
    // drop comments (no '#' occurs inside a string literal in these files — checked by hand in the spike)
    t = t
      .split('\n')
      .map((l) => l.replace(/[ \t]*#[^\r\n]*/, ''))
      .join('\n');
    // docstring lines that describe the deliberate flaws become blank (the quotes stay)
    t = t
      .split('\n')
      .map((l) => (/vulnerable|bad practice|debug endpoint/i.test(l) && !/[=(]/.test(l) ? '' : l))
      .join('\n');
  }
  t = t.replace(/vuln_app/g, 'api_app').replace(/\bvuln\b/g, 'compat_mode').replace(/'vulnerable'/g, "'compat_mode'");
  t = t.replace(/VAmPI is a vulnerable on purpose API\.[^'\n]*/g, 'Shelf is a small book catalogue API.');
  t = t
    .replace(/'created in order to evaluate the efficiency of third party tools in identifying vulnerabilities '/g, "'with users and their books, '")
    .replace(/'in APIs but it can also be used in learning\/teaching purposes\.", /g, "'served over JSON.\", ");
  t = t.replace(/VAmPI the Vulnerable API/g, 'Shelf API').replace(/VAmPI/g, 'Shelf');
  t = t.replace(/"vulnerable":/g, '"compat_mode":').replace(/^(\s*)vulnerable:/gm, '$1compat_mode:');
  if (rel.endsWith('openapi3.yml')) {
    t = t
      .split('\n')
      .map((l) => (/vulnerab|evaluate the efficiency|learning\/teaching/i.test(l) ? l.replace(/\S[^\r\n]*/, 'Book catalogue API.') : l))
      .join('\n');
  }
  assertSameLineCount(orig, t, `app-v/${rel}`);
  return t;
}

// ---------- app-j: OWASP Juice Shop backend (TS/Express), commit 1618a61 ----------

/** Challenge machinery the spike left out of app-j entirely. */
export const JUICE_EXCLUDE =
  /^(routes\/(verify|continueCode|restoreProgress|vulnCodeSnippet|vulnCodeFixes)\.ts|lib\/(antiCheat|codingChallenges|accuracy)\.ts|lib\/scripts\/|models\/(challenge|challengeDependency|hint)\.ts)/;

/** Whether a repository-relative POSIX path is part of app-j (given that it is under server.ts/app.ts/routes/lib/models). */
export function isJuiceFile(rel: string): boolean {
  return /\.ts$/.test(rel) && !JUICE_EXCLUDE.test(rel);
}

/**
 * `<name>Challenge` identifiers → `e001`, `e002`, … in sorted order, computed
 * over the text of every app-j file at once (so the same name gets the same
 * alias in every file).
 */
export function juiceAliases(allText: string): Map<string, string> {
  const names = [...new Set([...allText.matchAll(/\b([a-z][A-Za-z0-9]*Challenge)\b/g)].map((m) => m[1] ?? ''))]
    .filter((n) => n !== '')
    .sort();
  return new Map(names.map((n, i) => [n, `e${String(i + 1).padStart(3, '0')}`]));
}

export function blindJuiceText(rel: string, orig: string, alias: ReadonlyMap<string, string>): string {
  let t = orig.replace(/[ \t]*\/\/ vuln-code-snippet.*$/gm, '');
  t = t.replace(/\b([a-z][A-Za-z0-9]*Challenge)\b/g, (m) => alias.get(m) ?? m);
  t = t
    .replace(/challengeUtils/g, 'telemetry')
    .replace(/\bsolveIf\b/g, 'trackIf')
    .replace(/\bsolve\(/g, 'track(')
    .replace(/\bchallenges\b/g, 'events')
    .replace(/insecurity/g, 'secutil')
    .replace(/OWASP Juice Shop/gi, 'Shop')
    .replace(/juice[- ]?shop/gi, 'shop-app')
    .replace(/CHALLENGE/g, 'EVENT')
    .replace(/Challenge/g, 'Event')
    .replace(/challenge/g, 'event')
    .replace(/\bvuln/gi, 'item')
    .replace(/owasp-juice\.shop/g, 'example.org')
    .replace(/juice_shop/g, 'shop_app')
    .replace(/OWASP/g, 'PROMO')
    .replace(/Owasp/g, 'Promo')
    .replace(/owasp/g, 'promo')
    .replace(/PoisonNullByteExploit/g, 'FileName')
    .replace(/Exploit/g, 'Event')
    .replace(/Vuln/g, 'Item')
    .replace(/exploiter/g, 'sender')
    .replace(/abused_ssti_bug/g, 'flag_a')
    .replace(/abused_ssrf_bug/g, 'flag_b')
    .replace(/isUnintendedRedirect/g, 'isOtherTarget')
    .replace(/xssBonusPayload/g, 'bonusText')
    .replace(/hackingInstructor/gi, 'tutorial');
  assertSameLineCount(orig, t, `app-j/${rel}`);
  return t;
}

/** The two files app-j renames (their names alone give the game away). */
export function juiceOutPath(rel: string): string {
  return rel.replace('lib/insecurity.ts', 'lib/secutil.ts').replace('lib/challengeUtils.ts', 'lib/telemetry.ts');
}

// ---------- app-d: DVWA modules (PHP), commit 43b0f8b ----------

export type DvwaLevel = 'low' | 'medium' | 'high' | 'impossible';

/**
 * The spike's app-d layout, exactly as `blind-map.tsv` recorded it: module
 * alias and, per variant letter, the security level it holds. `blind.cjs`
 * shuffled the levels with `crypto.randomInt`, so a fresh run would produce
 * a different layout — and the verification items C06–C09 and C15–C17 name
 * these paths. Fixed here so the items stay true.
 */
export const DVWA_LAYOUT: Readonly<Record<string, { alias: string; variants: readonly [DvwaLevel, DvwaLevel, DvwaLevel, DvwaLevel] }>> = {
  exec: { alias: 'm1', variants: ['impossible', 'high', 'low', 'medium'] },
  sqli: { alias: 'm2', variants: ['medium', 'high', 'impossible', 'low'] },
  sqli_blind: { alias: 'm3', variants: ['medium', 'low', 'high', 'impossible'] },
  captcha: { alias: 'm4', variants: ['impossible', 'high', 'medium', 'low'] },
  upload: { alias: 'm5', variants: ['medium', 'low', 'high', 'impossible'] },
  fi: { alias: 'm6', variants: ['impossible', 'medium', 'high', 'low'] },
  brute: { alias: 'm7', variants: ['high', 'impossible', 'medium', 'low'] },
};

/** Every app-d file: the DVWA source path and the blind path it is copied to. */
export function dvwaFiles(): Array<{ source: string; out: string; level: DvwaLevel }> {
  const out: Array<{ source: string; out: string; level: DvwaLevel }> = [];
  for (const [mod, { alias, variants }] of Object.entries(DVWA_LAYOUT)) {
    variants.forEach((level, i) => {
      out.push({ source: `vulnerabilities/${mod}/source/${level}.php`, out: `${alias}/variant_${'abcd'[i] ?? '?'}.php`, level });
    });
  }
  return out;
}

export function blindDvwaText(rel: string, orig: string): string {
  let t = orig.replace(/dvwa/gi, (m) => (m === m.toUpperCase() ? 'APP' : m[0] === 'D' ? 'App' : 'app'));
  t = t.replace(/(impossible|low|medium|high)\.php/gi, 'variant.php');
  assertSameLineCount(orig, t, `app-d/${rel}`);
  return t;
}

// ---------- app-b: OWASP BenchmarkPython, commit f129148 ----------

/**
 * What of BenchmarkPython is copied: the application and its test cases.
 * Never `expectedresults-*.csv` (the answer key), `results/` (tools' scored
 * runs), `scripts/`, the scorecard config, README or LICENSE.
 */
export const BENCHMARK_PY_ROOTS: readonly string[] = ['app.py', 'requirements.txt', 'helpers', 'testcode', 'testfiles'];

/**
 * Every `.py` file opens with a `'''` docstring naming the OWASP Benchmark
 * and its licence. Its inner lines become blank (the quotes stay), so the
 * copy no longer announces itself as a benchmark; nothing else changes.
 */
export function blindBenchmarkPyText(rel: string, orig: string): string {
  if (!rel.endsWith('.py')) return orig;
  const lines = orig.split('\n');
  const bare = (l: string | undefined): string => (l ?? '').replace(/\r$/, '').trim();
  if (bare(lines[0]) !== "'''") return orig;
  let close = -1;
  for (let i = 1; i < lines.length; i += 1) {
    if (bare(lines[i]) === "'''") {
      close = i;
      break;
    }
  }
  if (close === -1) return orig;
  for (let i = 1; i < close; i += 1) {
    const l = lines[i] ?? '';
    lines[i] = l.endsWith('\r') ? '\r' : '';
  }
  const t = lines.join('\n');
  assertSameLineCount(orig, t, `app-b/${rel}`);
  return t;
}
