/**
 * Blinding — pure text transforms that take the tell-tale names out of a
 * public, deliberately vulnerable corpus WITHOUT moving a single line, so a
 * key's `file:line` in the original is the same `file:line` in the copy.
 *
 * Built on the spike's `tools/blind.cjs` (2026-10-02): the same file lists,
 * the same regular expressions in the same order, and the same app-d layout
 * (recorded in the spike's `answer-keys/blind-map.tsv` and fixed here,
 * because the C-items of the verification set name those paths). Review
 * round 1 found what `blind.cjs` left behind, so on top of it:
 *   - every comment that carries a tell (`tells.ts`) is emptied first, on the
 *     ORIGINAL text — "intentionally vulnerable to XXE" must be recognised
 *     before `\bvuln` → `item` turns it into "itemerable";
 *   - app-j loses the CTF vocabulary, "Hacking Instructor" and its author's
 *     address; app-b (BenchmarkPython, which `blind.cjs` never covered) is
 *     blinded in file names and contents alike.
 * Review round 2 found tells in code strings and camelCase identifiers, so
 * every code file now ends with `tells.ts#scrubCode` (and every data file
 * with `scrubProse`): one deterministic token map renames each tell-bearing
 * identifier, string word and — through {@link blindPathOf} — file name, the
 * same way everywhere. `corpora.ts` then greps every finished copy for tells
 * (raw words, split identifiers, string literals, comments, paths) and
 * refuses it if any survives. Only the I/O lives there; everything here is unit-tested for
 * line preservation (`test/unit/evals/llmScanBlind.test.ts`).
 */

import type { CorpusId } from './corpora.js';
import { neutraliseTellComments, rewritePath, scrubCode, scrubProse, type ScrubLog } from './tells.js';

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

export function blindVampiText(rel: string, orig: string, log?: ScrubLog): string {
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
  t = rel.endsWith('.py') ? scrubCode(t, 'python', log) : scrubProse(t, log);
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

export function blindJuiceText(rel: string, orig: string, alias: ReadonlyMap<string, string>, log?: ScrubLog): string {
  // Comments that state a flaw, name the project or its author (every licence
  // header): emptied on the original text, before any rename can mangle them.
  let t = neutraliseTellComments(orig, 'js').text;
  t = t.replace(/[ \t]*\/\/ vuln-code-snippet.*$/gm, '');
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
    .replace(/hacking[\s_-]?instructor/gi, 'tutorial')
    // review round 1: the CTF vocabulary (config keys, the flag key file, log lines) and the author's address
    .replace(/CTF/g, 'SCORE')
    .replace(/Ctf/g, 'Score')
    .replace(/ctf/g, 'score')
    .replace(/bjoern\.kimminich/gi, 'shop.owner')
    .replace(/kimminich/gi, 'owner')
    .replace(/\bpwning\b/gi, 'docs');
  // review round 2: the tells in strings and identifiers (antiCheat, 'Malicious activity…', alert(`xss`))
  t = scrubCode(t, 'js', log);
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

export function blindDvwaText(rel: string, orig: string, log?: ScrubLog): string {
  let t = neutraliseTellComments(orig, 'php').text;
  t = t.replace(/dvwa/gi, (m) => (m === m.toUpperCase() ? 'APP' : m[0] === 'D' ? 'App' : 'app'));
  t = t.replace(/(impossible|low|medium|high)\.php/gi, 'variant.php');
  // review round 2: `hackable/uploads/` → `storage/uploads/`, the `SQLI_DB` config key … (paths map the same way: blindPathOf)
  t = scrubCode(t, 'php', log);
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
 * A test case's number in app-b: an affine bijection on 0–99999 (7919 is
 * prime to 100000), so `BenchmarkTest00432` does not survive as `View00432`.
 */
export function benchmarkViewNumber(n: number): string {
  return String((n * 7919 + 1237) % 100000).padStart(5, '0');
}

/** The test-case categories, as route and template paths spell them (`/xss-00/`). */
const BENCHMARK_CATEGORIES = [
  'cmdi', 'codeinj', 'deserialization', 'hash', 'ldapi', 'pathtraver', 'redirect',
  'securecookie', 'sqli', 'trustbound', 'weakrand', 'xpathi', 'xss', 'xxe',
];
const CATEGORY_SEGMENT = new RegExp(`/(?:${BENCHMARK_CATEGORIES.join('|')})-(\\d\\d)/`, 'g');

/**
 * The renames app-b applies to file NAMES and file CONTENTS alike — so every
 * file a test case opens by name is still there, under its new name: the
 * test-case names, the project's own name, the two `testfiles/` names that
 * say which branch runs ("This should never happen"), the XXE resource and
 * the "insecure" command script.
 */
export function benchmarkRenames(s: string): string {
  return s
    .replace(/BenchmarkTest(\d{5})/g, (_m, n: string) => `View${benchmarkViewNumber(Number(n))}`)
    .replace(/BenchmarkTest/g, 'View')
    .replace(/Benchmark/g, 'View')
    .replace(/BENCHMARK/g, 'SITE')
    .replace(/benchmark/gi, 'site')
    .replace(/This should never happen/g, 'fixed value b')
    .replace(/This_should_always_happen/g, 'fixed_value_a')
    .replace(/xxe\.txt/g, 'entity.txt')
    .replace(/insecureCmd/g, 'runCmd');
}

/**
 * The benchmark's verdict-hinting constants and what they become. Some of
 * them are also the names of `testfiles/` (a path-traversal case opens
 * `testfiles/moresafe`), so file names follow the same map.
 */
export const BENCHMARK_HINT_NAMES: Readonly<Record<string, string>> = {
  safe: 'value_a',
  moresafe: 'value_b',
  alsosafe: 'value_c',
  'safe!': 'value_d!',
};

/** A BenchmarkPython path → its path in app-b. */
export function benchmarkBlindPath(rel: string): string {
  const renamed = benchmarkRenames(rel);
  const slash = renamed.lastIndexOf('/');
  const hint = BENCHMARK_HINT_NAMES[renamed.slice(slash + 1)];
  return hint === undefined ? renamed : `${renamed.slice(0, slash + 1)}${hint}`;
}

/**
 * One app-b file. Python files lose the licence docstring that opens each of
 * them (OWASP Benchmark, GPL notice — the quotes stay) and every comment
 * carrying a tell. Every text file then gets {@link benchmarkRenames}, the
 * route and template category segments (`/xss-00/` → `/pages-00/`), and —
 * the semantic hints the benchmark plants in its constants — `'safe'`,
 * `'moresafe'`, `'alsosafe'`, `'safe!'`, `'_SafeStuff'`, `'SafeToby{num}'`
 * become neutral names. Every one is a constant renamed consistently in every
 * file, so the code does what it did; only the words that hint at the
 * verdict go.
 */
export function blindBenchmarkText(rel: string, orig: string, log?: ScrubLog): string {
  let t = orig;
  if (rel.endsWith('.py')) {
    const lines = t.split('\n');
    const bare = (l: string | undefined): string => (l ?? '').replace(/\r$/, '').trim();
    if (bare(lines[0]) === "'''") {
      const close = lines.findIndex((l, i) => i > 0 && bare(l) === "'''");
      for (let i = 1; i < close; i += 1) lines[i] = (lines[i] ?? '').endsWith('\r') ? '\r' : '';
      t = lines.join('\n');
    }
    t = neutraliseTellComments(t, 'python').text;
    t = t
      .replace(/(['"])(safe!?|moresafe|alsosafe)\1/g, (_m, q: string, name: string) => `${q}${BENCHMARK_HINT_NAMES[name] ?? name}${q}`)
      .replace(/_SafeStuff/g, '_Stuff')
      .replace(/\bSafe([A-Z][a-z]+)\{/g, '$1{')
      .replace(/\bpwned\b/g, 'redirected');
  }
  t = benchmarkRenames(t)
    .replace(CATEGORY_SEGMENT, '/pages-$1/')
    .replace(/XXE Attack SUCCESSFUL-U_R_L33T!/g, 'entity resolved');
  t = rel.endsWith('.py') ? scrubCode(t, 'python', log) : scrubProse(t, log);
  assertSameLineCount(orig, t, `app-b/${rel}`);
  return t;
}

// ---------- every corpus ----------

/**
 * Where a corpus file is in its blind copy: the corpus's own renames, then
 * the tell-token map every file name goes through (`tells.ts#rewritePath`,
 * the same map as the code, so an import of `./antiCheat` and the file it
 * names agree, and `hackable/uploads/` becomes `storage/uploads/` in a path
 * as in a string). The C-items of app-j and app-d already name blind paths;
 * this is idempotent on them. `corpora.ts` writes every copy through here, so
 * grading maps a path exactly as the copy was written.
 */
export function blindPathOf(corpus: CorpusId, rel: string): string {
  if (corpus === 'benchmark-python') return rewritePath(benchmarkBlindPath(rel));
  if (corpus === 'juice-shop') return rewritePath(juiceOutPath(rel));
  return rewritePath(rel);
}
