/**
 * `bug_hunt` — bug-focused Semgrep scan using curated rule packs.
 *
 * Same shell-out pattern as `scan_sast` but with `--config=p/r2c-bug-scan`
 * and `--config=p/security-audit` instead of `--config=auto`. The
 * post-processing step re-tags findings so they land in the `bug` category
 * (instead of whatever the semgrep metadata says), so the model can ask for
 * "bug-category findings" via resources and get the right slice.
 *
 * `p/r2c-bug-scan` replaces the original `p/bugs`, which was retired from
 * Semgrep's registry (`https://semgrep.dev/c/p/bugs` now 404s) — see the
 * bug_hunt fix report. Registry packs can go away at any time, and a dead
 * `--config=` does not fail gracefully on its own: Semgrep aborts the WHOLE
 * invocation, including any *other* pack passed alongside it, and reports
 * the failure only inside the JSON's `errors[]` array. This file reads that
 * array (`semgrepConfigFailure.ts`) and re-runs with whatever packs still
 * resolve, so one retirement degrades coverage instead of erasing it — and
 * never lets a run that scanned nothing get reported as a clean bug report.
 *
 * `p/r2c-bug-scan`'s own content is Python-heavy (32 of 44 rules) and thin
 * for JS/TypeScript (3 rules, none of which are the race/null/off-by-one/
 * leak/error-handling classes the tool's category vocabulary names) — see
 * `title`/`description` below, which say this to the model reading them
 * rather than only in this comment.
 *
 * `buildPackList` (below) is where every `--config=` value gets assembled,
 * and it always appends every local `configs/semgrep/bugfix-*.yml` pack —
 * one hand-authored file per language, each covering the same six bug
 * classes for its language (fourteen rules for JS/TS, design of record:
 * docs/superpowers/specs/2026-08-17-bugfix-rules-jsts-design.md; ten for
 * Python, docs/superpowers/specs/2026-08-18-bugfix-rules-python-design.md;
 * ten for Go, docs/superpowers/specs/2026-08-18-bugfix-rules-go-design.md —
 * Go is where the registry pack leaves the biggest hole among the languages
 * it partially covers (5 Go rules, only 2 land in a bug class), and the
 * design doc's §8 records a fourth exclusion clause that shipped dead and
 * was removed; eight for Java,
 * docs/superpowers/specs/2026-08-19-bugfix-rules-java-design.md — Java is
 * the emptiest of the four: p/r2c-bug-scan ships 4 Java rules and NONE of
 * them land in a bug class, all four being equality/comparison style)
 * — resolved to absolute paths via `resolveBugfixRules`
 * (`../platform/configsDir.js`). Unlike `include_language_packs` below, this
 * is ON BY DEFAULT: a local file cannot 404, so it is also what keeps
 * `bug_hunt` reporting something true even when the registry is entirely
 * unreachable and both registry packs fail to resolve. `resolveBugfixRules`
 * returns `[]` when the directory cannot be read, and `buildPackList` omits
 * the packs rather than pass Semgrep a `--config` path that does not exist
 * — which would reproduce, locally, the exact whole-scan-aborts failure the
 * paragraph above describes for a 404.
 *
 * `configuredPacks` also grows by whatever `detectLanguages` finds — one
 * Semgrep per-language pack (`p/javascript` OR `p/typescript` for a JS/TS
 * project, never both — see `languagePacksFor` — plus `p/python`, `p/java`,
 * `p/golang`) for each language family the project's stack uses, sourced
 * from `detect_stack`'s persisted snapshot when one exists, or a cheap
 * filesystem check otherwise — same shape as `scanSast.ts`'s own conditional
 * `p/csharp` pack, BUT ONLY when the caller passes `include_language_packs:
 * true`. Off by default: the user this fix was for approved adding these
 * packs but asked for them "available and silent by default; whoever wants
 * them asks." Deliberately a separate input from `categories`, not a value
 * inside it — `categories` filters OUTPUT (which findings come back),
 * `include_language_packs` decides INPUT (which scanners run); folding pack
 * selection into `categories` would mean requesting a finding category
 * silently changed which scanners ran, coupling two axes that need to stay
 * independent (see `BugHuntInput`'s own doc comment).
 *
 * VERIFIED (not assumed): every one of those five packs is Semgrep's
 * per-language security bundle, ~100% `category: security`, with ZERO rules
 * in any of the six canonical bug subcategories — confirmed by inspecting
 * their rules (401 entries, 327 distinct — `p/javascript` and `p/typescript`
 * carry the identical 74 rule ids, which is why `languagePacksFor` now
 * configures only one of them for a JS/TS project instead of both), by
 * running every configured pack against a fixture built to trigger every
 * canonical subcategory (zero matches), and by sweeping `mapSubcategory`
 * across every distinct rule id bug_hunt can run (516 total; 13 land in a
 * canonical bucket, none from these five packs). They
 * widen security coverage per language; they do not close the bug-class gap
 * `p/r2c-bug-scan` leaves in JS/TS or any other language. Overlap with the
 * always-on `p/security-audit` is real but partial (measured: 22% exact
 * rule-id duplication overall, ~9% for JS/TS specifically, up to 40-43% for
 * Java/Go) — not "largely redundant". See `title`/`description`, which say
 * all of this plainly to the model reading them.
 *
 * `mapSubcategory`'s classification and the `categories` input (which
 * filters findings to specific subcategories) are exercised together: a
 * caller can use `categories` to keep only the canonical bug-class findings
 * and drop the language packs' security volume, or vice versa — independent
 * of whether `include_language_packs` was also set.
 *
 * `missing_tools` entries stay bare (`'semgrep'`), never pack-qualified
 * (`'semgrep:p/r2c-bug-scan'`): the dashboard's `TOOL_CATEGORIES` map
 * (`dashboard/types.ts`) and every other reader of `missing_tools` key off
 * literal, installable tool names, and a colon-qualified name has no entry
 * there — it falls back to rendering itself as its own "category", producing
 * `MISSING semgrep:p/r2c-bug-scan — semgrep:p/r2c-bug-scan findings are NOT
 * in these numbers`. Which pack failed and why is real, useful detail, but
 * it belongs on the `semgrep` `tools_run` entry's `reason` (free text, meant
 * for exactly this) rather than smuggled through a field every consumer
 * assumes is a bare tool name.
 */

import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { z } from 'zod';
import { resolveBugfixRules } from '../platform/configsDir.js';
import { resolveCustomSemgrepConfigs } from '../platform/customRules.js';
import { semgrepParser } from '../runners/scannerParsers/semgrep.js';
import { runProcess, type ProcessRunResult } from '../runners/processRunner.js';
import {
  AllowDirty,
  AutoFix,
  Force,
  ProjectPath,
  SeverityMin,
} from '../schemas.js';
import { computeFingerprint } from '../fingerprint/findingFingerprint.js';
import type {
  Category,
  Finding,
  ToolRun,
} from '../types.js';
import {
  type ParserOutput,
  type ScannerParser,
} from '../runners/scannerParsers/index.js';
import { registerToolModule } from './index.js';
import {
  ensureReportDir,
  readJsonSafe,
  scannerAvailable,
} from './scanHelpers.js';
import {
  describeConfigFailures,
  describeRawErrors,
  findConfigDownloadFailures,
  survivingPacks,
  wasAnythingScanned,
  type ConfigDownloadFailure,
} from './semgrepConfigFailure.js';
import {
  makeScanTool,
  type InvokeContext,
  type ScannerInvocation,
  type ScanToolBaseInput,
} from './scanToolFactory.js';

/**
 * `bug_hunt`'s input, beyond the fields every scan tool shares.
 * `categories`, unlike the base fields, is `bug_hunt`-specific (its six-name
 * subcategory vocabulary), which is why it lives here and not on
 * `ScanToolBaseInput` — every other scan tool has no use for it.
 *
 * `include_language_packs` is deliberately a SEPARATE input from
 * `categories`, not a value inside it, even though the user who requested
 * this asked for it "behind the categories parameter": `categories` filters
 * OUTPUT (which findings come back), while pack selection is INPUT (which
 * scanners run). Folding pack selection into `categories` would mean asking
 * for a finding category silently changed which scanners ran — coupling two
 * independent axes that need to be reasoned about separately (a caller
 * might want `categories: ['null_safety']` with or without the language
 * packs enabled, and `include_language_packs: true` with or without a
 * `categories` filter).
 */
interface BugHuntInput extends ScanToolBaseInput {
  categories?: string[];
  include_language_packs?: boolean;
}

/**
 * Packs `bug_hunt` always runs, regardless of detected stack.
 * Exported so tests can assert against the real, current list instead of
 * duplicating the literal pack names.
 */
export const BUG_HUNT_BASE_PACKS: readonly string[] = ['p/r2c-bug-scan', 'p/security-audit'];

/**
 * `StackSnapshot.languages` entry -> the Semgrep registry pack it selects.
 *
 * IMPORTANT, verified (fix report, round 2; re-verified independently by
 * fetching both packs' raw YAML from the registry directly, not by trusting
 * that report's claim): every one of these five is Semgrep's per-language
 * DEFAULT bundle, and every one of them is ~100% `category: security` (XSS,
 * SQL injection, crypto, auth, SSRF, hard-coded secrets, …) — confirmed by
 * fetching and inspecting their rules (401 entries, 327 distinct: `p/javascript`
 * and `p/typescript` are the same 74 rule ids, sorted-and-diffed to confirm —
 * the two files differ only in rule ORDER, and every rule in both already
 * declares `languages: [javascript, typescript, ...]`, so either pack name
 * scans both languages' files with the identical rule set), and again by
 * running all seven configured packs (these five plus BUG_HUNT_BASE_PACKS)
 * against a fixture containing real instances of every canonical bug
 * subcategory: zero matches. Adding these widens SECURITY coverage per
 * language; it does not add race-condition, null-safety, off-by-one,
 * memory-leak or error-handling coverage for that language. See
 * `title`/`description` below, which say this to the model reading them
 * rather than only in this comment.
 */
const LANGUAGE_PACKS: ReadonlyMap<string, string> = new Map([
  ['javascript', 'p/javascript'],
  ['typescript', 'p/typescript'],
  ['python', 'p/python'],
  ['java', 'p/java'],
  ['go', 'p/golang'],
]);

/**
 * Pure: which of `LANGUAGE_PACKS` a set of detected languages selects.
 * Exported so the mapping itself is unit-testable without storage or the
 * filesystem.
 *
 * `javascript` and `typescript` collapse to ONE pack, never both: since
 * `p/javascript` and `p/typescript` are the identical 74 rules under two
 * registry names (see `LANGUAGE_PACKS`'s doc comment), running both against
 * a TypeScript project — which is the common case, since `detect-stack.sh`
 * (mirrored by `fallbackLanguages` below) only ever sets `typescript`
 * alongside `javascript`, never in place of it — used to pay for two
 * registry fetches and configure the same rule set twice for zero extra
 * coverage. Prefer `p/typescript` when TypeScript is detected (the more
 * specific signal); a plain JS project with no `typescript` entry still gets
 * `p/javascript`.
 */
export function languagePacksFor(languages: readonly string[]): string[] {
  const packs: string[] = [];
  for (const [language, pack] of LANGUAGE_PACKS) {
    if (language === 'javascript' && languages.includes('typescript')) continue; // p/typescript covers it — see doc comment
    if (languages.includes(language)) packs.push(pack);
  }
  return packs;
}

/**
 * Cheap, top-level-only filesystem signals, reusing `detect-stack.sh`'s own
 * per-language marker files rather than inventing new heuristics — same
 * shape as `scanSast.ts`'s own `anyCsprojInProject`. Only consulted when no
 * stack snapshot has ever been persisted for this project (`detect_stack`
 * was never run); the persisted snapshot is preferred whenever one exists.
 */
function fallbackLanguages(projectPath: string): string[] {
  const has = (name: string): boolean => existsSync(join(projectPath, name));
  const languages: string[] = [];
  if (has('package.json')) {
    languages.push('javascript');
    if (has('tsconfig.json')) languages.push('typescript');
  }
  if (has('pyproject.toml') || has('requirements.txt') || has('setup.py')) {
    languages.push('python');
  }
  if (has('pom.xml') || has('build.gradle') || has('build.gradle.kts')) languages.push('java');
  if (has('go.mod')) languages.push('go');
  return languages;
}

/**
 * Which languages `bug_hunt` should treat the project as using, preferring
 * the persisted `detect_stack` snapshot (same two-tier lookup as
 * `observabilitySetup.ts`'s `inferStack`: prefer the snapshot, fall back to
 * filesystem markers) so `bug_hunt` still gets stack-aware coverage the very
 * first time it runs against a project. Returns raw language names (e.g.
 * `typescript`), not pack names — `buildPackList` does that mapping itself,
 * via `languagePacksFor`, so the mapping step stays testable in isolation
 * from storage/filesystem access.
 */
function detectLanguages(ctx: InvokeContext): string[] {
  const snapshotLanguages = ctx.plugin.storage.stack.getLatest()?.snapshot.languages;
  return snapshotLanguages ?? fallbackLanguages(ctx.projectPath);
}

/** Options for {@link buildPackList}. */
export interface BuildPackListOptions {
  /** Mirrors `BugHuntInput.include_language_packs`. */
  readonly includeLanguagePacks: boolean;
  /** Raw language names (e.g. `typescript`), consulted only when
   *  `includeLanguagePacks` is true — see `detectLanguages`. */
  readonly languages: readonly string[];
  /**
   * Absolute paths to the local `configs/semgrep/bugfix-*.yml` rule files,
   * or `[]` to omit them. Defaults to `resolveBugfixRules()`'s real, on-disk
   * answer whenever the caller does not pass this field at all (production
   * code, in `invoke` below, always takes that default). Passing it
   * explicitly — including an explicit empty array — is how tests exercise
   * both the inclusion and the omission path without touching the
   * filesystem or Semgrep.
   */
  readonly bugfixRulesPaths?: readonly string[];
  /**
   * The project's own Semgrep rules, registered via `register_custom_rules`
   * and read back by `resolveCustomSemgrepConfigs`. Defaults to none, because
   * this assembly is pure: `invoke` passes the real answer, and tests pass
   * whatever they are exercising.
   */
  readonly customConfigs?: readonly string[];
}

/**
 * Assembles the full `--config=` pack list `bug_hunt` runs with. Extracted
 * from `invoke` (rather than inlined) so the assembly itself is
 * unit-testable without spawning Semgrep — see `bugHuntConfigs.test.ts`.
 *
 * Order: base packs, then the local bugfix rules (both on by default), then
 * the optional per-language packs — mirroring the header comment's own
 * description of what is always-on vs. opt-in.
 */
export function buildPackList(opts: BuildPackListOptions): string[] {
  const bugfixRulesPaths = opts.bugfixRulesPaths ?? resolveBugfixRules();
  return [
    ...BUG_HUNT_BASE_PACKS,
    ...bugfixRulesPaths,
    ...(opts.customConfigs ?? []),
    ...(opts.includeLanguagePacks ? languagePacksFor(opts.languages) : []),
  ];
}

/** The six canonical bug subcategories `mapSubcategory` classifies into.
 *  Exported so tests can assert against the real vocabulary instead of
 *  duplicating the literal names. */
export const BUG_SUBCATEGORIES: ReadonlySet<string> = new Set([
  'race_condition',
  'null_safety',
  'edge_case',
  'error_handling',
  'memory_leak',
  'off_by_one',
]);

/**
 * Wraps the semgrep parser to re-tag every finding as `category=bug`,
 * normalise the subcategory to the BUG_SUBCATEGORIES vocabulary where the
 * matching rule's own id says so (see `mapSubcategory`), and — when the
 * caller passed `categories` — drop every finding whose subcategory is not
 * in that list. Filtering happens here, inside the parser, rather than as a
 * generic post-filter in `scanToolFactory.ts`: `categories` is a `bug_hunt`
 * concept (its six-name vocabulary), not something every scan tool has.
 * Built per-invoke (not a module-level constant) because it closes over the
 * caller's `categories` input. Fingerprints are recomputed because the
 * original parser ran with `category=security`/`quality`/etc — but tool,
 * rule_id, file_path, line range and snippet are unchanged, so the
 * fingerprint identity stays stable across `bug_hunt` invocations.
 */
function makeBugCategoryParser(categories: readonly string[] | undefined): ScannerParser {
  return {
    name: semgrepParser.name,
    parse(input, ctx): ParserOutput {
      const out = semgrepParser.parse(input, ctx);
      const recategorised: Finding[] = out.findings.map((f) => recategoriseAsBug(f));
      const findings =
        categories !== undefined && categories.length > 0
          ? recategorised.filter(
              (f) => f.subcategory !== undefined && categories.includes(f.subcategory),
            )
          : recategorised;
      return { findings, cves: out.cves };
    },
  };
}

function recategoriseAsBug(f: Finding): Finding {
  const category: Category = 'bug';
  const subcategory = mapSubcategory(f.rule_id ?? '', f.subcategory);
  const refingerprintInput: Parameters<typeof computeFingerprint>[0] = { tool: f.tool };
  if (f.rule_id !== undefined) refingerprintInput.rule_id = f.rule_id;
  if (f.file_path !== undefined) refingerprintInput.file_path = f.file_path;
  if (f.line_start !== undefined) refingerprintInput.line_start = f.line_start;
  if (f.line_end !== undefined) refingerprintInput.line_end = f.line_end;
  if (f.snippet !== undefined) refingerprintInput.snippet = f.snippet;
  // Fingerprint inputs are unchanged compared to the security parser, so the
  // hash is stable. Compute once for consistency with the type discipline.
  const fingerprint = computeFingerprint(refingerprintInput);
  return { ...f, category, subcategory, fingerprint };
}

/**
 * Rule-id keyword classifier into the six canonical bug subcategories.
 *
 * Widened and validated (fix report, round 2) against every DISTINCT rule id
 * in every pack `bug_hunt` can now run (r2c-bug-scan, security-audit, and
 * the five language packs — 516 distinct ids; the packs' own file entries
 * sum to 670, but `p/javascript`/`p/typescript` are byte-identical rule
 * sets, so counting both double-counts 74): 13 correctly land in a
 * canonical bucket, 503 correctly fall through untouched. Two near-misses
 * shaped the exact wording below — `java...crypto.no-null-cipher` (an insecure-cipher
 * *name*, not a null-safety bug) and `python...logger-credential-leak` (a
 * secret-disclosure finding, not a memory leak) — both matched a bare
 * `null`/`leak` keyword and had to be excluded by requiring a
 * safety/resource-relevant qualifier alongside it, not just the bare word.
 *
 * The previous version of this function's fallback line was
 * `return existing && BUG_SUBCATEGORIES.has(existing) ? existing : existing`
 * — both ternary branches identical, so nothing was ever validated against
 * BUG_SUBCATEGORIES and the six patterns above rarely matched anything at
 * all (`list-modify-while-iterate`, `unchecked-subprocess-call` — both cited
 * as examples in an earlier version of this fix's own report — matched
 * NEITHER the old patterns nor `BUG_SUBCATEGORIES`; that citation was wrong,
 * caught by actually running the function instead of tracing it by hand).
 */
export function mapSubcategory(ruleId: string, existing: string | undefined): string | undefined {
  const lowered = ruleId.toLowerCase();
  if (/(race.condition|concurren|thread.safety|deadlock|\bmutex\b|synchroniz)/.test(lowered)) {
    return 'race_condition';
  }
  if (
    /(null.?safety|null.?check|null.?deref|null.?pointer|nullptr|nullable|none.check|nil.?deref|\bnpe\b|undefined.?behav|undefined.?check)/.test(
      lowered,
    )
  ) {
    return 'null_safety';
  }
  if (/(off.by.one|boundary|index.out|out.of.bound|out.of.range|overflow|underflow)/.test(lowered)) {
    return 'off_by_one';
  }
  if (
    /(memory.?leak|resource.?leak|unreleased|unclosed|disposed|use.after.free|dangling|before.close)/.test(
      lowered,
    )
  ) {
    return 'memory_leak';
  }
  if (
    /(error.handling|swallow|catch.all|exception|unchecked|uncaught|unhandled|ignored.return)/.test(
      lowered,
    )
  ) {
    return 'error_handling';
  }
  if (
    /(edge.case|empty.input|modify.*iterat|iterat.*modify|mutable.*default|default.*mutable)/.test(
      lowered,
    )
  ) {
    return 'edge_case';
  }
  // No canonical keyword matched: keep whatever raw, tool-specific tag the
  // generic Semgrep parser derived (rule id's last segment, or explicit
  // metadata) rather than forcing it into one of the six. This is most
  // findings from every pack except r2c-bug-scan — by design: a security
  // pack's XSS/SQLi/crypto rule is not a bug_hunt bug class, and must stay
  // filterable OUT of `categories: [...canonical names]`, not disguised as
  // one of them.
  return existing;
}

registerToolModule(
  makeScanTool({
    name: 'bug_hunt',
    title:
      'Bug hunt (Semgrep r2c-bug-scan + security-audit + always-on local JS/TS, Python, Go and ' +
      'Java bug rules; optional language packs, off by default; other languages still ' +
      'registry-only)',
    description:
      'Semgrep with p/r2c-bug-scan + p/security-audit always on, plus local, always-on ' +
      'JS/TS, Python, Go and Java rule packs: `configs/semgrep/bugfix-js.yml` (fourteen rules), ' +
      '`configs/semgrep/bugfix-py.yml` (ten rules), `configs/semgrep/bugfix-go.yml` (ten ' +
      'rules) and `configs/semgrep/bugfix-java.yml` (eight rules), each covering all six subcategories ' +
      'below for its language — race_condition, null_safety, off_by_one, memory_leak, ' +
      'error_handling, edge_case. `commands/guardian-fix.md` also ' +
      'names "broken happy paths" as a bug-hunting focus; that is not a syntactic pattern, ' +
      'so only its commonest concrete form is covered (an un-awaited mutating call inside ' +
      'an async function — rule `floating-mutation`, the race_condition entry, covering async ' +
      'declarations, arrow functions, and class/object methods, but NOT async function expressions ' +
      '— a Semgrep engine limitation, not an oversight) and nothing covers the rest of it. ' +
      "These are Semgrep OSS pattern rules: they match syntax, not " +
      'dataflow, so this finds the shapes bugs take, not bugs proven by analysis — a null ' +
      'dereference two functions from its guard is invisible to them. The heuristic-tier ' +
      'rules (WARNING/INFO) produce false positives by construction — `floating-mutation` ' +
      "matches on the method name alone, so it can't tell a real mutation like " +
      "`repo.save()` from an unrelated call that just shares the name, like `ctx.save()` " +
      "(Canvas 2D's synchronous state-stack push, nothing to do with persistence) — both " +
      "fire identically. That's why it isn't ERROR and why `severity_min` exists to " +
      'filter it out. Go is where the registry pack leaves the biggest hole among the ' +
      'languages it partially covers: p/r2c-bug-scan ' +
      'ships 5 Go rules and only 2 land in a bug class, both integer-overflow, so ' +
      'error_handling, race_condition, null_safety, memory_leak and edge_case were all empty ' +
      'before this local pack. Its own gaps: no goroutine-leak rule; no loop-variable-capture ' +
      'rule (built and verified working, then deliberately excluded — Go 1.22 made loop ' +
      'variables per-iteration and Semgrep cannot read go.mod, so on a modern module it would ' +
      'fire on correct code); `body-not-closed` only recognises http.Get, so http.Post and ' +
      'client.Do(req) leak identically and are not covered; `lock-without-defer` accepts any ' +
      'defer mu.Unlock() in the block, so it cannot tell a correctly scoped unlock from one ' +
      'deferred in the wrong branch, and it does not cover sync.RWMutex read locks — the pattern ' +
      'matches the literal Lock()/Unlock() method names, not RLock()/RUnlock(), so a read-lock ' +
      'without defer, a common Go idiom, is entirely outside its reach (the write lock, ' +
      'Lock()/Unlock(), on a *sync.RWMutex IS covered); `body-not-closed` and ' +
      '`ticker-not-stopped` match only the := declaration form, so the var-then-assign form is ' +
      'silent for both; `nil-map-write` only ' +
      'catches a locally var-declared map — a nil map arriving as a function parameter, a ' +
      'struct field, or a return value panics identically on write and is not covered, ' +
      'arguably the commoner real-world shape; and `err-blank-assign` fires on deliberate ' +
      'discards like ' +
      '`_ = os.Remove(tmp)` in a cleanup path, which is why it is WARNING. Java is the ' +
      'emptiest language of the four: p/r2c-bug-scan ships 4 Java rules and NONE land in a ' +
      'bug class — all four are equality and comparison style — so every subcategory was at ' +
      'zero, in the language whose most famous defect is the NullPointerException. Its own ' +
      'gaps: no `Integer ==` rule — expressing it needs type inference Semgrep OSS does not ' +
      'have, and the attempt fired on `v == null` and on primitive comparison, so it was ' +
      'dropped rather than shipped as a rule that would be uninstalled within a day; ' +
      '`stream-not-closed` only recognises `new FileInputStream(...)`, and only by that ' +
      'simple name, so `FileOutputStream`, `FileReader`, `Socket` and every other closeable ' +
      'leak identically and are not covered — as does a fully-qualified ' +
      '`new java.io.FileInputStream(...)`, which the pattern does not see (measured); ' +
      '`static-dateformat` only recognises `SimpleDateFormat`, so a shared `Calendar` or ' +
      '`Matcher` in a static field is not covered, but it ships a single FULLY-QUALIFIED ' +
      'pattern, so a `static final java.text.SimpleDateFormat` field in a file with no import ' +
      'IS seen — it was not before (measured across four import shapes: the qualified pattern ' +
      'also matches the short forms whenever an import lets Semgrep resolve them, while the ' +
      'short pattern never matched the qualified one, so the short branch was inert and was ' +
      'deleted); `map-get-deref` cannot tell a nullable map from one whose keys are ' +
      'guaranteed present by anything other than the guard and population shapes it ' +
      'enumerates, so a map filled in a static initialiser or a total enum mapping declared ' +
      'as a `Map` is still flagged; and `modify-during-iteration` only matches the ' +
      'enhanced-for form, so an indexed loop removing from the list it indexes has the same ' +
      'defect and is missed. Two Java rules restrict the receiver by DECLARED type, which buys precision ' +
      'and costs recall: `metavariable-type` matches the exact declared type with no ' +
      'subtyping (measured — `type: List` does NOT match a CopyOnWriteArrayList, which is ' +
      'precisely what keeps the rule off it), so `map-get-deref`, enumerating Map, HashMap, ' +
      'TreeMap, LinkedHashMap and ConcurrentHashMap, is silent on a map behind a project ' +
      'interface or a generic type parameter (`<M extends Map<K,V>> ... m.get(k).f()`), ' +
      'though a raw `Map` still fires (measured); and `modify-during-iteration`, enumerating ' +
      'List, ArrayList, LinkedList, Set, HashSet, LinkedHashSet and Collection, is silent on ' +
      'a Deque, a Queue, a SortedSet or a project collection type — an EnumMap is outside ' +
      "map-get-deref's enumeration for the same reason. Both bind the receiver through a " +
      '`metavariable-pattern` accepting a bare name OR a `this.`-qualified one; before that, ' +
      '`cache.get(k).trim()` fired while `this.cache.get(k).trim()` was invisible — same ' +
      'class, same field, same bug (measured). `map-get-deref` shipped with NO guard ' +
      'exclusion at all, so the canonical Java guard `if (m.containsKey(k)) { ... ' +
      'm.get(k).trim() ... }` fired at ERROR and advised `getOrDefault` on already-guarded ' +
      'code; it now excludes the measured shapes that prove the key present, and every one of ' +
      'them is SCOPED TO THE ARM THE GUARD ACTUALLY PROVES: the inline `containsKey` and ' +
      '`get() != null` tests IN THE CONDITION OF AN `if` (alone or as either operand of a ' +
      'conjunction) with the dereference in the THEN branch, braced or braceless; ' +
      '`while (m.containsKey(k))`; the same two tests used as an EXPRESSION rather than as the ' +
      'condition of anything — `return m.containsKey(k) && m.get(k).isEmpty();`, or assigned to ' +
      'a local — together with their De Morgan duals `!m.containsKey(k) || ...` and ' +
      '`m.get(k) == null || ...`, where `||` short-circuits so the right operand only runs when ' +
      'the key IS present; all four ternary polarities, with the dereference in the guarded arm; ' +
      'an early return/throw/continue under `!containsKey` or `get() == null`; population by ' +
      '`put`, `putIfAbsent`, `computeIfAbsent` or `if (!containsKey) { put(); }`; and ITERATION ' +
      "OVER THE MAP'S OWN keySet() — `for (String k : m.keySet()) { ... m.get(k).trim() ... }`, " +
      'the commonest map-iteration idiom in Java, where the loop header binds the key FROM THE ' +
      'MAP ITSELF so presence is guaranteed on every path reaching the dereference. That last ' +
      'clause unifies the map AND the key, so iterating one map and dereferencing another, or ' +
      'dereferencing a key other than the loop variable, both still fire and are real bugs; the ' +
      '`entrySet()` form and a key set copied to a local before the loop are NOT reached and are ' +
      'accepted false positive (12). The ARM ' +
      'SCOPING is the whole point and was a shipped regression before it: written unscoped, ' +
      '`pattern-not-inside: if (m.containsKey(k)) { ... }` matches the entire IF-ELSE statement ' +
      'and the ternary clauses matched the entire conditional expression, so BOTH arms were ' +
      'excluded — including the branch the guard proves is a GUARANTEED NullPointerException. ' +
      'Measured on a file of eight such bugs: six fired before the guard exclusions went in, ' +
      'one after, eight now. `X || m.containsKey(k)` is still NOT treated as a guard and still ' +
      'fires — `force` true with the key absent is an NPE — and it is structurally ' +
      'distinguishable from the negative-first form, which is why excluding one does not ' +
      'reintroduce the other. `modify-during-iteration` had ' +
      'a false negative worth more than any of its false positives — a `remove()` inside a ' +
      '`switch` followed by `break;` is a real ConcurrentModificationException, because that ' +
      'break leaves the SWITCH and not the loop, and the paired `remove(); break;` exclusion ' +
      'swallowed it whole; the plain-break exclusion now applies only when the removal sits in ' +
      'a `switch` that is itself INSIDE the for-each over that collection. The nesting ORDER is ' +
      'what the clause tests, and it used to test mere lexical containment — any removal ' +
      'anywhere inside a `case` re-armed the rule, including one inside a LOOP written in that ' +
      'case, where a plain `break` exits the loop and the code is correct; a switch dispatching ' +
      'a command with a search-and-remove loop in one arm fired three times. return, throw and ' +
      'a LABELLED break do leave the method or the loop from inside a switch and ' +
      'stay excluded everywhere. `loop-lte-length` restricts its array metavariable to an ' +
      'ARRAY TYPE, because `$A.length` otherwise matches any int field named `length` and ' +
      "fired at ERROR on a domain object's deliberately inclusive loop; measured, that costs " +
      'no recall — parameter, local, field, `this.`-qualified field and `var`-inferred local ' +
      'arrays are all still matched. The exit-terminated exclusions across `map-get-deref`, ' +
      '`optional-get-no-ispresent` and `modify-during-iteration` tolerate exactly ONE ' +
      'statement between the guard (or the removal) and the exit rather than an arbitrary ' +
      'ellipsis: measured, the ellipsis form matches DEEP, so ' +
      '`if (!m.containsKey(k)) { if (strict) { return ""; } }` and ' +
      '`items.remove(s); if (done) { break; }` both stop firing — and both are real bugs. ' +
      '`empty-catch` honours the ' +
      'Checkstyle/IntelliJ convention and never fires when the exception variable is named ' +
      '`ignore`, `ignored` or `expected` — the flip side being that a genuinely swallowed ' +
      'exception escapes the rule simply by being named `ignored`. The same trade has a second ' +
      'edge worth stating outright, because `empty-catch` is now the ONLY rule left at ERROR ' +
      'and the whole tier argument rests on it: the JUnit expected-exception idiom (call the ' +
      'code, `throw new AssertionError` if it did not throw, empty `catch`) fires at ERROR when ' +
      'the caught variable is named `e`, and is silent when it is named `expected` — the test ' +
      'idiom has to use the conventional name. ' +
      'READ THIS BEFORE WONDERING WHY A JAVA FIX PR CAME BACK EMPTY: seven of these eight ' +
      'rules are WARNING, and create_fix_pr defaults severity_min to `high`, so the Java pack ' +
      'contributes almost nothing to the DEFAULT fix-PR set — ask for it with ' +
      '`severity_min: "medium"`. bug_hunt itself does not filter by default, so nothing ' +
      'disappears from a SCAN; only the fix PR is affected. That default was deliberately NOT ' +
      'changed here: it affects all four language packs and is a separate decision. The tier ' +
      "split applies this pack's own criterion cold, stated as a question about the OUTPUT " +
      'rather than the pattern — is what the rule EMITS always a bug? A rule whose ' +
      'correctness depends on having recognised a GUARD emits a false positive every time it ' +
      'meets a guard shape nobody enumerated, and no exclusion list closes that, because the ' +
      'guard can always be one method away. Only `empty-catch` clears that bar, and it clears ' +
      'it for the one reason available: its escape hatch is not a guard but a DECLARATION OF ' +
      'INTENT the rule itself reads (the Checkstyle/IntelliJ ignore/ignored/expected ' +
      'convention), so what it emits afterwards is an UNMARKED silent swallow — a bug ' +
      'whatever the author meant. One rule in eight is the honest result for a syntactic ' +
      'matcher with no dataflow, not a failure of the pack. `map-get-deref`, ' +
      '`modify-during-iteration`, `static-dateformat` and `loop-lte-length` were demoted on ' +
      'that criterion. `loop-lte-length` only after the obvious tightening was MEASURED and ' +
      'rejected: requiring the body to index `a[i]` fixes the loop that never indexes `a`, ' +
      'does NOT fix the sentinel loop that fills a longer array ' +
      '(`b[i] = (i < a.length) ? a[i] : -1` is correct, and the guarded `a[i]` sits right ' +
      'there inside the ternary), and LOSES a real bug where the out-of-bounds index is ' +
      'passed to a helper (`sum += at(a, i)`) — a false positive traded for a false ' +
      'negative, so the patterns were left alone and only the tier moved. ' +
      '`optional-get-no-ispresent` is WARNING for the same reason, a round earlier: ERROR is ' +
      'for a pattern that is a bug regardless of ' +
      'intent, and `o.get()` is a bug only when UNGUARDED. It recognises exactly these guard ' +
      'shapes, enumerated rather than summarised because the summary that stood here — ' +
      '"inline against the same Optional variable" — was falsifiable and was falsified by a ' +
      'compound condition, a multi-statement exit, a `while` and an `Optional.of`: ' +
      '`if (o.isPresent())` alone OR as either operand of a conjunction, IN THE CONDITION OF AN ' +
      '`if`, with the `get()` in the THEN branch, braced or braceless — the ELSE arm is a ' +
      'guaranteed NoSuchElementException and still fires; `while (o.isPresent())`; the same ' +
      'test used as an EXPRESSION rather than as the condition of anything, ' +
      '`return o.isPresent() && o.get().isEmpty();`, plus the negative-first disjunctions ' +
      '`!o.isPresent() || ...` and `o.isEmpty() || ...`, which short-circuit the same way; an ' +
      'early return/throw/continue/break under `!isPresent()` or ' +
      '`isEmpty()`, with or without one statement before the exit; the three ternary ' +
      'forms, with the `get()` in the arm the condition PROVES safe (a ternary needs its own ' +
      'clauses because it is a conditional EXPRESSION, a ' +
      'different AST node from an `if` statement); `if (o.filter(p).isPresent())`; and an ' +
      '`Optional<T> o = Optional.of(...)` construction, which cannot be empty — `ofNullable` ' +
      'can, and still fires. It misses any guard that reaches the check through another ' +
      'method, and it deliberately does not treat `a.isPresent() || b` as a guard — that ' +
      'proves nothing about `a`, unlike the negative-first form above. ' +
      'The concrete missed case is a guard delegated to a helper, ' +
      '`if (!present(o)) { return d; }`, which needs interprocedural analysis Semgrep OSS ' +
      'does not do; that shape is a false positive and always will be, which is why the rule ' +
      'is WARNING instead of carrying an ever-longer exclusion list. ' +
      'Twelve Java limitations are accepted rather than fixed, each reproduced against the ' +
      'review fixtures, and EACH STATES ITS DIRECTION — for six waves this list had nine ' +
      'entries and all nine were false positives, which is the asymmetry that let a wave close ' +
      'a false positive, silently delete recall, and still go green. FALSE POSITIVES: (1) `stream-not-closed` on `open(); try {} finally { close(); }` (already ' +
      'the stated reason it is WARNING); (2) `static-dateformat` on a static final ' +
      'SimpleDateFormat whose every access goes through a synchronized method (proving ALL ' +
      'accesses are synchronized is whole-program analysis, which Semgrep OSS does not do; ' +
      'this used to add "and a shared formatter serialises every caller anyway", which is a ' +
      'PRODUCT argument rather than the tier criterion, and is why the rule sat at ERROR for ' +
      'four rounds carrying a documented un-fixable false positive); (3) `loop-lte-length` on ' +
      '`i <= a.length` where the body guards with `i < a.length` or never indexes `a` (the ' +
      'tightening was tried and rejected — see the tier note above); (4) ' +
      '`printstacktrace-only` on the one place the call is right — the fallback when the ' +
      'logger itself threw; (5) `map-get-deref`, `optional-get-no-ispresent` and ' +
      '`modify-during-iteration` where TWO OR MORE statements sit between the guard (or the ' +
      'removal) and the exit — `if (!m.containsKey(k)) { log(); metric(); return ""; }`, ' +
      '`items.remove(s); log(s); n++; break;` — the deliberate price of not using a ' +
      'deep-matching ellipsis, which would hide real bugs instead; (6) all three of those ' +
      'rules on any guard reached THROUGH A HELPER METHOD, `if (!present(o)) { return d; }`, ' +
      'which needs interprocedural analysis; (7) `map-get-deref` on a key whose presence ' +
      'is established outside its enumerated shapes — a map filled in a static initialiser, ' +
      'or a total enum mapping declared as a `Map`; (8) `map-get-deref` and ' +
      '`optional-get-no-ispresent` on a guard held in a LOCAL BOOLEAN — ' +
      '`boolean present = m.containsKey(k); if (!present) { return ""; }` — which is dataflow, ' +
      'not syntax, and outside Semgrep OSS; (9) the same two on a conjunction CHAIN of ' +
      'three or more operands — `flag && o.isPresent() && o.get().isEmpty()` — because the ' +
      'expression clause binds the conjunction LEFT OPERAND to the guard test itself, and a ' +
      'Java conjunction nests to the left, so in a chain that left operand is another ' +
      'conjunction rather than the guard. That row USED to justify itself with a measurement ' +
      'taken on a line carrying TWO get() calls, which does not generalise — re-measured in ' +
      'wave 7, the last-but-one-operand clause silences single-get chains of any length, so ' +
      'it is deferred by scope rather than rejected; and (12) `map-get-deref` on the two ' +
      'keySet()-adjacent idioms the keySet() exclusion does not reach — `entrySet()`, where ' +
      'the key is `e.getKey()` and not the loop variable, and a key set copied to a local ' +
      'before the loop, where the header no longer mentions keySet(). FALSE NEGATIVES, the ' +
      'direction nobody was writing down for six waves: (10) the INVALIDATED-GUARANTEE class ' +
      '— a guarantee the guard establishes and the code then destroys INSIDE the region the ' +
      'exclusion covers, `if (m.containsKey(k)) { m.remove(k); return m.get(k).trim(); }` and ' +
      'four more measured shapes, all guaranteed throws, all silent. Same root cause as the ' +
      'else-arm bug — pattern-not-inside excludes the whole node it matched — but on the ' +
      'TEMPORAL axis rather than the branch axis, and not fixable without dataflow; and (11) ' +
      'the same two rules on a guard held in a LOCAL BOOLEAN, the recall mirror of (8). ' +
      'JS/TS, Python, Go and Java only: no other language has ' +
      'a local rule pack yet, so C#, PHP, Ruby and Rust get only the ' +
      'registry coverage described below, same as before these packs existed. The local ' +
      'packs degrade rather than failing the whole scan if one is ever hand-edited into a bad ' +
      'state — a YAML syntax error drops just that file and retries with everything else, a ' +
      'single bad rule pattern inside an otherwise-valid file is dropped alone and every other ' +
      "rule's findings still return — verified against the real built server, not assumed. " +
      "These rules do not make bug_hunt a substitute for the model-driven guardian-fix " +
      'path: they catch shapes, reading the code catches reasons. Optional ' +
      '`include_language_packs` (off by default) also runs one per-language pack for each ' +
      'language family `detect_stack` finds in the project (or, absent a snapshot, a quick ' +
      'package.json/tsconfig.json/pyproject.toml/pom.xml/go.mod check): p/javascript OR ' +
      'p/typescript for a JS/TS project — never both, they are the identical 74 rules under ' +
      'two registry names, so only p/typescript runs once TypeScript is detected — plus ' +
      "p/python, p/java, p/golang. Read this before turning it on: every one of those is " +
      "Semgrep's per-language SECURITY bundle (XSS, SQL/command injection, crypto, auth, " +
      'SSRF, hard-coded secrets, …) — verified against their 327 distinct rules and a live ' +
      'scan of a fixture built to trigger every canonical subcategory below: zero ' +
      'matches, in any language. They widen security coverage per language; they add no ' +
      'race-condition, null/undefined-safety, off-by-one, memory-leak or swallowed-error ' +
      'coverage. Overlap with the always-on p/security-audit is real but partial, not "largely ' +
      'redundant" — measured (exact rule-id duplication): 22% overall, but only ~9% for the ' +
      'JS/TS packs specifically (up to 40-43% for Java/Go) — most of what they add, especially ' +
      'for JS/TS, is net-new security scanning, not duplicate coverage. Beyond the local ' +
      'JS/TS, Python, Go and Java packs, p/r2c-bug-scan (44 rules: 32 Python, 5 Go, 4 Java, 3 JS/TS) is the only ' +
      'registry pack reaching these six classes, and only for Python and Go — Java, C#, ' +
      'PHP, Ruby and Rust get none of them from the registry; C#, PHP, Ruby and Rust have ' +
      'none yet from a local pack either (Java does — `configs/semgrep/bugfix-java.yml`, ' +
      'described above). On any of those languages, a quiet or security-only result (with or ' +
      'without the language packs) is not evidence of a bug-free project; pair with ' +
      "`scan_sast` or the guardian-bugfix skill's manual review. " +
      'Findings are categorised as `bug`, with subcategories (race_condition, null_safety, ' +
      'edge_case, error_handling, memory_leak, off_by_one) attached where the matching rule\'s ' +
      'own id says so — everything else keeps its own raw, tool-specific tag instead of being ' +
      'forced into one of those six. `categories` and `include_language_packs` are ' +
      'independent inputs on purpose: `include_language_packs` decides which scanners RUN, ' +
      '`categories` decides which findings already found are RETURNED — use ' +
      '`categories: ["null_safety", "edge_case"]` to narrow to the six bug classes regardless ' +
      'of which packs ran. If a configured pack is retired from the Semgrep registry, the ' +
      'scan re-runs with whichever packs still resolve and reports the gap via `missing_tools` ' +
      'instead of silently scanning nothing.',
    scan_type: 'bugs',
    category: 'bug',
    inputSchema: {
      project_path: ProjectPath,
      severity_min: SeverityMin,
      auto_fix: AutoFix,
      allow_dirty: AllowDirty,
      categories: z
        .array(z.string())
        .optional()
        .describe('Restrict to these bug subcategories (e.g. race_condition, null_safety).'),
      include_language_packs: z
        .boolean()
        .optional()
        .default(false)
        .describe(
          'Off by default. When true, also run one per-language Semgrep pack for each ' +
            'language family detect_stack finds in the project (or a filesystem fallback): ' +
            'p/javascript OR p/typescript for a JS/TS project (never both — identical 74-rule ' +
            'packs under two registry names), plus p/python, p/java, p/golang. These are ' +
            'per-language SECURITY bundles (XSS, injection, crypto, auth, SSRF, hard-coded ' +
            'secrets, ...), not bug-class rules — they add no race-condition/null-safety/off-by-one/' +
            'memory-leak/error-handling coverage. Independent of `categories`: this decides ' +
            'which scanners run (input); `categories` decides which findings come back ' +
            '(output). Turn on when you specifically want broader per-language security ' +
            'scanning alongside the bug hunt.',
        ),
      force: Force,
    },
    invoke: async (input: BugHuntInput, ctx): Promise<ScannerInvocation> => {
      const reportDir = ensureReportDir(ctx.projectPath, ctx.scanId, 'bugs');
      const tools_run: ToolRun[] = [];
      const missing_tools: string[] = [];
      const parser_inputs: ScannerInvocation['parser_inputs'] = [];

      const semgrepBin = await scannerAvailable('semgrep');
      if (!semgrepBin) {
        tools_run.push({ name: 'semgrep', status: 'skipped', reason: 'not_installed' });
        missing_tools.push('semgrep');
        return {
          outcome: 'completed',
          tools_run,
          missing_tools,
          parser_inputs,
          report_paths: [reportDir],
        };
      }

      // Language packs are off by default (§ BugHuntInput above: this is
      // deliberately not part of `categories`, which filters output, not
      // input). Detection only runs when asked — a project with a
      // persisted JS/TS stack snapshot does NOT get p/javascript/p/typescript
      // added unless the caller opts in. The local bugfix-*.yml rules, by
      // contrast, are NOT gated behind a flag — `buildPackList` appends
      // all of them by default (omitting them only if resolveBugfixRules()
      // finds none); see this file's header comment.
      const configuredPacks: readonly string[] = buildPackList({
        includeLanguagePacks: input.include_language_packs === true,
        languages: input.include_language_packs === true ? detectLanguages(ctx) : [],
        customConfigs: resolveCustomSemgrepConfigs(ctx.plugin),
      });
      const categoryParser = makeBugCategoryParser(input.categories);

      const outFile = join(reportDir, 'bugs.json');
      const runWithPacks = (packs: readonly string[]): Promise<ProcessRunResult> => {
        const args = packs.map((pack) => `--config=${pack}`);
        args.push('--json', '--quiet', '--output', outFile);
        if (input.auto_fix === true) args.push('--autofix');
        args.push(ctx.projectPath);
        return runProcess({
          command: 'semgrep',
          args,
          cwd: ctx.projectPath,
          env: ctx.scriptEnv,
          signal: ctx.signal,
          onLog: ctx.onLog,
        });
      };
      // A gap that survives every retry attempt: nothing scanned, and that
      // must never be reported as a clean bug report. `outcome: 'completed'`
      // matches scan_sast's convention for an expected, named gap — the
      // signal lives in `missing_tools` / `coverage`, not in `outcome`.
      // `missing_tools` gets the bare tool name only (never
      // `semgrep:<pack>`) — see the header comment for why; the pack-level
      // detail lives in the `reason` string below instead.
      const reportGap = (failures: readonly ConfigDownloadFailure[]): ScannerInvocation => {
        tools_run.push({
          name: 'semgrep',
          status: 'failed',
          reason: `no configured pack could be scanned (${describeConfigFailures(failures)})`,
        });
        missing_tools.push('semgrep');
        return {
          outcome: 'completed',
          tools_run,
          missing_tools,
          parser_inputs,
          report_paths: [reportDir],
        };
      };

      const result = await runWithPacks(configuredPacks);
      const raw = readJsonSafe(outFile);
      const failures = findConfigDownloadFailures(raw);

      if (failures.length === 0) {
        // The ordinary case: no WHOLE `--config=` failed to load —
        // findConfigDownloadFailures found nothing whole-config-fatal. That
        // does NOT mean the exit code is clean: a single bad RULE inside an
        // otherwise-valid local file (e.g. a typo'd bugfix-js.yml pattern)
        // also exits non-zero/non-one, but Semgrep still scans with
        // everything else that loaded — verified live, not assumed (see
        // semgrepConfigFailure.ts's header comment). wasAnythingScanned is
        // what tells the two apart; exit code/outcome alone cannot (same
        // file, same comment).
        if (raw) parser_inputs.push({ parser: categoryParser, input: raw });
        const okByExit = result.outcome === 'completed' || result.exitCode === 1;
        const ok = okByExit || wasAnythingScanned(raw);
        const toolRun: ToolRun = { name: 'semgrep', status: ok ? 'ok' : 'failed' };
        if (!okByExit) {
          // Either genuinely failed, or "ok" only because something was
          // scanned anyway despite a non-clean exit — both need the
          // human-readable reason attached. Before this, a malformed local
          // rule file reported status:'failed' with NO reason at all,
          // alongside assessCoverage's "install semgrep" warning — which
          // sends a user chasing their toolchain instead of their own rule
          // file (bugfix-rules-jsts task-3 fix round).
          const reason = describeRawErrors(raw);
          if (reason !== null) toolRun.reason = reason;
        }
        tools_run.push(toolRun);
        return {
          outcome: ok ? 'completed' : result.outcome,
          tools_run,
          missing_tools,
          parser_inputs,
          report_paths: [reportDir],
        };
      }

      // At least one configured pack failed to download (registry
      // retirement, outage, typo). A single bad `--config=` aborts the
      // WHOLE invocation — `raw` above has empty results/paths.scanned even
      // for packs that resolved fine — so it cannot be reused as-is. Re-run
      // with whatever survives rather than reporting a scan that covered
      // nothing.
      const survivors = survivingPacks(configuredPacks, failures);
      if (survivors.length === 0 || survivors.length === configuredPacks.length) {
        // Nothing to retry with (every pack failed), or the failure(s)
        // could not be attributed to a specific configured pack (so a retry
        // would just reproduce the same result).
        return reportGap(failures);
      }

      const retry = await runWithPacks(survivors);

      // A cancelled/timed-out/oversized retry never produced a genuine
      // second attempt — the child was killed before (or while) writing
      // `--output`, so `outFile` may still hold attempt one's STALE content,
      // or nothing at all. Reading that as "the retry also hit a download
      // failure" would duplicate attempt one's own failure, and forcing
      // `outcome: 'completed'` below would misreport a cancelled/timed-out
      // run as having finished normally — the same family of untruth this
      // whole fix exists to close. Propagate the retry's real outcome
      // instead, and report only what attempt one actually found (never
      // touching `outFile` in this branch at all).
      if (retry.outcome !== 'completed' && retry.outcome !== 'failed') {
        tools_run.push({
          name: 'semgrep',
          status: 'failed',
          reason:
            `retry with ${survivors.join(', ')} did not finish (${retry.outcome}) — ` +
            `original gap: ${describeConfigFailures(failures)}`,
        });
        missing_tools.push('semgrep');
        return {
          outcome: retry.outcome,
          tools_run,
          missing_tools,
          parser_inputs,
          report_paths: [reportDir],
        };
      }

      const retryRaw = readJsonSafe(outFile);
      const retryFailures = findConfigDownloadFailures(retryRaw);
      const retryOk =
        retryFailures.length === 0 && (retry.outcome === 'completed' || retry.exitCode === 1);

      if (!retryOk) {
        // The retry ran to a real exit but didn't help either (network
        // flake, or the "survivor" just got retired too) — combine every
        // failure we saw and refuse to trust either attempt's output.
        return reportGap([...failures, ...retryFailures]);
      }

      if (retryRaw) parser_inputs.push({ parser: categoryParser, input: retryRaw });
      tools_run.push({
        name: 'semgrep',
        status: 'ok',
        reason: `ran with ${survivors.join(', ')} only — ${describeConfigFailures(failures)}`,
      });
      missing_tools.push('semgrep');
      return {
        outcome: 'completed',
        tools_run,
        missing_tools,
        parser_inputs,
        report_paths: [reportDir],
      };
    },
  }),
);
