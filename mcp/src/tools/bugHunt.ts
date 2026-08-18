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
 * Python, docs/superpowers/specs/2026-08-18-bugfix-rules-python-design.md)
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
      'Bug hunt (Semgrep r2c-bug-scan + security-audit + always-on local JS/TS and Python ' +
      'bug rules; optional language packs, off by default; other languages still registry-only)',
    description:
      'Semgrep with p/r2c-bug-scan + p/security-audit always on, plus local, always-on ' +
      'JS/TS and Python rule packs: `configs/semgrep/bugfix-js.yml` (fourteen rules) and ' +
      '`configs/semgrep/bugfix-py.yml` (ten rules), each covering all six subcategories ' +
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
      'filter it out. JS/TS and Python only: no other language has ' +
      'a local rule pack yet, so Go, Java, C#, PHP, Ruby and Rust get only the ' +
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
      'JS/TS and Python packs, p/r2c-bug-scan (44 rules: 32 Python, 5 Go, 4 Java, 3 JS/TS) is the only ' +
      'registry pack reaching these six classes, and only for Python and Go — Java, C#, ' +
      'PHP, Ruby and Rust get none of them from the registry, and none yet from a local ' +
      'pack either. On any of those languages, a quiet or security-only result (with or ' +
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
