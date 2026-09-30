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
 * leak/error-handling classes the tool's category vocabulary names). The
 * description below says which languages the local packs cover; the
 * registry-pack numbers are kept here, not in the model-facing text.
 *
 * `buildPackList` (below) is where every `--config=` value gets assembled,
 * and it always appends every local `configs/semgrep/bugfix-*.yml` pack —
 * one hand-authored file per language, each covering the same six bug
 * classes for its language (thirteen rules for JS/TS, design of record:
 * the design of record; ten for
 * Python, the design of record;
 * nine for Go, the design of record —
 * Go is where the registry pack leaves the biggest hole among the languages
 * it partially covers (5 Go rules, only 2 land in a bug class), and the
 * design of record records a fourth exclusion clause that shipped dead and
 * was removed, as was the tenth rule, `edge-case-append-discarded`, whose
 * true-positive set is empty in any project that compiles; seven for Java,
 * the design of record — Java is
 * emptier still: p/r2c-bug-scan ships 4 Java rules and NONE of
 * them land in a bug class, all four being equality/comparison style;
 * eleven for C#,
 * language where the registry is at zero — p/r2c-bug-scan ships no C# rules
 * at all; six for PHP,
 * the design of record; and exactly
 * ONE for Rust,
 * one rule is the whole answer there, not partial coverage, and Ruby ships
 * nothing at all, both by measurement)
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
 * Java/Go) — not "largely redundant". The description and the
 * `include_language_packs` schema text tell the model the conclusion
 * (security bundles, not bug classes); the measurements stay here.
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

import { presentInProject } from '../platform/projectFs.js';
import { join } from 'node:path';
import { z } from 'zod';
import { resolveBugfixRules } from '../platform/configsDir.js';
import {
  legacyRegistrationNote,
  legacyRegistrationsNotApplied,
  resolveCustomSemgrepConfigs,
} from '../platform/customRules.js';
import { semgrepExcludeArgs } from '../platform/guardianIgnore.js';
import { ScanScopeInput } from '../platform/scope.js';
import { semgrepOnFiles } from '../runners/fileBatchScan.js';
import { withSemgrepEngineNote } from '../runners/semgrepConfigs.js';
import { checkSemgrepReport, describeNoRuleLoaded, describePartialParse, describeRulesNotLoaded } from '../runners/semgrepReport.js';
import { localRuleIdNormalizer, noRuleLoaded } from '../runners/semgrepRuleIds.js';
import { semgrepParser, semgrepParserFor } from '../runners/scannerParsers/semgrep.js';
import type { ProcessRunResult } from '../runners/processRunner.js';
import { runSemgrep } from '../runners/semgrepRun.js';
import { applySemgrepCoverageGaps, markMissing, semgrepCoverageGaps } from '../runners/semgrepCoverageGaps.js';
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
import type { PluginContext } from '../context.js';
import {
  makeScanTool,
  type InvokeContext,
  type ResponseView,
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
 * memory-leak or error-handling coverage for that language. The description
 * and the `include_language_packs` schema text below say so to the model.
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
 * a TypeScript project — which is the common case, since `detect_stack`
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
 * Cheap, top-level-only filesystem signals, reusing `detect_stack`'s own
 * per-language marker files rather than inventing new heuristics — same
 * shape as `scanSast.ts`'s own `anyCsprojInProject`. Only consulted when no
 * stack snapshot has ever been persisted for this project (`detect_stack`
 * was never run); the persisted snapshot is preferred whenever one exists.
 */
function fallbackLanguages(projectPath: string): string[] {
  const has = (name: string): boolean => presentInProject(projectPath, name);
  const languages: string[] = [];
  if (has('package.json')) {
    languages.push('javascript');
    if (has('tsconfig.json')) languages.push('typescript');
  }
  if (has('pyproject.toml') || has('requirements.txt') || has('setup.py')) {
    languages.push('python');
  }
  if (has('pom.xml') || has('build.gradle')) languages.push('java');
  // A Kotlin build script, as detect_stack reads it — never Java: p/java ran
  // against Kotlin sources and read as a Java bug hunt with 0 findings.
  if (has('build.gradle.kts')) languages.push('kotlin');
  if (has('go.mod')) languages.push('go');
  return languages;
}

/**
 * Detected languages with a bug pack of their own: a local
 * `configs/semgrep/bugfix-*.yml` (always on), or a `LANGUAGE_PACKS` entry.
 * Kotlin and Ruby have neither — their code gets only whatever registry
 * rules happen to target them.
 */
const LANGUAGES_WITH_BUG_RULES: ReadonlySet<string> = new Set([
  'javascript', 'typescript', 'python', 'go', 'java', 'csharp', 'php', 'rust', ...LANGUAGE_PACKS.keys(),
]);

/**
 * Pure: the detected languages `bug_hunt` has no pack for at all, in the
 * order detected. Exported for tests.
 */
export function languagesNotCovered(languages: readonly string[]): string[] {
  return [...new Set(languages.filter((l) => !LANGUAGES_WITH_BUG_RULES.has(l)))];
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
 *
 * The snapshot is THIS project's: `stack.getLatest()` was the newest one of
 * any project, so a TypeScript project got Python's packs (and none of its
 * own) whenever a Python project was detected last (Task 24).
 */
function detectLanguages(plugin: PluginContext, projectPath: string): string[] {
  const snapshotLanguages = plugin.storage.stack.getLatestForProject(projectPath)?.snapshot.languages;
  return snapshotLanguages ?? fallbackLanguages(projectPath);
}

/**
 * The exact `--config=` list a call runs with first — `invoke` and the cache
 * key (`rulePacks`) both read it from here, so an edited local pack can
 * never be served from a cache entry computed with its old content.
 */
function configuredPacksFor(
  input: BugHuntInput,
  plugin: PluginContext,
  projectPath: string,
): string[] {
  const includeLanguagePacks = input.include_language_packs === true;
  return buildPackList({
    includeLanguagePacks,
    languages: includeLanguagePacks ? detectLanguages(plugin, projectPath) : [],
    customConfigs: resolveCustomSemgrepConfigs(plugin, projectPath),
  });
}

/**
 * The LOCAL rule files a `bug_hunt` of `projectPath` loads — the shipped
 * bugfix packs plus the project's registered rules. Everything else it runs
 * is a registry pack. `create_fix_pr` needs this split to apply exactly one
 * rule's autofix: a local rule comes from a filtered copy of its file, a
 * registry rule from `r/<rule-id>`.
 */
export function bugHuntLocalConfigs(plugin: PluginContext, projectPath: string): string[] {
  return [...resolveBugfixRules(), ...resolveCustomSemgrepConfigs(plugin, projectPath)];
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
 * Wraps the semgrep parser to re-tag every finding as `category=bug` and
 * normalise the subcategory to the BUG_SUBCATEGORIES vocabulary where the
 * matching rule's own id says so (see `mapSubcategory`). Fingerprints are
 * recomputed because the original parser ran with
 * `category=security`/`quality`/etc — but tool, rule_id, file_path, line
 * range and snippet are unchanged, so the fingerprint identity stays stable
 * across `bug_hunt` invocations.
 *
 * It does NOT apply `categories`. It used to, and the findings it dropped
 * were therefore never stored: a baseline taken from a filtered run forgot
 * them, and the next unfiltered run reported them as `new` — the defect
 * `severity_min` had already been fixed for (see `scanToolFactory.ts`).
 * `categories` is now a response-only view, {@link categoriesView}.
 */
function bugCategoryParserFor(packs: readonly string[], ctx: Pick<InvokeContext, 'projectPath' | 'rulesProjectPath'>): ScannerParser {
  // A plugin pack's rule is stored under its own id, never under the path of
  // the plugin's install (runners/semgrepRuleIds.ts).
  const base = semgrepParserFor(packs, { projectPath: ctx.rulesProjectPath, cwd: ctx.projectPath });
  return {
    name: semgrepParser.name,
    parse(input, ctx): ParserOutput {
      const out = base.parse(input, ctx);
      return { findings: out.findings.map((f) => recategoriseAsBug(f)), cves: out.cves };
    },
  };
}

/**
 * `categories` as a view over the stored findings: the ones whose
 * subcategory is not listed are withheld from THIS response, counted by
 * subcategory, and named in a warning — never dropped from the scan. `null`
 * when no filter was asked for. Exported for tests.
 */
export function categoriesView(
  categories: readonly string[] | undefined,
  findings: readonly Finding[],
  scanId: string,
): ResponseView | null {
  if (categories === undefined || categories.length === 0) return null;
  const visible: Finding[] = [];
  const withheldBySubcategory: Record<string, number> = {};
  for (const f of findings) {
    if (f.subcategory !== undefined && categories.includes(f.subcategory)) {
      visible.push(f);
    } else {
      const key = f.subcategory ?? '(none)';
      withheldBySubcategory[key] = (withheldBySubcategory[key] ?? 0) + 1;
    }
  }
  const withheld = findings.length - visible.length;
  return {
    visible,
    disclosure: {
      category_filter: {
        categories: [...categories],
        withheld,
        withheld_by_subcategory: withheldBySubcategory,
      },
    },
    warning:
      withheld === 0
        ? null
        : `categories ${JSON.stringify(categories)} withheld ${withheld} finding(s) from this ` +
          `response only; they are recorded in scan ${scanId}, and baselines and diffs against ` +
          'it include them.',
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
      'Bug hunt (Semgrep r2c-bug-scan + security-audit + always-on local JS/TS, Python, Go, ' +
      'Java, C# and PHP bug rules, plus ONE Rust rule; optional language packs, off by ' +
      'default; other languages still registry-only)',
    // What the tool does, its inputs, what it returns and its limits — nothing
    // else. The measurement history behind every rule (corpora, counts, the
    // rules deleted and why, each accepted false positive and false negative)
    // lives in the packs' own comments (configs/semgrep/bugfix-*.yml) and in
    // CHANGELOG.md; the registry-pack composition lives in this file's header.
    // A description is loaded into every session, so it stays under 1500
    // characters (test/unit/pluginSurface/descriptionLimits.test.ts).
    description:
      'Hunt implementation bugs with Semgrep: the registry packs p/r2c-bug-scan + p/security-audit, plus ' +
      'local always-on packs (configs/semgrep/bugfix-*.yml) covering six classes — race_condition, ' +
      'null_safety, off_by_one, memory_leak, error_handling, edge_case — for JS/TS (13 rules), Python (10), ' +
      'Go (9), Java (7), C# (11) and PHP (6; no memory_leak rule). Rust has one rule (a blocking sleep ' +
      'inside an async fn; use cargo clippy for the rest); Ruby has none (use RuboCop). Rules registered ' +
      'with register_custom_rules also run. Findings are category bug, with a subcategory when the rule id ' +
      'names one; other findings keep their own tag. `categories` filters the RESPONSE only (every finding is ' +
      'recorded; category_filter counts the rest). `include_language_packs` (off by default) also runs ' +
      'p/typescript or p/javascript, p/python, p/java and p/golang — security bundles, not bug classes. ' +
      '`scope` limits the scan to paths, a git diff, or what changed since a ref or date. Limits: pattern ' +
      'rules match syntax, not dataflow, so a quiet result is not a bug-free project; most local rules are ' +
      'WARNING (medium) heuristics; none ships an autofix, so create_fix_pr cannot fix them — use ' +
      'suggest_fix. A retired registry pack or a broken local rule file degrades to the packs that still ' +
      'load and is reported in tools_run / missing_tools, never as a clean scan. Per-rule measurements and ' +
      "known false positives and negatives live in each pack's comments and in CHANGELOG.md.",
    scan_type: 'bugs',
    category: 'bug',
    // `scope`: the packs run over exactly the scoped files (`invokeBugHuntOnScope`).
    supportsScope: true,
    // `categories` filters the response (see `categoriesView`), so it stays
    // out of the cache key: every filter over the same tree is one scan.
    responseOnlyInputs: ['categories'],
    responseView: (input: BugHuntInput, findings, scanId) =>
      categoriesView(input.categories, findings, scanId),
    // `rulesProjectPath`: the scanned path itself, except when create_fix_pr
    // re-scans a worktree of a project and needs that project's rules.
    rulePacks: (input: BugHuntInput, { plugin, rulesProjectPath }) =>
      configuredPacksFor(input, plugin, rulesProjectPath),
    configWarnings: (_input: BugHuntInput, { plugin, rulesProjectPath }) => {
      const note = legacyRegistrationNote(legacyRegistrationsNotApplied(plugin, rulesProjectPath));
      return note === null ? [] : [note];
    },
    inputSchema: {
      project_path: ProjectPath,
      severity_min: SeverityMin,
      auto_fix: AutoFix,
      allow_dirty: AllowDirty,
      categories: z
        .array(z.string())
        .optional()
        .describe(
          'Show only these bug subcategories (e.g. race_condition, null_safety) in the response. ' +
            'Every finding is still recorded; `category_filter` counts what was withheld.',
        ),
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
      scope: ScanScopeInput,
    },
    // The pack choice is recorded on the scan row (meta, via extras) so
    // create_fix_pr can re-scan a fix with the SAME packs that found it.
    invoke: async (input: BugHuntInput, ctx): Promise<ScannerInvocation> =>
      reportUncoveredLanguages(ctx, recordPackChoice(input, await withSemgrepGaps(ctx, await invokeBugHunt(input, ctx)))),
  }),
);

/**
 * The shared Semgrep coverage gaps (`runners/semgrepCoverageGaps.ts`: files
 * over the size limit, initialised submodules) on the run's `semgrep` entry
 * — every path of {@link invokeBugHunt} and its scoped twin ends in one such
 * entry. Not for a Semgrep that never ran (not installed, an empty scope).
 */
async function withSemgrepGaps(ctx: InvokeContext, inv: ScannerInvocation): Promise<ScannerInvocation> {
  const i = inv.tools_run.findIndex((t) => t.name === 'semgrep');
  const entry = inv.tools_run[i];
  if (entry === undefined) return inv;
  if (entry.status === 'skipped' && (entry.reason === 'not_installed' || /scope holds no file/.test(entry.reason ?? ''))) return inv;
  const gaps = await semgrepCoverageGaps(ctx.projectPath, ctx.scope !== null ? { files: ctx.scope.files } : {});
  const applied = applySemgrepCoverageGaps(entry, gaps, { scannedNothing: entry.status === 'skipped' });
  const tools_run = [...inv.tools_run];
  tools_run[i] = applied.toolRun;
  const missing_tools = [...inv.missing_tools];
  if (applied.missing) markMissing(missing_tools, 'semgrep');
  return { ...inv, tools_run, missing_tools };
}

async function invokeBugHunt(input: BugHuntInput, ctx: InvokeContext): Promise<ScannerInvocation> {
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
  const configuredPacks: readonly string[] = configuredPacksFor(
    input,
    ctx.plugin,
    ctx.rulesProjectPath,
  );
  const categoryParser = bugCategoryParserFor(configuredPacks, ctx);

  if (ctx.scope !== null) {
    return invokeBugHuntOnScope({ input, ctx, reportDir, packs: configuredPacks, files: ctx.scope.files });
  }

  const outFile = join(reportDir, 'bugs.json');
  const runWithPacks = (packs: readonly string[]): Promise<ProcessRunResult> => {
    const args = packs.map((pack) => `--config=${pack}`);
    // `.guardianignore` — see `platform/guardianIgnore.ts`.
    args.push(...semgrepExcludeArgs(ctx.exclusions));
    args.push('--json', '--quiet', '--output', outFile);
    if (input.auto_fix === true) args.push('--autofix');
    args.push(ctx.projectPath);
    // UTF-8 mode (runners/semgrepRun.ts): without it a file named 日本.py
    // made Semgrep exit 2 without a report on Windows (review M3).
    return runSemgrep({
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
  const reportGap = (failures: readonly ConfigDownloadFailure[], retryReason?: string): ScannerInvocation => {
    tools_run.push({
      name: 'semgrep',
      status: 'failed',
      reason:
        `no configured pack could be scanned (${describeConfigFailures(failures)})` +
        (retryReason !== undefined ? `; the retry: ${retryReason}` : ''),
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
    // findConfigDownloadFailures found nothing whole-config-fatal. Judged by
    // the shared Semgrep judge ({@link judgeBugHuntRun}), never by the exit
    // code alone.
    if (raw) parser_inputs.push({ parser: categoryParser, input: raw });
    const judged = judgeBugHuntRun(raw, result, ctx, configuredPacks);
    tools_run.push(judged.toolRun);
    if (judged.missing) missing_tools.push('semgrep');
    return {
      outcome: judged.toolRun.status === 'failed' && !wasAnythingScanned(raw) ? result.outcome : 'completed',
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
  if (retryFailures.length > 0) {
    // The retry ran to a real exit but didn't help either (network
    // flake, or the "survivor" just got retired too) — combine every
    // failure we saw and refuse to trust either attempt's output.
    return reportGap([...failures, ...retryFailures]);
  }
  // Judged like the first run (fix round 2: it read the exit code alone) —
  // and a gap whatever the verdict, since the dead packs did not run.
  const judged = judgeBugHuntRun(retryRaw, retry, ctx, survivors);
  if (judged.toolRun.status !== 'ok') return reportGap(failures, judged.toolRun.reason);

  if (retryRaw) parser_inputs.push({ parser: categoryParser, input: retryRaw });
  tools_run.push({
    ...judged.toolRun,
    reason: [`ran with ${survivors.join(', ')} only — ${describeConfigFailures(failures)}`, judged.toolRun.reason]
      .filter((x) => x !== undefined)
      .join('; '),
  });
  missing_tools.push('semgrep');
  return {
    outcome: 'completed',
    tools_run,
    missing_tools,
    parser_inputs,
    report_paths: [reportDir],
  };
}

/**
 * One whole-project bug_hunt run's `semgrep` entry, judged by the shared
 * Semgrep judge (`runners/semgrepReport.ts`), as scan_sast and this tool's
 * own scoped run are — never by the exit code alone, which read a partly
 * parsed file and a run that scanned nothing as ok, coverage full (fix
 * round 1). `missing`: list `semgrep` in `missing_tools` too.
 *
 *   - partial (files only partly parsed) → ok + missing, `partially_parsed`;
 *   - rules that did not load while the others ran (a typo'd pattern in
 *     bugfix-js.yml or a registered rule: exit 2, `paths.scanned` filled —
 *     the judge's `rules_not_loaded`, semgrepConfigFailure.ts) → ok +
 *     missing, the rules in `failed_rules` under their stored ids, and a
 *     reason naming each one. Fix round 1 made this `failed`: coverage
 *     `none`, "NO scanner ran … Install semgrep" for a Semgrep that was
 *     installed and scanned, and the open set skipping the row — so one
 *     persistent broken custom rule froze the bugs slot at the last good
 *     scan. That undid bugfix-rules-jsts task 3 ("one bad rule costs that
 *     rule"). The broken rule's earlier findings stay open as not
 *     re-measured (`history/runCompare.ts`, `failed_rules`);
 *   - scanned nothing → skipped + missing;
 *   - anything else → failed, the errors as its reason.
 */
function judgeBugHuntRun(
  raw: string | null,
  run: ProcessRunResult,
  ctx: Pick<InvokeContext, 'projectPath' | 'rulesProjectPath'>,
  packs: readonly string[],
): { toolRun: ToolRun; missing: boolean } {
  // What the engine cannot report (taint fixpoint timeouts), on a run that scanned.
  const judged = judgeBugHuntReport(raw, run, ctx, packs);
  return { ...judged, toolRun: withSemgrepEngineNote(judged.toolRun, raw) };
}

function judgeBugHuntReport(
  raw: string | null,
  run: ProcessRunResult,
  ctx: Pick<InvokeContext, 'projectPath' | 'rulesProjectPath'>,
  packs: readonly string[],
): { toolRun: ToolRun; missing: boolean } {
  const check = checkSemgrepReport({
    raw,
    exitCode: run.exitCode,
    outcome: run.outcome,
    targets: 1,
    projectPath: ctx.projectPath,
    ruleIdOf: localRuleIdNormalizer(packs, { projectPath: ctx.rulesProjectPath, cwd: ctx.projectPath }),
  });
  if (check.verdict === 'ok') return { toolRun: { name: 'semgrep', status: 'ok' }, missing: false };
  if (check.verdict === 'partial' && check.partial !== undefined) {
    return {
      toolRun: {
        name: 'semgrep',
        status: 'ok',
        reason: describePartialParse(check.partial, 'bugs in the unparsed spans may be missing'),
        partially_parsed: check.partial,
      },
      missing: true,
    };
  }
  if (check.verdict === 'scanned_nothing') {
    return {
      toolRun: {
        name: 'semgrep',
        status: 'skipped',
        reason: 'semgrep scanned 0 files — nothing here is a language its packs cover, or the packs loaded nothing',
      },
      missing: true,
    };
  }
  const notLoaded = check.rules_not_loaded;
  const rules = { projectPath: ctx.rulesProjectPath, cwd: ctx.projectPath };
  if (notLoaded !== undefined && notLoaded.length > 0 && noRuleLoaded(packs, notLoaded, rules)) {
    // Every local rule failed and no registry pack ran (M-1): nothing was scanned for.
    return {
      toolRun: { name: 'semgrep', status: 'failed', reason: describeNoRuleLoaded(notLoaded), failed_rules: notLoaded, rule_config_error: true },
      missing: false,
    };
  }
  if (notLoaded !== undefined && notLoaded.length > 0) {
    const toolRun: ToolRun = {
      name: 'semgrep',
      status: 'ok',
      reason: [
        describeRulesNotLoaded(notLoaded, check.scanned),
        ...(check.partial !== undefined ? [describePartialParse(check.partial, 'bugs in the unparsed spans may be missing')] : []),
      ].join('; '),
      failed_rules: notLoaded,
    };
    if (check.partial !== undefined) toolRun.partially_parsed = check.partial;
    return { toolRun, missing: true };
  }
  const reason = describeRawErrors(raw) ?? check.reason ?? 'semgrep failed';
  if (check.rule_config_error !== undefined) {
    return {
      toolRun: {
        name: 'semgrep',
        status: 'failed',
        reason: `the rule configuration did not load — ${check.rule_config_error} (semgrep exit ${String(run.exitCode)})`,
        rule_config_error: true,
      },
      missing: false,
    };
  }
  return { toolRun: { name: 'semgrep', status: 'failed', reason }, missing: false };
}

/**
 * `bug_hunt` over a scope's files: the same packs, as explicit targets
 * (`semgrepOnFiles` — batched, every batch judged by its report), and the
 * same retry when a registry pack fails to load: a dead `--config=` aborts
 * every batch it is passed to, so the survivors are re-run over the whole
 * file list and the gap is named.
 */
async function invokeBugHuntOnScope(args: {
  input: BugHuntInput;
  ctx: InvokeContext;
  reportDir: string;
  packs: readonly string[];
  files: readonly string[];
}): Promise<ScannerInvocation> {
  const { input, ctx, reportDir, packs, files } = args;
  const tools_run: ToolRun[] = [];
  const missing_tools: string[] = [];
  const parser_inputs: ScannerInvocation['parser_inputs'] = [];
  const finish = (outcome: ScannerInvocation['outcome']): ScannerInvocation => ({
    outcome,
    tools_run,
    missing_tools,
    parser_inputs,
    report_paths: [reportDir],
  });
  if (files.length === 0) {
    tools_run.push({ name: 'semgrep', status: 'skipped', reason: 'the scope holds no file — nothing to scan' });
    return finish('completed');
  }
  const runOn = (use: readonly string[]) =>
    semgrepOnFiles({
      rules: { configs: use, ctx: { projectPath: ctx.rulesProjectPath, cwd: ctx.projectPath } },
      configArgs: [...use.map((pack) => `--config=${pack}`), ...(input.auto_fix === true ? ['--autofix'] : [])],
      files,
      cwd: ctx.projectPath,
      reportDir,
      env: ctx.scriptEnv,
      signal: ctx.signal,
      ...(ctx.onLog ? { onLog: ctx.onLog } : {}),
    });
  // Every batch reports the same dead `--config=`: once each.
  const failuresOf = (reports: readonly string[]): ConfigDownloadFailure[] => {
    const seen = new Map<string, ConfigDownloadFailure>();
    for (const f of reports.flatMap((raw) => findConfigDownloadFailures(raw))) seen.set(`${f.pack ?? ''}\0${f.message}`, f);
    return [...seen.values()];
  };
  const reportGap = (failures: readonly ConfigDownloadFailure[]): ScannerInvocation => {
    tools_run.push({
      name: 'semgrep',
      status: 'failed',
      reason: `no configured pack could be scanned (${describeConfigFailures(failures)})`,
    });
    missing_tools.push('semgrep');
    return finish('completed');
  };

  const first = await runOn(packs);
  const failures = failuresOf(first.reports);
  if (failures.length === 0) {
    for (const raw of first.reports) parser_inputs.push({ parser: bugCategoryParserFor(packs, ctx), input: raw });
    tools_run.push(withSemgrepEngineNote(first.toolRun, first.reports[0] ?? null));
    // Scanned nothing, or some files only partly parsed or rules not loaded (`ok` + missing).
    const narrower = first.partial.length > 0 || first.failedRules.length > 0;
    if (first.nothingScanned || (first.toolRun.status === 'ok' && narrower)) missing_tools.push('semgrep');
    return finish(first.cancelled ? 'cancelled' : 'completed');
  }
  const survivors = survivingPacks(packs, failures);
  if (survivors.length === 0 || survivors.length === packs.length) return reportGap(failures);

  const retry = await runOn(survivors);
  if (retry.cancelled) {
    tools_run.push({
      name: 'semgrep',
      status: 'failed',
      reason: `retry with ${survivors.join(', ')} did not finish (cancelled) — original gap: ${describeConfigFailures(failures)}`,
    });
    missing_tools.push('semgrep');
    return finish('cancelled');
  }
  const retryFailures = failuresOf(retry.reports);
  if (retryFailures.length > 0) return reportGap([...failures, ...retryFailures]);
  for (const raw of retry.reports) parser_inputs.push({ parser: bugCategoryParserFor(packs, ctx), input: raw });
  const retried = withSemgrepEngineNote(retry.toolRun, retry.reports[0] ?? null);
  tools_run.push({
    ...retried,
    reason: [`ran with ${survivors.join(', ')} only — ${describeConfigFailures(failures)}`, retried.reason]
      .filter((s) => s !== undefined)
      .join('; '),
  });
  missing_tools.push('semgrep');
  return finish('completed');
}

/**
 * Names the project's languages no bug_hunt pack covers (`languages_not_covered`,
 * plus a warning the row keeps for cache hits), so a Kotlin project's run
 * never reads as a bug hunt of its Kotlin code. Not a coverage gap: no
 * scanner is missing or failed — the rules do not exist.
 */
function reportUncoveredLanguages(ctx: InvokeContext, invocation: ScannerInvocation): ScannerInvocation {
  const uncovered = languagesNotCovered(detectLanguages(ctx.plugin, ctx.rulesProjectPath));
  if (uncovered.length === 0) return invocation;
  return {
    ...invocation,
    warnings: [
      ...(invocation.warnings ?? []),
      `No bug_hunt pack covers ${uncovered.join(', ')} (no local bugfix rules, no language pack): ` +
        'that code was not bug-hunted beyond whatever registry rules happen to target it, so a quiet ' +
        'result says nothing about it.',
    ],
    extras: { ...(invocation.extras ?? {}), languages_not_covered: uncovered },
  };
}

function recordPackChoice(input: BugHuntInput, invocation: ScannerInvocation): ScannerInvocation {
  return {
    ...invocation,
    extras: { ...(invocation.extras ?? {}), include_language_packs: input.include_language_packs === true },
  };
}
