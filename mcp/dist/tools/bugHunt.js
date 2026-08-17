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
 * `configuredPacks` grows by whatever `detectLanguagePacks` finds — one
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
import { semgrepParser } from '../runners/scannerParsers/semgrep.js';
import { runProcess } from '../runners/processRunner.js';
import { AllowDirty, AutoFix, Force, ProjectPath, SeverityMin, } from '../schemas.js';
import { computeFingerprint } from '../fingerprint/findingFingerprint.js';
import { registerToolModule } from './index.js';
import { ensureReportDir, readJsonSafe, scannerAvailable, } from './scanHelpers.js';
import { describeConfigFailures, findConfigDownloadFailures, survivingPacks, } from './semgrepConfigFailure.js';
import { makeScanTool, } from './scanToolFactory.js';
/**
 * Packs `bug_hunt` always runs, regardless of detected stack.
 * Exported so tests can assert against the real, current list instead of
 * duplicating the literal pack names.
 */
export const BUG_HUNT_BASE_PACKS = ['p/r2c-bug-scan', 'p/security-audit'];
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
const LANGUAGE_PACKS = new Map([
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
export function languagePacksFor(languages) {
    const packs = [];
    for (const [language, pack] of LANGUAGE_PACKS) {
        if (language === 'javascript' && languages.includes('typescript'))
            continue; // p/typescript covers it — see doc comment
        if (languages.includes(language))
            packs.push(pack);
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
function fallbackLanguages(projectPath) {
    const has = (name) => existsSync(join(projectPath, name));
    const languages = [];
    if (has('package.json')) {
        languages.push('javascript');
        if (has('tsconfig.json'))
            languages.push('typescript');
    }
    if (has('pyproject.toml') || has('requirements.txt') || has('setup.py')) {
        languages.push('python');
    }
    if (has('pom.xml') || has('build.gradle') || has('build.gradle.kts'))
        languages.push('java');
    if (has('go.mod'))
        languages.push('go');
    return languages;
}
/**
 * Which language packs to add, preferring the persisted `detect_stack`
 * snapshot (same two-tier lookup as `observabilitySetup.ts`'s `inferStack`:
 * prefer the snapshot, fall back to filesystem markers) so `bug_hunt` still
 * gets stack-aware coverage the very first time it runs against a project.
 */
function detectLanguagePacks(ctx) {
    const snapshotLanguages = ctx.plugin.storage.stack.getLatest()?.snapshot.languages;
    const languages = snapshotLanguages ?? fallbackLanguages(ctx.projectPath);
    return languagePacksFor(languages);
}
/** The six canonical bug subcategories `mapSubcategory` classifies into.
 *  Exported so tests can assert against the real vocabulary instead of
 *  duplicating the literal names. */
export const BUG_SUBCATEGORIES = new Set([
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
function makeBugCategoryParser(categories) {
    return {
        name: semgrepParser.name,
        parse(input, ctx) {
            const out = semgrepParser.parse(input, ctx);
            const recategorised = out.findings.map((f) => recategoriseAsBug(f));
            const findings = categories !== undefined && categories.length > 0
                ? recategorised.filter((f) => f.subcategory !== undefined && categories.includes(f.subcategory))
                : recategorised;
            return { findings, cves: out.cves };
        },
    };
}
function recategoriseAsBug(f) {
    const category = 'bug';
    const subcategory = mapSubcategory(f.rule_id ?? '', f.subcategory);
    const refingerprintInput = { tool: f.tool };
    if (f.rule_id !== undefined)
        refingerprintInput.rule_id = f.rule_id;
    if (f.file_path !== undefined)
        refingerprintInput.file_path = f.file_path;
    if (f.line_start !== undefined)
        refingerprintInput.line_start = f.line_start;
    if (f.line_end !== undefined)
        refingerprintInput.line_end = f.line_end;
    if (f.snippet !== undefined)
        refingerprintInput.snippet = f.snippet;
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
export function mapSubcategory(ruleId, existing) {
    const lowered = ruleId.toLowerCase();
    if (/(race.condition|concurren|thread.safety|deadlock|\bmutex\b|synchroniz)/.test(lowered)) {
        return 'race_condition';
    }
    if (/(null.?safety|null.?check|null.?deref|null.?pointer|nullptr|nullable|none.check|nil.?deref|\bnpe\b|undefined.?behav|undefined.?check)/.test(lowered)) {
        return 'null_safety';
    }
    if (/(off.by.one|boundary|index.out|out.of.bound|out.of.range|overflow|underflow)/.test(lowered)) {
        return 'off_by_one';
    }
    if (/(memory.?leak|resource.?leak|unreleased|unclosed|disposed|use.after.free|dangling|before.close)/.test(lowered)) {
        return 'memory_leak';
    }
    if (/(error.handling|swallow|catch.all|exception|unchecked|uncaught|unhandled|ignored.return)/.test(lowered)) {
        return 'error_handling';
    }
    if (/(edge.case|empty.input|modify.*iterat|iterat.*modify|mutable.*default|default.*mutable)/.test(lowered)) {
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
registerToolModule(makeScanTool({
    name: 'bug_hunt',
    title: 'Bug hunt (Semgrep r2c-bug-scan + security-audit; optional language packs, off by ' +
        'default; bug classes Python-strong, JS/TS-thin)',
    description: 'Semgrep with p/r2c-bug-scan + p/security-audit always on. Optional ' +
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
        'for JS/TS, is net-new security scanning, not duplicate coverage. Only p/r2c-bug-scan ' +
        '(44 rules: 32 Python, 5 Go, 4 Java, 3 JS/TS) covers the six bug classes today, and ' +
        'thinly outside Python — on a JS/TS project, a quiet or security-only result (with or ' +
        'without the language packs) is not evidence of a bug-free project; pair with ' +
        '`scan_sast` or the guardian-bugfix skill\'s manual review for JS/TS logic bugs. ' +
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
            .describe('Off by default. When true, also run one per-language Semgrep pack for each ' +
            'language family detect_stack finds in the project (or a filesystem fallback): ' +
            'p/javascript OR p/typescript for a JS/TS project (never both — identical 74-rule ' +
            'packs under two registry names), plus p/python, p/java, p/golang. These are ' +
            'per-language SECURITY bundles (XSS, injection, crypto, auth, SSRF, hard-coded ' +
            'secrets, ...), not bug-class rules — they add no race-condition/null-safety/off-by-one/' +
            'memory-leak/error-handling coverage. Independent of `categories`: this decides ' +
            'which scanners run (input); `categories` decides which findings come back ' +
            '(output). Turn on when you specifically want broader per-language security ' +
            'scanning alongside the bug hunt.'),
        force: Force,
    },
    invoke: async (input, ctx) => {
        const reportDir = ensureReportDir(ctx.projectPath, ctx.scanId, 'bugs');
        const tools_run = [];
        const missing_tools = [];
        const parser_inputs = [];
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
        // Off by default (§ BugHuntInput above: this is deliberately not part
        // of `categories`, which filters output, not input). Detection only
        // runs when asked — a project with a persisted JS/TS stack snapshot
        // does NOT get p/javascript/p/typescript added unless the caller
        // opts in.
        const configuredPacks = [
            ...BUG_HUNT_BASE_PACKS,
            ...(input.include_language_packs === true ? detectLanguagePacks(ctx) : []),
        ];
        const categoryParser = makeBugCategoryParser(input.categories);
        const outFile = join(reportDir, 'bugs.json');
        const runWithPacks = (packs) => {
            const args = packs.map((pack) => `--config=${pack}`);
            args.push('--json', '--quiet', '--output', outFile);
            if (input.auto_fix === true)
                args.push('--autofix');
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
        const reportGap = (failures) => {
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
            // The ordinary case: every configured pack resolved. Exit code /
            // outcome alone decide ok-ness here, same as before — there is
            // nothing in errors[] casting doubt on the result.
            if (raw)
                parser_inputs.push({ parser: categoryParser, input: raw });
            const ok = result.outcome === 'completed' || result.exitCode === 1;
            tools_run.push({ name: 'semgrep', status: ok ? 'ok' : 'failed' });
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
                reason: `retry with ${survivors.join(', ')} did not finish (${retry.outcome}) — ` +
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
        const retryOk = retryFailures.length === 0 && (retry.outcome === 'completed' || retry.exitCode === 1);
        if (!retryOk) {
            // The retry ran to a real exit but didn't help either (network
            // flake, or the "survivor" just got retired too) — combine every
            // failure we saw and refuse to trust either attempt's output.
            return reportGap([...failures, ...retryFailures]);
        }
        if (retryRaw)
            parser_inputs.push({ parser: categoryParser, input: retryRaw });
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
}));
//# sourceMappingURL=bugHunt.js.map