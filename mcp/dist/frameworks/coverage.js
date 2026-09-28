/**
 * Which OWASP Top 10:2025 categories the scans behind a report actually
 * TESTED — the one rule every renderer of the taxonomy shares.
 *
 * ---- The rule -----------------------------------------------------------
 *
 * A scanner's rules see the languages they were written for and nothing
 * else: the registry's Rust rules hold one injection rule, so a Rust
 * project scanned clean for injection was barely looked at. Coverage is
 * therefore judged per (category, source language of the project):
 *
 *   - `tested` — for EVERY source language of the project, a rule-based
 *     detector that ran fully ok reaches the category with at least
 *     {@link MIN_RULES} rules in that language covering at least
 *     {@link MIN_WEAKNESSES} distinct CWEs — three rules of one CWE are one
 *     check repeated (the registry's three Rust A07 rules are all CWE-295);
 *   - `partial` — some language has only 1–2 rules or one weakness
 *     ("thin"), some language has none (the covered and uncovered languages
 *     are named), the only run that reached it was incomplete, the only
 *     detector that reached it is NARROW, or the project's language list
 *     may be incomplete (a truncated or unreadable listing: a language it
 *     missed could have no rules at all);
 *   - `not_tested` — no detector that ran reaches the category in any of
 *     the project's languages. Zero findings there are not a clean result.
 *
 * A narrow detector sees one slice of a category, whatever the language:
 * gitleaks finds hard-coded credentials, one weakness of A07; Trivy and the
 * dependency auditors find known-vulnerable components, not the build and
 * distribution integrity the rest of A03 is about. It never makes a
 * category `tested` on its own — at most `partial`, with its scope named. A
 * rule-based detector meeting the bar above still can.
 *
 * The project's languages come from `frameworks/projectLanguages.ts`. With
 * none detected, only language-agnostic detectors can test anything; with
 * languages that could not be determined, a language-specific claim is at
 * most `partial`.
 *
 * A run is INCOMPLETE — it counts only toward `partial` — when the scan was
 * scoped to part of the project (a `scope` run, a diff review), when any
 * pass of the same detector in the same scan failed or is listed missing
 * (`gitleaks` beside a failed `gitleaks-working-tree`, `npm` beside a failed
 * `pip-audit`, `trivy` with a `trivy:npm` gap), or when the run only partly
 * parsed files or lost rules. A pass skipped as not applicable (skipped and
 * not listed missing) is no gap.
 *
 * ---- "Able to detect it" is per tools_run name AND scan type ------------
 *
 * `semgrep` in a `scan_sast` row ran the registry (unless `local_only`); in
 * a `bug_hunt` row it ran the bugfix packs; `trivy` in `scan_deps` is the
 * vulnerability pass, in `compliance_check` a license-only pass. Each
 * detector below names the scan types it holds for, records its rule
 * counts per (category, language) with the date they were measured, and
 * states the basis. Our own packs' counts are recounted from the YAML by
 * `test/unit/frameworks/packTaxonomy.test.ts`; the registry's and Bandit's
 * cannot be (they live outside the repo) and carry their measurement.
 *
 * Findings are counted separately and never decide coverage. A finding with
 * no `owasp` field is counted as unmapped — unknown, never under a category.
 *
 * Pure: bookkeeping, findings and languages in, a table out.
 */
import { canonicalLanguage } from './languages.js';
import { OWASP_TOP10_2025 } from './owaspTop10_2025.js';
import { classifyTaxonomy } from './taxonomy.js';
/** The fewest rules in a language for a detector to TEST a category there. Fewer is "thin". */
export const MIN_RULES = 3;
/** The fewest distinct CWEs those rules must cover. One is a single check, repeated. */
export const MIN_WEAKNESSES = 2;
/** `cell(10, 7)`, or `cell(3, 'CWE-295')` for rules that all name one CWE. */
function cell(rules, weaknesses) {
    return typeof weaknesses === 'string' ? { rules, weaknesses: 1, sole: weaknesses } : { rules, weaknesses };
}
/**
 * The registry ran: an explicit `local_only: false` on a scan_sast or
 * review_pr row (both record it); always on a script-era security_full row
 * (its script ran `--config=auto`); never on an orchestrated security_full
 * parent, whose merged bookkeeping does not say — its children do.
 */
function registryRan(run) {
    if (run.scan_type === 'security_full')
        return !Array.isArray(run.meta?.['child_scans']);
    return run.meta?.['local_only'] === false;
}
const rules = (perLanguage) => ({ kind: 'rules', perLanguage });
/**
 * Semgrep registry, p/default (1074 rules), fetched 2026-09-28: per
 * (category, language), the rules and the distinct CWEs they name — each
 * rule counted in every source language it lists, under every category
 * `classifyTaxonomy` gives its metadata (what its findings would carry).
 * `--config=auto` picks registry rulesets by language; p/default is the
 * measured stand-in.
 */
const REGISTRY_RULES = {
    'A01:2025': rules({
        csharp: cell(7, 4), go: cell(10, 8), java: cell(10, 7), javascript: cell(32, 8), php: cell(8, 6), python: cell(20, 8),
        ruby: cell(14, 7), scala: cell(5, 2), typescript: cell(32, 8),
    }),
    'A02:2025': rules({
        csharp: cell(3, 'CWE-611'), go: cell(6, 4), java: cell(11, 3), javascript: cell(10, 5), kotlin: cell(2, 2), python: cell(12, 6),
        scala: cell(3, 'CWE-611'), typescript: cell(10, 5),
    }),
    'A03:2025': rules({ javascript: cell(1, 'CWE-1104'), typescript: cell(1, 'CWE-1104') }),
    'A04:2025': rules({
        csharp: cell(2, 2), go: cell(24, 6), java: cell(43, 7), javascript: cell(19, 8), kotlin: cell(11, 5), php: cell(6, 5),
        python: cell(53, 7), ruby: cell(11, 4), scala: cell(3, 3), typescript: cell(15, 8),
    }),
    'A05:2025': rules({
        c: cell(1, 'CWE-94'), csharp: cell(4, 3), go: cell(28, 6), java: cell(38, 11), javascript: cell(60, 8), kotlin: cell(2, 2),
        lua: cell(1, 'CWE-94'), php: cell(17, 6), python: cell(92, 12), ruby: cell(30, 4), rust: cell(1, 'CWE-94'), scala: cell(9, 4),
        typescript: cell(61, 8),
    }),
    'A06:2025': rules({
        c: cell(3, 'CWE-676'), csharp: cell(2, 2), go: cell(2, 'CWE-362'), java: cell(4, 4), javascript: cell(12, 3), php: cell(1, 'CWE-676'),
        python: cell(5, 3), ruby: cell(5, 3), scala: cell(2, 'CWE-522'), swift: cell(1, 'CWE-311'), typescript: cell(16, 5),
    }),
    'A07:2025': rules({
        csharp: cell(2, 2), go: cell(3, 2), java: cell(5, 4), javascript: cell(9, 5), kotlin: cell(2, 2), php: cell(3, 2), python: cell(10, 4),
        ruby: cell(3, 2), rust: cell(3, 'CWE-295'), typescript: cell(10, 6),
    }),
    'A08:2025': rules({
        csharp: cell(11, 2), go: cell(2, 2), java: cell(7, 2), javascript: cell(9, 5), php: cell(2, 'CWE-502'), python: cell(17, 2),
        ruby: cell(9, 4), typescript: cell(9, 5),
    }),
    'A09:2025': rules({ python: cell(1, 'CWE-532') }),
    'A10:2025': rules({ csharp: cell(1, 'CWE-209'), go: cell(1, 'CWE-476'), php: cell(1, 'CWE-252'), ruby: cell(1, 'CWE-369') }),
};
/**
 * Bandit 1.9.4 (`bandit/core/issue.py` and every `Cwe.*` assignment in its
 * plugins and blacklists — 85), measured 2026-09-28. Python only.
 */
const BANDIT_RULES = {
    'A01:2025': rules({ python: cell(8, 4) }),
    'A04:2025': rules({ python: cell(22, 4) }),
    'A05:2025': rules({ python: cell(38, 6) }),
    'A07:2025': rules({ python: cell(4, 2) }),
    'A08:2025': rules({ python: cell(5, 2) }),
    // Three checks, all CWE-703 — a class MITRE discourages for mapping.
    'A10:2025': rules({ python: cell(3, 'CWE-703') }),
};
/** configs/semgrep/bugfix-*.yml, recounted by packTaxonomy.test.ts. */
const BUGFIX_RULES = {
    'A06:2025': rules({ javascript: cell(1, 'CWE-362'), typescript: cell(1, 'CWE-362') }),
    'A10:2025': rules({
        csharp: cell(3, 3), go: cell(5, 4), java: cell(3, 2), javascript: cell(6, 3), php: cell(2, 2), python: cell(5, 4),
        typescript: cell(6, 3),
    }),
};
/**
 * configs/semgrep/rgpd.yml, recounted by packTaxonomy.test.ts. Its four
 * tracker/embed rules are `generic` rules over templates and count for no
 * source language, so the pack reaches A09 only — and only for personal
 * data written to logs.
 */
const RGPD_RULES = {
    'A09:2025': rules({
        csharp: cell(1, 'CWE-532'), javascript: cell(1, 'CWE-532'), php: cell(1, 'CWE-532'), python: cell(1, 'CWE-532'),
        typescript: cell(1, 'CWE-532'),
    }),
};
const DEPENDENCY_AUDITORS = ['npm', 'pip-audit', 'dotnet'];
/** The narrow scopes (see the module comment): named in every table that shows them. */
const CREDENTIALS_ONLY = 'hard-coded credentials only';
const DEPENDENCIES_ONLY = 'known-vulnerable dependencies only; build and distribution integrity not assessed';
export const OWASP_DETECTORS = [
    {
        id: 'semgrep-registry',
        label: 'Semgrep registry rules (scan_sast without local_only)',
        runs: ['semgrep'],
        scanTypes: ['sast', 'security_full', 'review_pr'],
        applies: registryRan,
        reach: REGISTRY_RULES,
        basis: 'Registry ruleset p/default, 1074 rules; each rule counted per source language it lists, under the ' +
            'categories its cwe/owasp metadata gives (classifyTaxonomy).',
        measured: 'p/default fetched 2026-09-28',
    },
    {
        id: 'bandit',
        label: 'Bandit (scan_sast, Python)',
        runs: ['bandit'],
        scanTypes: ['sast', 'security_full', 'review_pr'],
        reach: BANDIT_RULES,
        basis: "Bandit's own CWE assignments across its plugins and blacklists, mapped with OWASP's CWE list.",
        measured: 'Bandit 1.9.4, 2026-09-28',
    },
    {
        id: 'bugfix-packs',
        label: 'bug_hunt packs (configs/semgrep/bugfix-*.yml)',
        runs: ['semgrep'],
        scanTypes: ['bugs'],
        reach: BUGFIX_RULES,
        scope: 'swallowed errors, unchecked results and null dereferences',
        basis: "The packs' own metadata.cwe/owasp, per rule language.",
        measured: 'configs/semgrep/bugfix-*.yml, 2026-09-28 (recounted by packTaxonomy.test.ts)',
    },
    {
        id: 'rgpd-pack',
        label: 'RGPD pack (compliance_check, configs/semgrep/rgpd.yml)',
        runs: ['semgrep-rgpd'],
        scanTypes: ['compliance'],
        reach: RGPD_RULES,
        scope: 'personal data written to logs only',
        basis: "The pack's own metadata: one CWE-532 rule per language (JS/TS, PHP, Python, C#). The tracker and embed " +
            'rules are generic template rules and count for no source language.',
        measured: 'configs/semgrep/rgpd.yml, 2026-09-28 (recounted by packTaxonomy.test.ts)',
    },
    {
        id: 'trivy-vulnerabilities',
        label: 'Trivy vulnerability pass (scan_deps, deps_audit)',
        runs: ['trivy'],
        scanTypes: ['deps', 'deps_audit', 'security_full'],
        reach: { 'A03:2025': { kind: 'any-language' } },
        narrow: DEPENDENCIES_ONLY,
        basis: 'Language-agnostic for A03: it reads every lock file it supports; a root manifest it produced no result for ' +
            "is recorded as a `trivy:<ecosystem>` gap, which makes the run incomplete. compliance_check's Trivy pass is " +
            'license-only and is not counted.',
        measured: 'Trivy behaviour as recorded by scan_deps/deps_audit, 2026-09-28',
    },
    {
        id: 'trivy-image',
        label: 'Trivy image pass (scan_containers with an image)',
        runs: ['trivy-image'],
        scanTypes: ['containers'],
        reach: { 'A03:2025': { kind: 'any-language' } },
        narrow: DEPENDENCIES_ONLY,
        basis: 'The same vulnerability pass over an image, language-agnostic for A03.',
        measured: '2026-09-28',
    },
    {
        id: 'npm-audit',
        label: 'npm audit (deps_audit)',
        runs: ['npm'],
        family: DEPENDENCY_AUDITORS,
        scanTypes: ['deps_audit', 'deps'],
        reach: { 'A03:2025': { kind: 'languages', languages: ['javascript', 'typescript'] } },
        narrow: DEPENDENCIES_ONLY,
        basis: "The npm advisory database, complete for the project's npm dependencies — JavaScript and TypeScript only.",
        measured: '2026-09-28',
    },
    {
        id: 'pip-audit',
        label: 'pip-audit (deps_audit)',
        runs: ['pip-audit'],
        family: DEPENDENCY_AUDITORS,
        scanTypes: ['deps_audit', 'deps'],
        reach: { 'A03:2025': { kind: 'languages', languages: ['python'] } },
        narrow: DEPENDENCIES_ONLY,
        basis: 'The PyPI advisory database (OSV), for Python requirements only.',
        measured: '2026-09-28',
    },
    {
        id: 'dotnet-list-package',
        label: 'dotnet list package --vulnerable (deps_audit)',
        runs: ['dotnet'],
        family: DEPENDENCY_AUDITORS,
        scanTypes: ['deps_audit', 'deps'],
        reach: { 'A03:2025': { kind: 'languages', languages: ['csharp'] } },
        narrow: DEPENDENCIES_ONLY,
        basis: 'The NuGet advisory data, for .NET projects only.',
        measured: '2026-09-28',
    },
    {
        id: 'gitleaks',
        label: 'gitleaks (scan_secrets)',
        runs: ['gitleaks', 'gitleaks-working-tree'],
        scanTypes: ['secrets', 'security_full', 'wordpress', 'review_pr'],
        reach: { 'A07:2025': { kind: 'any-language' } },
        narrow: CREDENTIALS_ONLY,
        basis: 'Language-agnostic for A07: its secret patterns match any file. Every finding is a hard-coded credential, ' +
            'one weakness of A07 among many.',
        measured: '2026-09-28',
    },
];
/** Every scan type an OWASP detector reads — the rows that record their languages at scan time. */
export const OWASP_SCAN_TYPES = new Set(OWASP_DETECTORS.flatMap((d) => d.scanTypes));
/**
 * Rules and distinct CWEs per (category, source language) of a rule list —
 * how the pack detectors above are counted, and how their test recounts
 * them. A rule counts in every source language it lists (`generic` counts
 * in none), under every category `classifyTaxonomy` gives its metadata; its
 * CWEs all count toward the cell's distinct weaknesses.
 */
export function countRuleReach(ruleList) {
    const acc = {};
    for (const rule of ruleList) {
        const langs = new Set((Array.isArray(rule.languages) ? rule.languages : [])
            .map((l) => (typeof l === 'string' ? canonicalLanguage(l) : null))
            .filter((l) => l !== null));
        const tax = classifyTaxonomy({ cwe: rule.metadata?.['cwe'], owasp: rule.metadata?.['owasp'] });
        for (const cat of tax.owasp ?? []) {
            for (const lang of langs) {
                const row = (acc[cat] ??= {});
                const c = (row[lang] ??= { rules: 0, cwes: new Set() });
                c.rules += 1;
                for (const cwe of tax.cwe ?? [])
                    c.cwes.add(cwe);
            }
        }
    }
    const out = {};
    for (const [cat, row] of Object.entries(acc)) {
        out[cat] = Object.fromEntries(Object.entries(row)
            .sort((a, b) => a[0].localeCompare(b[0]))
            .map(([lang, c]) => {
            const only = c.cwes.size === 1 ? [...c.cwes][0] : undefined;
            return [lang, only !== undefined ? cell(c.rules, only) : cell(c.rules, c.cwes.size)];
        }));
    }
    return out;
}
const COMPLETE_CELL = { rules: Number.POSITIVE_INFINITY, weaknesses: Number.POSITIVE_INFINITY };
/** What `reach` has in `lang`: a complete cell when it is complete there, null when it has nothing. */
function cellIn(reach, lang) {
    switch (reach.kind) {
        case 'any-language':
            return COMPLETE_CELL;
        case 'languages':
            return reach.languages.includes(lang) ? COMPLETE_CELL : null;
        case 'rules':
            return reach.perLanguage[lang] ?? null;
    }
}
/** A cell that could make a category tested — before the detector's narrowness and the run's completeness. */
function meetsBar(c) {
    return c.rules >= MIN_RULES && c.weaknesses >= MIN_WEAKNESSES;
}
/** Why a reached cell falls short: `3 rule(s), one weakness (CWE-295)`, `1 rule(s)`. */
function shortfall(c) {
    if (c.rules < MIN_RULES)
        return `${c.rules} rule(s)`;
    if (c.weaknesses === 1)
        return `${c.rules} rule(s), one weakness (${c.sole ?? 'one CWE'})`;
    return `${c.rules} rule(s), ${c.weaknesses === 0 ? 'no CWE named' : `${c.weaknesses} CWEs`}`;
}
function incompleteReason(run, d) {
    const reasons = [];
    if (run.scan_type === 'review_pr')
        reasons.push('a diff review looks only at changed files');
    const scope = run.meta?.['scope'];
    if (scope !== undefined && scope !== null)
        reasons.push('the scan was scoped to part of the project');
    const family = d.family ?? d.runs;
    const failed = run.tools_run.filter((t) => family.includes(t.name) && t.status === 'failed').map((t) => t.name);
    if (failed.length > 0)
        reasons.push(`${[...new Set(failed)].join(', ')} failed`);
    const gaps = run.missing_tools.filter((m) => family.some((n) => m === n || m.startsWith(`${n}:`)));
    if (gaps.length > 0)
        reasons.push(`listed missing (${[...new Set(gaps)].join(', ')})`);
    const okPasses = run.tools_run.filter((t) => family.includes(t.name) && t.status === 'ok');
    if (okPasses.some((t) => (t.partially_parsed?.length ?? 0) > 0))
        reasons.push('some files were only partly parsed');
    if (okPasses.some((t) => (t.failed_rules?.length ?? 0) > 0))
        reasons.push('some rules did not load');
    return reasons.length > 0 ? reasons.join('; ') : undefined;
}
function contributionsOf(runs, id) {
    const out = [];
    for (const run of runs) {
        for (const d of OWASP_DETECTORS) {
            const reach = d.reach[id];
            if (reach === undefined)
                continue;
            if (!d.scanTypes.includes(run.scan_type))
                continue;
            if (d.applies !== undefined && !d.applies(run))
                continue;
            const ok = run.tools_run.find((t) => d.runs.includes(t.name) && t.status === 'ok');
            if (ok === undefined)
                continue;
            const entry = { scan_id: run.scan_id, scan_type: run.scan_type, tool: ok.name, detector: d.id };
            const partial = incompleteReason(run, d);
            if (partial !== undefined)
                entry.partial = partial;
            if (!out.some((c) => c.detector.id === d.id && c.entry.scan_id === run.scan_id))
                out.push({ detector: d, reach, entry });
        }
    }
    return out;
}
/** `javascript 60 rules, 8 CWEs` / `javascript 1 rule(s), one weakness (CWE-532)` / `javascript`. */
function cellText(reach, lang, c) {
    if (reach.kind !== 'rules')
        return lang;
    if (meetsBar(c))
        return `${lang} ${c.rules} rules, ${c.weaknesses} CWEs`;
    const cwes = c.weaknesses === 1 ? `one weakness (${c.sole ?? 'one CWE'})` : c.weaknesses === 0 ? 'no CWE named' : `${c.weaknesses} CWEs`;
    return `${lang} ${c.rules} rule(s), ${cwes}`;
}
/**
 * M-d: for the project's languages (all a detector reaches when they are
 * unknown), the detectors that COULD make the category tested, the ones
 * that could only partly cover it, and the languages nothing can test.
 */
function hints(id, languages) {
    const could = [];
    const partly = [];
    const testable = new Set();
    for (const d of OWASP_DETECTORS) {
        const reach = d.reach[id];
        if (reach === undefined)
            continue;
        const scope = d.narrow ?? d.scope;
        const tail = scope !== undefined ? ` — ${scope}` : '';
        if (reach.kind === 'any-language') {
            // Language-agnostic detectors are all narrow: never "would test".
            partly.push(`${d.label}: any language${tail}`);
            continue;
        }
        const langs = languages ??
            (reach.kind === 'languages' ? [...reach.languages] : Object.keys(reach.perLanguage));
        const meets = [];
        const short = [];
        for (const lang of langs) {
            const c = cellIn(reach, lang);
            if (c === null)
                continue;
            if (d.narrow === undefined && meetsBar(c)) {
                meets.push(cellText(reach, lang, c));
                testable.add(lang);
            }
            else
                short.push(cellText(reach, lang, c));
        }
        if (meets.length > 0)
            could.push(`${d.label}: ${meets.join(', ')}${d.scope !== undefined ? ` — ${d.scope}` : ''}`);
        if (short.length > 0)
            partly.push(`${d.label}: ${short.join(', ')}${tail}`);
    }
    return {
        could_be_tested_by: could,
        could_partly_cover: partly,
        untestable_languages: languages === null ? [] : languages.filter((l) => !testable.has(l)),
    };
}
function judge(contributions, project) {
    const { languages } = project;
    const agnostic = contributions.filter((c) => c.reach.kind === 'any-language');
    const complete = (c) => c.entry.partial === undefined;
    const narrow = (c) => c.detector.narrow !== undefined;
    const incompleteLines = (list) => [...new Set(list.filter((c) => !complete(c)).map((c) => `${c.detector.label} incomplete: ${c.entry.partial ?? ''}`))];
    const narrowLines = (list) => [...new Set(list.filter(narrow).map((c) => `${c.detector.label}: ${c.detector.narrow ?? ''}`))];
    // No language to judge per: only a language-agnostic detector can test —
    // and a narrow one only in part.
    if (languages === null || languages.length === 0) {
        const why = languages === null ? 'project languages could not be determined' : 'no source language detected in the project';
        const specific = contributions.filter((c) => c.reach.kind !== 'any-language');
        if (agnostic.some((c) => complete(c) && !narrow(c)))
            return { status: 'tested', perLanguage: [], reasons: [], used: agnostic };
        const narrowOk = agnostic.filter(complete);
        if (narrowOk.length > 0)
            return { status: 'partial', perLanguage: [], reasons: narrowLines(narrowOk), used: agnostic };
        if (agnostic.length > 0)
            return { status: 'partial', perLanguage: [], reasons: incompleteLines(agnostic), used: agnostic };
        if (languages === null && specific.length > 0) {
            return { status: 'partial', perLanguage: [], reasons: [`${why}: a rule-based claim cannot be checked`], used: specific };
        }
        return { status: 'not_tested', perLanguage: [], reasons: specific.length > 0 ? [why] : [], used: [] };
    }
    const perLanguage = [];
    const reasons = [];
    const used = new Set();
    for (const lang of languages) {
        const reaching = contributions.filter((c) => cellIn(c.reach, lang) !== null);
        for (const c of reaching)
            used.add(c);
        const cellOf = (c) => cellIn(c.reach, lang) ?? { rules: 0, weaknesses: 0 };
        const full = reaching.filter((c) => complete(c) && !narrow(c) && meetsBar(cellOf(c)));
        if (full.length > 0) {
            perLanguage.push({ language: lang, coverage: 'full' });
            continue;
        }
        const thin = reaching.filter((c) => complete(c) && !narrow(c));
        const narrowOk = reaching.filter((c) => complete(c) && narrow(c));
        if (thin.length > 0 || narrowOk.length > 0) {
            perLanguage.push({ language: lang, coverage: thin.length > 0 ? 'thin' : 'narrow' });
            for (const c of thin)
                reasons.push(`thin: ${shortfall(cellOf(c))} for ${lang} (${c.detector.label})`);
            reasons.push(...narrowLines(narrowOk));
            continue;
        }
        if (reaching.length > 0) {
            perLanguage.push({ language: lang, coverage: 'incomplete' });
            reasons.push(...incompleteLines(reaching));
            continue;
        }
        perLanguage.push({ language: lang, coverage: 'none' });
    }
    const covered = perLanguage.filter((l) => l.coverage !== 'none').map((l) => l.language);
    const uncovered = perLanguage.filter((l) => l.coverage === 'none').map((l) => l.language);
    if (covered.length === 0)
        return { status: 'not_tested', perLanguage, reasons: [], used: [] };
    if (uncovered.length > 0)
        reasons.push(`covers ${covered.join(', ')}; nothing for ${uncovered.join(', ')}`);
    let status = perLanguage.every((l) => l.coverage === 'full') ? 'tested' : 'partial';
    // N2: a listing that may have missed a language cannot back "every
    // language of the project" — the one it missed could have no rules.
    if (status === 'tested' && project.incomplete !== undefined) {
        status = 'partial';
        reasons.push(`the language list may be incomplete (${project.incomplete}); a language it missed could have no rules`);
    }
    return { status, perLanguage, reasons: [...new Set(reasons)], used: [...used] };
}
export function owaspCoverage(runs, findings, project) {
    const counts = new Map();
    let unmapped = 0;
    for (const f of findings) {
        const ids = f.owasp ?? [];
        if (ids.length === 0) {
            unmapped += 1;
            continue;
        }
        for (const id of new Set(ids)) {
            const known = OWASP_TOP10_2025.find((c) => c.id === id);
            if (known !== undefined)
                counts.set(known.id, (counts.get(known.id) ?? 0) + 1);
        }
    }
    const languages = project.languages === null ? null : [...new Set(project.languages)].sort();
    const judged = { languages, ...(project.incomplete !== undefined ? { incomplete: project.incomplete } : {}) };
    const out = {
        categories: OWASP_TOP10_2025.map((c) => {
            const verdict = judge(contributionsOf(runs, c.id), judged);
            return {
                id: c.id,
                title: c.title,
                url: c.url,
                status: verdict.status,
                tested_by: verdict.used.map((u) => u.entry),
                languages: verdict.perLanguage,
                reasons: verdict.status === 'tested' ? [] : verdict.reasons,
                findings: counts.get(c.id) ?? 0,
                ...hints(c.id, languages === null || languages.length === 0 ? null : languages),
            };
        }),
        findings_total: findings.length,
        findings_unmapped: unmapped,
        languages,
        languages_source: project.source,
    };
    if (project.incomplete !== undefined)
        out.languages_incomplete = project.incomplete;
    return out;
}
/**
 * Coverage runs from an open set's per-slot bookkeeping (`history/openSet.ts`
 * `OpenSet.bookkeeping` + `OpenSet.scans`): each view keeps its own
 * tools_run/missing_tools and takes its scan's type and meta. A view whose
 * scan is not in `scans` is dropped — it cannot be judged without its type.
 */
export function coverageRunsOf(bookkeeping, scans) {
    const byId = new Map(scans.map((s) => [s.scan_id, s]));
    const out = [];
    for (const view of bookkeeping) {
        const scan = byId.get(view.scan_id);
        if (scan === undefined)
            continue;
        const r = {
            scan_id: view.scan_id,
            scan_type: scan.scan_type,
            tools_run: view.tools_run,
            missing_tools: view.missing_tools,
        };
        if (scan.meta !== undefined)
            r.meta = scan.meta;
        out.push(r);
    }
    return out;
}
//# sourceMappingURL=coverage.js.map