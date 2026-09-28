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
 *   - `tested` — for EVERY source language of the project, a detector that
 *     ran fully ok reaches the category with at least {@link MIN_RULES}
 *     rules in that language (or is language-agnostic for it, or is a
 *     vulnerability database complete for that language's packages);
 *   - `partial` — some language has only 1–2 rules ("thin"), some language
 *     has none (the covered and uncovered languages are named), or the only
 *     run that reached it was incomplete;
 *   - `not_tested` — no detector that ran reaches the category in any of
 *     the project's languages. Zero findings there are not a clean result.
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

import type { Finding, ScanType, ToolRun } from '../types.js';
import { canonicalLanguage, type SourceLanguage } from './languages.js';
import { OWASP_TOP10_2025, type Owasp2025Id } from './owaspTop10_2025.js';
import type { ProjectLanguages } from './projectLanguages.js';
import { classifyTaxonomy } from './taxonomy.js';

/** The fewest rules in a language for a detector to TEST a category there. Fewer is "thin". */
export const MIN_RULES = 3;

/** One scan's bookkeeping, as far as coverage needs it. */
export interface CoverageRun {
  scan_id: string;
  scan_type: string;
  meta?: Record<string, unknown>;
  tools_run: readonly ToolRun[];
  missing_tools: readonly string[];
}

type RuleCounts = Readonly<Partial<Record<SourceLanguage, number>>>;

/** How far a detector reaches into one category. */
export type Reach =
  /** Rule counts per language, measured. */
  | { kind: 'rules'; perLanguage: RuleCounts }
  /** A vulnerability database, complete for these languages' packages. */
  | { kind: 'languages'; languages: readonly SourceLanguage[] }
  /** Independent of the source language (secrets in any file, any lock file). */
  | { kind: 'any-language' };

export interface OwaspDetector {
  /** Stable key, recorded in `tested_by`. */
  id: string;
  /** What a reader is told ran, or should run. */
  label: string;
  /** `tools_run` names that stand for this detector. */
  runs: readonly string[];
  /**
   * The passes that make one run of it: when any of these failed or is
   * listed missing in the same scan, the run is incomplete. Defaults to
   * `runs`.
   */
  family?: readonly string[];
  /** The scan types in which those names run THIS rule set. */
  scanTypes: readonly ScanType[];
  /** Further condition on the scan row; absent: always. */
  applies?: (run: CoverageRun) => boolean;
  reach: Partial<Record<Owasp2025Id, Reach>>;
  /** What it looks for inside a category, when that is narrower than the category. */
  scope?: string;
  /** Why the counts hold. */
  basis: string;
  /** When, and from what, the counts were measured. */
  measured: string;
}

/**
 * The registry ran: an explicit `local_only: false` on a scan_sast or
 * review_pr row (both record it); always on a script-era security_full row
 * (its script ran `--config=auto`); never on an orchestrated security_full
 * parent, whose merged bookkeeping does not say — its children do.
 */
function registryRan(run: CoverageRun): boolean {
  if (run.scan_type === 'security_full') return !Array.isArray(run.meta?.['child_scans']);
  return run.meta?.['local_only'] === false;
}

const rules = (perLanguage: RuleCounts): Reach => ({ kind: 'rules', perLanguage });

/**
 * Semgrep registry, p/default (1074 rules), fetched 2026-09-28: rules per
 * (category, language), each rule counted in every source language it
 * lists, under every category `classifyTaxonomy` gives its metadata — what
 * its findings would carry. `--config=auto` picks registry rulesets by
 * language; p/default is the measured stand-in.
 */
const REGISTRY_RULES: Partial<Record<Owasp2025Id, Reach>> = {
  'A01:2025': rules({ csharp: 7, go: 10, java: 10, javascript: 32, php: 8, python: 20, ruby: 14, scala: 5, typescript: 32 }),
  'A02:2025': rules({ csharp: 3, go: 6, java: 11, javascript: 10, kotlin: 2, python: 12, scala: 3, typescript: 10 }),
  'A03:2025': rules({ javascript: 1, typescript: 1 }),
  'A04:2025': rules({ csharp: 2, go: 24, java: 43, javascript: 19, kotlin: 11, php: 6, python: 53, ruby: 11, scala: 3, typescript: 15 }),
  'A05:2025': rules({
    c: 1, csharp: 4, go: 28, java: 38, javascript: 60, kotlin: 2, lua: 1, php: 17, python: 92, ruby: 30, rust: 1, scala: 9, typescript: 61,
  }),
  'A06:2025': rules({ c: 3, csharp: 2, go: 2, java: 4, javascript: 12, php: 1, python: 5, ruby: 5, scala: 2, swift: 1, typescript: 16 }),
  'A07:2025': rules({ csharp: 2, go: 3, java: 5, javascript: 9, kotlin: 2, php: 3, python: 10, ruby: 3, rust: 3, typescript: 10 }),
  'A08:2025': rules({ csharp: 11, go: 2, java: 7, javascript: 9, php: 2, python: 17, ruby: 9, typescript: 9 }),
  'A09:2025': rules({ python: 1 }),
  'A10:2025': rules({ csharp: 1, go: 1, php: 1, ruby: 1 }),
};

/**
 * Bandit 1.9.4 (`bandit/core/issue.py` and every `Cwe.*` assignment in its
 * plugins and blacklists — 85), measured 2026-09-28. Python only.
 */
const BANDIT_RULES: Partial<Record<Owasp2025Id, Reach>> = {
  'A01:2025': rules({ python: 8 }),
  'A04:2025': rules({ python: 22 }),
  'A05:2025': rules({ python: 38 }),
  'A07:2025': rules({ python: 4 }),
  'A08:2025': rules({ python: 5 }),
  'A10:2025': rules({ python: 3 }),
};

/** configs/semgrep/bugfix-*.yml, recounted by packTaxonomy.test.ts. */
const BUGFIX_RULES: Partial<Record<Owasp2025Id, Reach>> = {
  'A06:2025': rules({ javascript: 1, typescript: 1 }),
  'A10:2025': rules({ csharp: 3, go: 5, java: 3, javascript: 6, php: 2, python: 5, typescript: 6 }),
};

/**
 * configs/semgrep/rgpd.yml, recounted by packTaxonomy.test.ts. Its four
 * tracker/embed rules are `generic` rules over templates and count for no
 * source language, so the pack reaches A09 only — and only for personal
 * data written to logs.
 */
const RGPD_RULES: Partial<Record<Owasp2025Id, Reach>> = {
  'A09:2025': rules({ csharp: 1, javascript: 1, php: 1, python: 1, typescript: 1 }),
};

const DEPENDENCY_AUDITORS = ['npm', 'pip-audit', 'dotnet'] as const;

export const OWASP_DETECTORS: readonly OwaspDetector[] = [
  {
    id: 'semgrep-registry',
    label: 'Semgrep registry rules (scan_sast without local_only)',
    runs: ['semgrep'],
    scanTypes: ['sast', 'security_full', 'review_pr'],
    applies: registryRan,
    reach: REGISTRY_RULES,
    basis:
      'Registry ruleset p/default, 1074 rules; each rule counted per source language it lists, under the ' +
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
    basis:
      "The pack's own metadata: one CWE-532 rule per language (JS/TS, PHP, Python, C#). The tracker and embed " +
      'rules are generic template rules and count for no source language.',
    measured: 'configs/semgrep/rgpd.yml, 2026-09-28 (recounted by packTaxonomy.test.ts)',
  },
  {
    id: 'trivy-vulnerabilities',
    label: 'Trivy vulnerability pass (scan_deps, deps_audit)',
    runs: ['trivy'],
    scanTypes: ['deps', 'deps_audit', 'security_full'],
    reach: { 'A03:2025': { kind: 'any-language' } },
    scope: 'known-vulnerable dependencies (CWE-1395)',
    basis:
      'Language-agnostic for A03: it reads every lock file it supports; a root manifest it produced no result for ' +
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
    scope: "the image's packages",
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
    scope: 'known-vulnerable npm packages',
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
    scope: 'known-vulnerable Python packages',
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
    scope: 'known-vulnerable NuGet packages',
    basis: 'The NuGet advisory data, for .NET projects only.',
    measured: '2026-09-28',
  },
  {
    id: 'gitleaks',
    label: 'gitleaks (scan_secrets)',
    runs: ['gitleaks', 'gitleaks-working-tree'],
    scanTypes: ['secrets', 'security_full', 'wordpress', 'review_pr'],
    reach: { 'A07:2025': { kind: 'any-language' } },
    scope: 'hard-coded credentials (CWE-798) only',
    basis:
      'Language-agnostic for A07: its secret patterns match any file. Every finding is a hard-coded credential, ' +
      'one weakness of A07 among many.',
    measured: '2026-09-28',
  },
];

/**
 * Rules per (category, source language) of a rule list — how the pack
 * detectors above are counted, and how their test recounts them. A rule
 * counts in every source language it lists (`generic` counts in none),
 * under every category `classifyTaxonomy` gives its metadata.
 */
export function countRuleReach(
  ruleList: ReadonlyArray<{ languages?: unknown; metadata?: Record<string, unknown> }>,
): Record<string, Record<string, number>> {
  const out: Record<string, Record<string, number>> = {};
  for (const rule of ruleList) {
    const langs = new Set(
      (Array.isArray(rule.languages) ? rule.languages : [])
        .map((l) => (typeof l === 'string' ? canonicalLanguage(l) : null))
        .filter((l): l is SourceLanguage => l !== null),
    );
    const cats = classifyTaxonomy({ cwe: rule.metadata?.['cwe'], owasp: rule.metadata?.['owasp'] }).owasp ?? [];
    for (const cat of cats) {
      for (const lang of langs) {
        const row = (out[cat] ??= {});
        row[lang] = (row[lang] ?? 0) + 1;
      }
    }
  }
  for (const cat of Object.keys(out)) {
    const row = out[cat] ?? {};
    out[cat] = Object.fromEntries(Object.entries(row).sort((a, b) => a[0].localeCompare(b[0])));
  }
  return out;
}

export type OwaspCoverageStatus = 'tested' | 'partial' | 'not_tested';

export interface OwaspTestedBy {
  scan_id: string;
  scan_type: string;
  tool: string;
  detector: string;
  /** Why this run counts only toward partial coverage. Absent: complete. */
  partial?: string;
}

export interface OwaspLanguageCoverage {
  language: string;
  /** full: ≥ MIN_RULES from a complete run; thin: 1–2; incomplete: only incomplete runs; none. */
  coverage: 'full' | 'thin' | 'incomplete' | 'none';
}

export interface OwaspCategoryCoverage {
  id: Owasp2025Id;
  title: string;
  url: string;
  status: OwaspCoverageStatus;
  tested_by: OwaspTestedBy[];
  /** Per project language. Empty when the languages are unknown or there are none. */
  languages: OwaspLanguageCoverage[];
  /** Why the status is not `tested` — thin counts, incomplete runs, uncovered languages. Empty when tested. */
  reasons: string[];
  /** Open findings of the covered scans that carry this category. */
  findings: number;
  /**
   * The detectors that reach this category in the project's languages, with
   * their counts — what to run when it was not tested. Empty when nothing
   * dev-guardian runs has rules for those languages.
   */
  could_be_tested_by: string[];
}

export interface OwaspCoverage {
  categories: OwaspCategoryCoverage[];
  findings_total: number;
  /** Findings with no OWASP 2025 category: no CWE known, a CWE outside the list, or stored before schema 13. */
  findings_unmapped: number;
  /** The languages coverage was judged against; null when unknown. */
  languages: string[] | null;
  languages_source: string;
}

/** What a run of a detector reached in one category, and whether the run was complete. */
interface Contribution {
  detector: OwaspDetector;
  reach: Reach;
  entry: OwaspTestedBy;
}

/** Rules `reach` has in `lang`: Infinity when it is complete there, 0 when it has none. */
function rulesIn(reach: Reach, lang: string): number {
  switch (reach.kind) {
    case 'any-language':
      return Number.POSITIVE_INFINITY;
    case 'languages':
      return (reach.languages as readonly string[]).includes(lang) ? Number.POSITIVE_INFINITY : 0;
    case 'rules':
      return (reach.perLanguage as Readonly<Record<string, number | undefined>>)[lang] ?? 0;
  }
}

function incompleteReason(run: CoverageRun, d: OwaspDetector): string | undefined {
  const reasons: string[] = [];
  if (run.scan_type === 'review_pr') reasons.push('a diff review looks only at changed files');
  const scope = run.meta?.['scope'];
  if (scope !== undefined && scope !== null) reasons.push('the scan was scoped to part of the project');
  const family = d.family ?? d.runs;
  const failed = run.tools_run.filter((t) => family.includes(t.name) && t.status === 'failed').map((t) => t.name);
  if (failed.length > 0) reasons.push(`${[...new Set(failed)].join(', ')} failed`);
  const gaps = run.missing_tools.filter((m) => family.some((n) => m === n || m.startsWith(`${n}:`)));
  if (gaps.length > 0) reasons.push(`listed missing (${[...new Set(gaps)].join(', ')})`);
  const okPasses = run.tools_run.filter((t) => family.includes(t.name) && t.status === 'ok');
  if (okPasses.some((t) => (t.partially_parsed?.length ?? 0) > 0)) reasons.push('some files were only partly parsed');
  if (okPasses.some((t) => (t.failed_rules?.length ?? 0) > 0)) reasons.push('some rules did not load');
  return reasons.length > 0 ? reasons.join('; ') : undefined;
}

function contributionsOf(runs: readonly CoverageRun[], id: Owasp2025Id): Contribution[] {
  const out: Contribution[] = [];
  for (const run of runs) {
    for (const d of OWASP_DETECTORS) {
      const reach = d.reach[id];
      if (reach === undefined) continue;
      if (!(d.scanTypes as readonly string[]).includes(run.scan_type)) continue;
      if (d.applies !== undefined && !d.applies(run)) continue;
      const ok = run.tools_run.find((t) => d.runs.includes(t.name) && t.status === 'ok');
      if (ok === undefined) continue;
      const entry: OwaspTestedBy = { scan_id: run.scan_id, scan_type: run.scan_type, tool: ok.name, detector: d.id };
      const partial = incompleteReason(run, d);
      if (partial !== undefined) entry.partial = partial;
      if (!out.some((c) => c.detector.id === d.id && c.entry.scan_id === run.scan_id)) out.push({ detector: d, reach, entry });
    }
  }
  return out;
}

/** `Semgrep registry rules (…): go 10, java 10 (personal data …)` for the languages given; null when it reaches none. */
function hint(d: OwaspDetector, reach: Reach, languages: readonly string[] | null): string | null {
  let summary: string;
  if (reach.kind === 'any-language') summary = 'any language';
  else if (reach.kind === 'languages') {
    const hit = languages === null ? [...reach.languages] : reach.languages.filter((l) => languages.includes(l));
    if (hit.length === 0) return null;
    summary = hit.join(', ');
  } else {
    const entries = Object.entries(reach.perLanguage as Readonly<Record<string, number | undefined>>)
      .filter((e): e is [string, number] => e[1] !== undefined && e[1] > 0)
      .filter(([l]) => languages === null || languages.includes(l));
    if (entries.length === 0) return null;
    summary = entries.map(([l, n]) => `${l} ${n}${n < MIN_RULES ? ' (thin)' : ''}`).join(', ');
  }
  return `${d.label}: ${summary}${d.scope !== undefined ? ` — ${d.scope}` : ''}`;
}

function judge(
  contributions: readonly Contribution[],
  languages: readonly string[] | null,
): { status: OwaspCoverageStatus; perLanguage: OwaspLanguageCoverage[]; reasons: string[]; used: Contribution[] } {
  const agnostic = contributions.filter((c) => c.reach.kind === 'any-language');
  const complete = (c: Contribution): boolean => c.entry.partial === undefined;
  const incompleteLines = (list: readonly Contribution[]): string[] =>
    [...new Set(list.filter((c) => !complete(c)).map((c) => `${c.detector.label} incomplete: ${c.entry.partial ?? ''}`))];

  // No language to judge per: only a language-agnostic detector can test.
  if (languages === null || languages.length === 0) {
    const why = languages === null ? 'project languages could not be determined' : 'no source language detected in the project';
    const specific = contributions.filter((c) => c.reach.kind !== 'any-language');
    if (agnostic.some(complete)) return { status: 'tested', perLanguage: [], reasons: [], used: agnostic };
    if (agnostic.length > 0) return { status: 'partial', perLanguage: [], reasons: incompleteLines(agnostic), used: agnostic };
    if (languages === null && specific.length > 0) {
      return { status: 'partial', perLanguage: [], reasons: [`${why}: a rule-based claim cannot be checked`], used: specific };
    }
    return { status: 'not_tested', perLanguage: [], reasons: specific.length > 0 ? [why] : [], used: [] };
  }

  const perLanguage: OwaspLanguageCoverage[] = [];
  const reasons: string[] = [];
  const used = new Set<Contribution>();
  for (const lang of languages) {
    const reaching = contributions.filter((c) => rulesIn(c.reach, lang) > 0);
    for (const c of reaching) used.add(c);
    const full = reaching.filter((c) => complete(c) && rulesIn(c.reach, lang) >= MIN_RULES);
    if (full.length > 0) {
      perLanguage.push({ language: lang, coverage: 'full' });
      continue;
    }
    const thin = reaching.filter(complete);
    if (thin.length > 0) {
      perLanguage.push({ language: lang, coverage: 'thin' });
      for (const c of thin) reasons.push(`thin: ${rulesIn(c.reach, lang)} rule(s) for ${lang} (${c.detector.label})`);
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
  if (covered.length === 0) return { status: 'not_tested', perLanguage, reasons: [], used: [] };
  if (uncovered.length > 0) reasons.push(`covers ${covered.join(', ')}; nothing for ${uncovered.join(', ')}`);
  const status: OwaspCoverageStatus = perLanguage.every((l) => l.coverage === 'full') ? 'tested' : 'partial';
  return { status, perLanguage, reasons: [...new Set(reasons)], used: [...used] };
}

export function owaspCoverage(
  runs: readonly CoverageRun[],
  findings: ReadonlyArray<Pick<Finding, 'owasp'>>,
  project: ProjectLanguages,
): OwaspCoverage {
  const counts = new Map<Owasp2025Id, number>();
  let unmapped = 0;
  for (const f of findings) {
    const ids = f.owasp ?? [];
    if (ids.length === 0) {
      unmapped += 1;
      continue;
    }
    for (const id of new Set(ids)) {
      const known = OWASP_TOP10_2025.find((c) => c.id === id);
      if (known !== undefined) counts.set(known.id, (counts.get(known.id) ?? 0) + 1);
    }
  }

  const languages = project.languages === null ? null : [...new Set(project.languages)].sort();
  return {
    categories: OWASP_TOP10_2025.map((c) => {
      const verdict = judge(contributionsOf(runs, c.id), languages);
      const hintLanguages = languages === null || languages.length === 0 ? null : languages;
      return {
        id: c.id,
        title: c.title,
        url: c.url,
        status: verdict.status,
        tested_by: verdict.used.map((u) => u.entry),
        languages: verdict.perLanguage,
        reasons: verdict.status === 'tested' ? [] : verdict.reasons,
        findings: counts.get(c.id) ?? 0,
        could_be_tested_by: OWASP_DETECTORS.flatMap((d) => {
          const reach = d.reach[c.id];
          const text = reach === undefined ? null : hint(d, reach, hintLanguages);
          return text === null ? [] : [text];
        }),
      };
    }),
    findings_total: findings.length,
    findings_unmapped: unmapped,
    languages,
    languages_source: project.source,
  };
}

/**
 * Coverage runs from an open set's per-slot bookkeeping (`history/openSet.ts`
 * `OpenSet.bookkeeping` + `OpenSet.scans`): each view keeps its own
 * tools_run/missing_tools and takes its scan's type and meta. A view whose
 * scan is not in `scans` is dropped — it cannot be judged without its type.
 */
export function coverageRunsOf(
  bookkeeping: ReadonlyArray<{ scan_id: string; tools_run: readonly ToolRun[]; missing_tools: readonly string[] }>,
  scans: ReadonlyArray<{ scan_id: string; scan_type: string; meta?: Record<string, unknown> }>,
): CoverageRun[] {
  const byId = new Map(scans.map((s) => [s.scan_id, s]));
  const out: CoverageRun[] = [];
  for (const view of bookkeeping) {
    const scan = byId.get(view.scan_id);
    if (scan === undefined) continue;
    const r: CoverageRun = {
      scan_id: view.scan_id,
      scan_type: scan.scan_type,
      tools_run: view.tools_run,
      missing_tools: view.missing_tools,
    };
    if (scan.meta !== undefined) r.meta = scan.meta;
    out.push(r);
  }
  return out;
}
