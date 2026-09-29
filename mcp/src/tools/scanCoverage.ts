/**
 * Scan coverage — turn per-scanner bookkeeping into a single trust signal.
 *
 * A scan's headline severity counts are only trustworthy when the scanners
 * that were *supposed* to run actually ran. A SAST scan reporting "0 critical"
 * because Semgrep was not installed is NOT a clean bill of health — it scanned
 * nothing. Every scan tool already records which scanners ran (`tools_run`)
 * and which were expected but absent (`missing_tools`); this module distils
 * that into a `coverage` value the factory and roll-ups can surface so a
 * silent "0 findings" never reads as "all clear".
 */

import { lockFileAdvice } from '../runners/scannerParsers/trivy.js';
import { suppressionNote } from '../runners/trivyRun.js';
import type { ScanCoverage, ToolRun } from '../types.js';

export type { ScanCoverage };

/**
 * One warning per run whose repository configuration suppressed findings
 * (`ToolRun.suppressed_by_repo_config`, round 4, item 2) — counted and named,
 * or said to be unlistable. Never a coverage gap: the repository decided it,
 * and {@link computeCoverage} does not read it.
 */
export function repoSuppressionWarnings(toolsRun: readonly ToolRun[]): string[] {
  const out: string[] = [];
  for (const run of toolsRun) {
    const s = run.suppressed_by_repo_config;
    if (s === undefined) continue;
    const tail =
      s.count === null ? 'its entries are not reported' : 'not reported, not counted; remove the entries to see them';
    const line = `${run.name}: ${suppressionNote(s)} — ${tail}`;
    if (!out.includes(line)) out.push(line);
  }
  return out;
}

/**
 * Derive coverage from the per-scanner outcomes.
 *
 *   - 'none'    — nothing ran successfully and something was expected but
 *                 missing or failed. A "0 findings" result here is meaningless.
 *   - 'partial' — at least one scanner ran ok, but some expected scanner was
 *                 missing or failed. Findings may be incomplete.
 *   - 'full'    — every scanner that was attempted ran ok and nothing expected
 *                 was missing. Counts can be trusted.
 *
 * A scan that legitimately had nothing to do (e.g. `scan_containers` with no
 * Dockerfile and no image) reports 'full': there were no gaps, just no work.
 * Such "nothing to scan" skips must NOT be added to `missing_tools` (they are
 * `skipped` with a not-applicable reason instead).
 */
export function computeCoverage(
  toolsRun: readonly ToolRun[],
  missingTools: readonly string[],
): ScanCoverage {
  const ranOk = toolsRun.some((t) => t.status === 'ok');
  const failed = toolsRun.some((t) => t.status === 'failed');
  const hasGaps = missingTools.length > 0 || failed;
  if (!hasGaps) return 'full';
  return ranOk ? 'partial' : 'none';
}

export interface CoverageAssessment {
  coverage: ScanCoverage;
  /** Loud, human-readable warning when coverage !== 'full', else null. */
  warning: string | null;
}

/** What a scan's own run says about its gaps, beyond `tools_run` / `missing_tools`. */
export interface CoverageContext {
  /**
   * `manifest_coverage_gaps` as scan_deps / deps_audit record it: each
   * ecosystem whose manifest Trivy produced nothing for, and its files.
   */
  manifestGaps?: unknown;
}

/** The `tools_run` reason scan_deps / deps_audit give Trivy when it read no manifest. */
const NO_SUPPORTED_MANIFEST = 'no_supported_manifest';

/** The sentinel, possibly followed by notes (`; honoured the project's .trivyignore …`). */
function isNoSupportedManifest(reason: string | undefined): boolean {
  return reason === NO_SUPPORTED_MANIFEST || (reason?.startsWith(`${NO_SUPPORTED_MANIFEST};`) ?? false);
}

interface ManifestGap {
  ecosystem: string;
  files: string[];
}

function parseManifestGaps(value: unknown): ManifestGap[] {
  if (!Array.isArray(value)) return [];
  const out: ManifestGap[] = [];
  for (const entry of value as unknown[]) {
    if (entry === null || typeof entry !== 'object') continue;
    const { ecosystem, files } = entry as { ecosystem?: unknown; files?: unknown };
    if (typeof ecosystem !== 'string') continue;
    out.push({
      ecosystem,
      files: Array.isArray(files) ? files.filter((f): f is string => typeof f === 'string') : [],
    });
  }
  return out;
}

/** `gradle (build.gradle)`, or the bare ecosystem when no file is known. */
function nameOf(gap: ManifestGap): string {
  return gap.files.length > 0 ? `${gap.ecosystem} (${gap.files.join(', ')})` : gap.ecosystem;
}

/** Each gap's manifest and the lock file that closes it (`trivy.ts#lockFileAdvice`). */
function manifestAdvice(gaps: readonly ManifestGap[]): string {
  if (gaps.length === 0) {
    return 'generate the lock file Trivy reads for each dependency manifest (see manifest_coverage_gaps) and re-run';
  }
  return gaps
    .map((g) => `${nameOf(g)}: ${lockFileAdvice(g.ecosystem) ?? 'generate the lock file Trivy reads for it'}`)
    .join('; ');
}

/**
 * Compute coverage and, when it is not 'full', a loud warning naming the
 * scanner(s) responsible for the gap. The warning for 'none' explicitly
 * states that a zero-findings result is not a clean result — this is the
 * anti-false-confidence line that downstream summaries and the model must
 * not paper over. The warning for 'partial' distinguishes a scanner that
 * genuinely did not run from one that ran (its own `tools_run` entry says
 * 'ok') but is still a named gap — the latter must not be worded as "did
 * not run", which would contradict its own status in the same response.
 *
 * Nor is "install it" the advice for a scanner that ran and had nothing it
 * could read: Trivy on a `build.gradle` with no `gradle.lockfile` is skipped
 * `no_supported_manifest` (or `ok` with a `trivy:<ecosystem>` gap beside a
 * covered ecosystem). The warning says Trivy ran, names the manifest from
 * `context.manifestGaps`, and names the lock file that closes the gap.
 */
export function assessCoverage(
  scanType: string,
  toolsRun: readonly ToolRun[],
  missingTools: readonly string[],
  context: CoverageContext = {},
): CoverageAssessment {
  const coverage = computeCoverage(toolsRun, missingTools);
  if (coverage === 'full') return { coverage, warning: null };

  const failedTools = toolsRun.filter((t) => t.status === 'failed').map((t) => t.name);
  // Installed and ran, but its rules did not load (`ToolRun.rule_config_error`):
  // the advice is the rule, never "install it".
  const ruleErrors = [
    ...new Set(toolsRun.filter((t) => t.status === 'failed' && t.rule_config_error === true).map((t) => t.name)),
  ].filter((name) => !toolsRun.some((t) => t.name === name && t.status === 'ok'));
  const ruleClause =
    ruleErrors.length > 0
      ? `${ruleErrors.join(', ')} ran, but its rules did not load (a rule configuration error — see its tools_run reason); fix or remove the rule and re-run`
      : null;
  const gaps = [...new Set([...missingTools, ...failedTools])].filter((name) => !ruleErrors.includes(name));
  const list = gaps.length > 0 ? gaps.join(', ') : 'one or more scanners';
  const manifestGaps = parseManifestGaps(context.manifestGaps);

  // A scanner that ran and read no manifest it supports — installed, working.
  const unreadable = gaps.filter((name) =>
    toolsRun.some((t) => t.name === name && t.status === 'skipped' && isNoSupportedManifest(t.reason)),
  );

  if (coverage === 'none') {
    // scan_sast: no registry or project rule loaded, but the plugin's LLM
    // pack did and its findings are recorded — "NOTHING was scanned" would
    // contradict the findings beside it (`ToolRun.plugin_pack_only`).
    const packOnly = ruleErrors.filter((name) =>
      toolsRun.some((t) => t.name === name && t.status === 'failed' && t.plugin_pack_only === true),
    );
    if (packOnly.length > 0 && packOnly.length === ruleErrors.length) {
      return {
        coverage,
        warning:
          `⚠️ ${scanType}: ${packOnly.join(', ')} ran, but no registry or project rule loaded; only the plugin's LLM ` +
          'pack ran — its findings are reported, and nothing else looked at this code (a rule configuration ' +
          'error — see its tools_run reason); fix or remove the rules and re-run.' +
          (gaps.length > 0 ? ` Also unavailable or failed: ${list} — install or fix it (or use the Docker fallback).` : '') +
          ' A result without them is NOT a clean bill of health.',
      };
    }
    if (ruleClause !== null) {
      return {
        coverage,
        warning:
          `⚠️ ${scanType}: NOTHING was scanned — ${ruleClause}.` +
          (gaps.length > 0 ? ` Also unavailable or failed: ${list} — install or fix it (or use the Docker fallback).` : '') +
          ' A "0 findings" result is NOT a clean bill of health.',
      };
    }
    if (unreadable.length === 0) {
      return {
        coverage,
        warning:
          `⚠️ ${scanType}: NO scanner ran (unavailable/failed: ${list}). ` +
          `A "0 findings" result is NOT a clean bill of health — nothing was actually scanned. ` +
          `Install ${list} (or use the Docker fallback) and re-run before trusting this scan.`,
      };
    }
    const others = gaps.filter((name) => !unreadable.includes(name));
    return {
      coverage,
      warning:
        `⚠️ ${scanType}: NOTHING was scanned — ${unreadable.join(', ')} is installed and ran, but no ` +
        `dependency manifest here has a lock file it can read: ${manifestAdvice(manifestGaps)}. ` +
        `A "0 findings" result is NOT a clean bill of health.` +
        (others.length > 0 ? ` Install ${others.join(', ')} (or use the Docker fallback).` : '') +
        ' Then re-run before trusting this scan.',
    };
  }

  // coverage === 'partial'. A name in `gaps` can mean different things:
  // it genuinely never ran (skipped/failed — "did not run" is accurate), or
  // it DID run (its own `tools_run` entry says 'ok') but coverage is still
  // short — e.g. bug_hunt retrying with surviving Semgrep packs after one
  // local `--config` failed to load: semgrep's own tools_run entry is 'ok',
  // with the detail in its `reason`, yet `missing_tools` still (correctly)
  // carries 'semgrep' so this stays 'partial'. Saying "semgrep did not run"
  // in that case contradicts the structured tools_run entry sitting right
  // next to this warning in the same response — same family of bug as the
  // misleading "install semgrep" text fixed elsewhere (bugfix-rules-jsts).
  // A `<scanner>:<part>` name with no run of its own is one part of a
  // scanner that ran (scan_deps: `trivy:gradle`).
  const ranOkNames = new Set(toolsRun.filter((t) => t.status === 'ok').map((t) => t.name));
  const hasOwnRun = (name: string): boolean => toolsRun.some((t) => t.name === name);
  const partsOf = new Map<string, string[]>();
  for (const name of gaps) {
    const colon = name.indexOf(':');
    if (colon <= 0 || hasOwnRun(name) || !ranOkNames.has(name.slice(0, colon))) continue;
    const base = name.slice(0, colon);
    partsOf.set(base, [...(partsOf.get(base) ?? []), name.slice(colon + 1)]);
  }
  const isPart = (name: string): boolean => {
    const colon = name.indexOf(':');
    return colon > 0 && (partsOf.get(name.slice(0, colon))?.includes(name.slice(colon + 1)) ?? false);
  };
  const notRun = gaps.filter((name) => !ranOkNames.has(name) && !isPart(name) && !unreadable.includes(name));
  const ranWithGaps = gaps.filter((name) => ranOkNames.has(name));
  const clauses: string[] = [];
  if (ruleClause !== null) clauses.push(ruleClause);
  if (notRun.length > 0) clauses.push(`${notRun.join(', ')} did not run`);
  if (unreadable.length > 0) {
    clauses.push(
      `${unreadable.join(', ')} ran but read no dependency manifest — ${manifestAdvice(manifestGaps)}`,
    );
  }
  for (const [base, allParts] of partsOf) {
    // `trivy:manifest-walk` (runners/trivyRun.ts#judgeTrivyFs): not a part
    // Trivy missed, but the check of which manifests it read cut short.
    const parts = allParts.filter((part) => part !== 'manifest-walk');
    if (parts.length < allParts.length) {
      clauses.push(
        `${base} ran, but the check of which dependency manifests it read stopped early (see its tools_run ` +
          'reason) — manifests beyond it were not checked',
      );
    }
    if (parts.length === 0) continue;
    const named = parts.map((part) => {
      const gap = manifestGaps.find((g) => g.ecosystem === part);
      return gap === undefined ? part : nameOf(gap);
    });
    const covered = manifestGaps.filter((g) => parts.includes(g.ecosystem));
    clauses.push(
      `${base} ran, but ${named.join(', ')} was not covered` +
        (covered.length > 0 ? ` — ${manifestAdvice(covered)}` : ''),
    );
  }
  if (ranWithGaps.length > 0) {
    clauses.push(`${ranWithGaps.join(', ')} ran with reduced coverage (see its tools_run reason)`);
  }
  const clause = clauses.length > 0 ? clauses.join('; ') : `${list} did not run`;

  return {
    coverage,
    warning: `⚠️ ${scanType}: partial coverage — ${clause}; findings may be incomplete.`,
  };
}
