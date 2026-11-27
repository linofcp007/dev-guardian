/**
 * `review_pr`'s merge-base comparison (3.18.0, DG-12): which of the review's
 * Semgrep findings were already in the code the change started from.
 *
 * Editing one line of a file listed every old finding of that file as if the
 * change brought it (on dev-spec-driven, path-join alone has about 900), and
 * the skill's "don't block on what the change did not do" was left to the
 * model. So each Semgrep finding of the head is judged against a Semgrep run
 * with the same rules and flags over the same files as they were at the
 * merge base (`tools/reviewPr.ts`), by the CI gate's own matcher
 * (`ci/baseline.ts#newFindings`: identity, the identity before a rename,
 * then `match_id` — one to one), never a second notion of "the same finding".
 *
 * Positive evidence only: a finding is `preexisting` when it lies on lines
 * the change kept and the base run reported it; every other Semgrep finding
 * is introduced, or `unknown` when the base run could not measure its file
 * (only partly analysed, or not scanned). A base side that could not be read
 * at all — no merge base, a failed checkout, a failed or cancelled run, a
 * file pair git could not diff — is `compared: false`, and nothing is
 * preexisting. Other scanners' findings are not compared (counted as such).
 * Nothing is hidden: every finding stays in the review's counts and
 * `top_findings`; the skill reads `preexisting` (the list, never an absence)
 * to judge a finding as not the change's.
 *
 * A finding on a line the change ADDED is introduced, whatever its identity
 * matches ({@link BaseSide}'s `addedLines`: the `-U0` diff of each compared
 * file at the merge base against the file the head run read — the working
 * tree when head is checked out). The identity alone said "the same finding"
 * of a new one twice (3.18.0 review 1): a credential rule's finding is keyed
 * without its line (`fingerprint/findingIdentity.ts#keyedWithoutLine`), so a
 * new hard-coded secret in a new function took the identity of the one the
 * change removed; and a new flagged line identical to an old one, put above
 * it, took the old one's occurrence. The kept findings alone are then
 * matched, so the occurrences of identical lines are counted among the kept
 * ones — as if the added lines were not there.
 *
 * What the comparison still cannot tell (the skill and docs/ci.md say it): a
 * flagged line the change kept reads preexisting when the base run flagged
 * the same, even if what reaches it changed — a new source, a removed check,
 * the function around it replaced (a deleted function and a new one sharing
 * an identical sink line, which the diff keeps); and of two identical lines,
 * which is the added one is the diff's choice.
 */

import { buildBaseline, newFindings } from '../ci/baseline.js';
import type { NameStatusEntry } from '../runners/git.js';
import { SEMGREP_TOOL_NAME } from '../runners/scannerParsers/semgrep.js';
import { countBySeverity, topFindings } from '../severity/counts.js';
import type { Finding, Severity } from '../types.js';

/** How many preexisting findings the result lists, by severity then fingerprint (`top_findings`' own order). */
export const PREEXISTING_LISTED = 10;

/** What the base side read, for {@link classifyAgainstBase}. */
export type BaseSide =
  | {
      compared: true;
      /** The merge base the files were read at. */
      base_sha: string;
      /** The base run's Semgrep findings, with identities from the base files' own lines. */
      findings: readonly Finding[];
      /** Head path → the path its file had at the merge base (a rename). */
      renamedFrom: ReadonlyMap<string, string>;
      /** Head paths whose base file the run could not measure (partly analysed, or not scanned). */
      unknownFiles: ReadonlySet<string>;
      /**
       * Head path → the line ranges the change added to it (inclusive, the head file's numbers), for every head
       * file compared with its base file. A file not here has no base counterpart the base run read.
       */
      addedLines: ReadonlyMap<string, readonly LineRange[]>;
    }
  | { compared: false; reason: string };

/** Lines `start` to `end` of a file, both included. */
export interface LineRange {
  start: number;
  end: number;
}

export type BaseComparison =
  | {
      compared: true;
      base_sha: string;
      /** Semgrep findings by verdict, and the findings of other scanners (not compared). */
      counts: { introduced: number; preexisting: number; unknown: number; not_compared: number };
      preexisting_by_severity: Record<Severity, number>;
      /** At most {@link PREEXISTING_LISTED} of the preexisting findings — never cut by the response's severity floor. */
      preexisting: Finding[];
    }
  | { compared: false; reason: string };

function posix(path: string): string {
  let out = path.replace(/\\/g, '/');
  while (out.startsWith('./')) out = out.slice(2);
  return out;
}

/**
 * Whether `f` lies on a line the change added to its file (`added`: the head path's ranges, or undefined for a
 * file not compared). A finding with no line of its own is never on a kept one.
 */
function onAddedLine(f: Finding, added: ReadonlyMap<string, readonly LineRange[]>): boolean {
  const ranges = f.file_path !== undefined ? added.get(posix(f.file_path)) : undefined;
  if (ranges === undefined) return false;
  const start = f.line_start;
  if (start === undefined) return true;
  const end = Math.max(start, f.line_end ?? start);
  return ranges.some((r) => r.start <= end && r.end >= start);
}

/** The verdict of each of `head`'s findings against `base` (see the module comment). */
export function classifyAgainstBase(head: readonly Finding[], base: BaseSide): BaseComparison {
  if (!base.compared) return { compared: false, reason: base.reason };
  const semgrep = head.filter((f) => f.tool === SEMGREP_TOOL_NAME);
  const added = new Set(semgrep.filter((f) => onAddedLine(f, base.addedLines)));
  const kept = semgrep.filter((f) => !added.has(f));
  const fresh = new Set(newFindings(kept, buildBaseline(base.findings, null, ''), base.renamedFrom));
  const preexisting = kept.filter((f) => !fresh.has(f));
  const unknown = kept.filter((f) => fresh.has(f) && f.file_path !== undefined && base.unknownFiles.has(posix(f.file_path)));
  return {
    compared: true,
    base_sha: base.base_sha,
    counts: {
      introduced: added.size + fresh.size - unknown.length,
      preexisting: preexisting.length,
      unknown: unknown.length,
      not_compared: head.length - semgrep.length,
    },
    preexisting_by_severity: countBySeverity(preexisting),
    preexisting: topFindings(preexisting, PREEXISTING_LISTED),
  };
}

/**
 * The files the base run reads, from the diff's `--name-status -M` listing
 * (`runners/git.ts#parseNameStatus`): each head file that holds a Semgrep
 * result, is in the review (`kept`: the factory's own `.guardianignore` predicate,
 * with head's tree when head is not checked out [INT-6]) and existed at the
 * merge base — modified (M, and T, which `parseNameStatus` reads as
 * modified) under its own path, renamed under its old one. An added file has
 * no counterpart: its findings are introduced. Head path → base path.
 */
export function baseTargetsOf(
  entries: readonly NameStatusEntry[],
  headResultPaths: ReadonlySet<string>,
  kept: (headPath: string) => boolean,
): Map<string, string> {
  const targets = new Map<string, string>();
  for (const e of entries) {
    if (!headResultPaths.has(e.path) || !kept(e.path)) continue;
    if (e.status === 'modified') targets.set(e.path, e.path);
    else if (e.status === 'renamed' && e.oldPath !== undefined) targets.set(e.path, e.oldPath);
  }
  return targets;
}
