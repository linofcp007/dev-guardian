// @ts-nocheck -- Phase 4 scaffold (dev-spec-driven): the failing tests come first; the implementation replaces these bodies.
/**
 * What a selftest prints: the table for a person, the JSON document for a
 * program, and the saved history. Pure — every function takes the result and
 * returns text.
 *
 * Nothing here is given a scanner's raw output, a path of the user's or the
 * canary secret: a control's line is its id, its verdict, the scanner's
 * version and the reason this code wrote.
 */

import type { ControlResult, SaveResult, SelftestRun } from './store.js';
import { VERDICTS, type Verdict } from './verdict.js';

/** Said in the table and in the JSON: what the hook checks prove, and what they do not. */
export const HOOKS_NOTE =
  "The hook checks prove that the installed detectors answer when the dispatcher is run; they do not prove that the host " +
  "runs it. Whether the hooks started in a session is health_status's `hooks`.";

/** What a selftest's caller prints: the run, and what happened around it. */
export interface SelftestReport {
  run: SelftestRun;
  /** The temporary directory, when it is still there: kept on request, or left because it could not be removed. */
  workspace?: { path: string; kept: boolean; note?: string };
  saved?: SaveResult & { skipped?: 'no-save' | 'interrupted' };
  /** Cut short by a signal: the controls not reached are `unverified`, and nothing was saved. */
  interrupted?: boolean;
  /** Earlier temporary directories of a selftest that never removed its own: said, never removed here. */
  leftovers?: string[];
}

/** The verdicts a reader is told what to do about. */
const NEEDS_NEXT: ReadonlySet<Verdict> = new Set<Verdict>(['silent', 'unverified', 'missing']);

export interface NextStepContext {
  /** The install command for a missing scanner, when the catalogue has one. */
  installCommand?: string | null;
  /** `semgrep-pack`: the pack's file name. */
  pack?: string;
}

/**
 * What to check next for a control that did not detect: one line, for the
 * verdicts that ask for one ({@link NEEDS_NEXT}); `undefined` for the rest.
 */
export function nextStepFor(control: Pick<ControlResult, 'id' | 'scanner' | 'verdict'>, ctx: NextStepContext = {}): string | undefined {
  throw new Error('selftest: not implemented');
}

const pad = (text: string, width: number): string => (text.length >= width ? text : text + ' '.repeat(width - text.length));

function summaryLine(run: SelftestRun): string {
  const parts = VERDICTS.filter((v) => v !== 'no_canary' && run.summary[v] > 0).map((v) => `${run.summary[v]} ${v}`);
  return `${run.controls.length} control${run.controls.length === 1 ? '' : 's'}: ${parts.length > 0 ? parts.join(', ') : 'none ran'}.`;
}

function controlNote(c: ControlResult): string {
  const notes: string[] = [];
  if (c.regressed === true) {
    notes.push(`REGRESSED — detected in the run before this one${c.changed && c.changed.length > 0 ? `; changed: ${c.changed.join(', ')}` : '; nothing recorded changed'}`);
  }
  if (c.reason !== undefined) notes.push(c.reason);
  return notes.join(' — ');
}

/** The table a person reads: one line per control, the summary, the hooks' note, and where it was saved. */
export function renderTable(report: SelftestReport): string {
  throw new Error('selftest: not implemented');
}

/** The one JSON document `--json` writes: the run's own fields, and what happened around it. */
export function renderJson(report: SelftestReport): string {
  throw new Error('selftest: not implemented');
}

/** The saved runs, newest first: one block per run, a line per control. */
export function renderHistory(runs: readonly SelftestRun[], problem?: string): string {
  throw new Error('selftest: not implemented');
}

/** The same history as one JSON document. */
export function renderHistoryJson(runs: readonly SelftestRun[], problem?: string): string {
  throw new Error('selftest: not implemented');
}
