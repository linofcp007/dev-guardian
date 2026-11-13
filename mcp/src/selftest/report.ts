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
  if (!NEEDS_NEXT.has(control.verdict)) return undefined;
  const hooks = control.scanner === 'hooks';
  if (control.verdict === 'missing') {
    if (hooks) return "the hooks' dispatcher (hooks/guardian-hook.mjs) is not in this install: reinstall the plugin";
    return ctx.installCommand
      ? `install ${control.scanner}: ${ctx.installCommand} (or the install_toolchain tool)`
      : `install ${control.scanner} (the check_toolchain tool gives the command for this system)`;
  }
  if (control.verdict === 'silent') {
    if (hooks) {
      return "the dispatcher ran and did not answer as a working guard does: run it with GUARDIAN_HOOKS_DEBUG=1, and reinstall the plugin if mcp/dist/hooks*.js is damaged";
    }
    if (ctx.pack !== undefined) {
      return `Semgrep read the canary and ${ctx.pack} reported nothing: check that configs/semgrep/${ctx.pack} is intact (reinstall the plugin) and the Semgrep version (check_toolchain)`;
    }
    return `${control.scanner} read the canary and reported nothing: check its version (check_toolchain) and any configuration of its own on this machine`;
  }
  if (hooks) return 'run the selftest again; if it repeats, run the dispatcher with GUARDIAN_HOOKS_DEBUG=1';
  return `see the reason, fix it and run the selftest again; check_toolchain shows whether ${control.scanner} itself runs`;
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
  const { run } = report;
  const idWidth = Math.max(7, ...run.controls.map((c) => c.id.length));
  const versionWidth = Math.max(7, ...run.controls.map((c) => (c.scanner_version ?? '-').length));
  const lines: string[] = [];
  lines.push(`dev-guardian selftest — dev-guardian ${run.plugin_version} on ${run.platform}, ${run.ran_at}`);
  lines.push('');
  lines.push(`  ${pad('CONTROL', idWidth)}  ${pad('VERDICT', 16)}  ${pad('VERSION', versionWidth)}  NOTE`);
  for (const c of run.controls) {
    lines.push(`  ${pad(c.id, idWidth)}  ${pad(c.verdict, 16)}  ${pad(c.scanner_version ?? '-', versionWidth)}  ${controlNote(c)}`.trimEnd());
    if (c.next !== undefined) lines.push(`  ${pad('', idWidth)}  next: ${c.next}`);
  }
  lines.push('');
  lines.push(summaryLine(run));
  if (report.interrupted === true) lines.push('Interrupted: the controls not reached are unverified, and nothing was saved.');
  if (run.no_canary.length > 0) {
    lines.push(`Installed, with no canary — not verified by this command: ${run.no_canary.join(', ')}.`);
  }
  lines.push(HOOKS_NOTE);
  lines.push('A canary proves that a control sees on this machine, not that it sees everything.');
  if (report.workspace !== undefined) {
    lines.push(
      report.workspace.kept
        ? `Kept, as asked: ${report.workspace.path}`
        : `NOT REMOVED — the temporary directory is still there: ${report.workspace.path}${report.workspace.note !== undefined ? ` (${report.workspace.note})` : ''}`,
    );
  }
  for (const left of report.leftovers ?? []) lines.push(`An earlier selftest left its temporary directory behind (not removed by this run): ${left}`);
  const saved = report.saved;
  if (saved !== undefined) {
    if (saved.saved) lines.push(`Saved in ${saved.dir ?? 'the data directory'}.`);
    else if (saved.skipped === 'no-save') lines.push('Not saved (--no-save).');
    else if (saved.skipped !== 'interrupted') lines.push(`Not saved: ${saved.note ?? 'the data directory could not be written'}.`);
    if (saved.history_note !== undefined) lines.push(`History: ${saved.history_note}.`);
  }
  return `${lines.join('\n')}\n`;
}

/** The one JSON document `--json` writes: the run's own fields, and what happened around it. */
export function renderJson(report: SelftestReport): string {
  const { run, ...around } = report;
  return `${JSON.stringify({ ...run, ...around }, null, 2)}\n`;
}

/** The saved runs, newest first: one block per run, a line per control. */
export function renderHistory(runs: readonly SelftestRun[], problem?: string): string {
  const lines: string[] = [];
  if (problem !== undefined) lines.push(`${problem}.`, '');
  if (runs.length === 0) {
    lines.push('No selftest has been saved on this machine.');
    return `${lines.join('\n')}\n`;
  }
  for (const run of runs) {
    lines.push(`${run.ran_at}  dev-guardian ${run.plugin_version} on ${run.platform} — ${summaryLine(run)} (exit ${run.exit_code})`);
    const idWidth = Math.max(7, ...run.controls.map((c) => c.id.length));
    for (const c of run.controls) {
      lines.push(`  ${pad(c.id, idWidth)}  ${pad(c.verdict, 16)}  ${c.scanner_version ?? '-'}${c.regressed === true ? '  REGRESSED' : ''}`);
    }
    lines.push('');
  }
  return `${lines.join('\n')}`;
}

/** The same history as one JSON document. */
export function renderHistoryJson(runs: readonly SelftestRun[], problem?: string): string {
  return `${JSON.stringify({ schema: 1, ...(problem !== undefined ? { problem } : {}), runs }, null, 2)}\n`;
}
