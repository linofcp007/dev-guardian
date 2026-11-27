/**
 * The files whose taint analysis did not finish when the baseline was
 * recorded — `taint_incomplete` in `.guardian/baseline.json` (3.18.0).
 *
 * ---- Why ------------------------------------------------------------------
 *
 * Semgrep's taint analysis gives up on a function past its budget (a
 * `Fixpoint timeout`, `runners/semgrepReport.ts`), and what it had not found
 * there is missing from that run. Even at `--jobs 1` a few heavy functions
 * time out, and a baseline recorded on a slower or busier machine, or with
 * `semgrep.jobs` above 1, lacks findings a later run reports: the gate called
 * them new — 16 new mediums on the baseline's own commit, every one in a file
 * the baseline's run had named as timed out (127 of 127 flickering findings
 * measured over 5 runs sat in such a file).
 *
 * ---- The rule -------------------------------------------------------------
 *
 * `baseline update` records each file a Semgrep run of its scan named as
 * fixpoint-timed-out, with the file's git object id after the run (`blob`:
 * `changedSince.ts#gitBlobsOf`, the gate's one "unchanged as git stores it"
 * — line endings as git stores them, the index's flags never consulted).
 * Later, a Semgrep finding new to the baseline in such a file is not counted
 * as new while the file still hashes to that blob: OSS Semgrep's analysis is
 * intrafile (dev-guardian never passes `--pro`), so a finding in content the
 * change did not touch is not the change's — flicker, or what a rule, a pack
 * or a Semgrep update now reports in old code. Such a finding is still listed
 * (`taintIncompleteAtBaseline`, the human report, the JSON).
 *
 * `pack_only`: every timeout in the file was the plugin's own pack's
 * (`FIXPOINT_TIMEOUT_PACK_TYPE`), so only a pack rule's finding is read
 * against it — two rules, two predicates, as history keeps (file, pack rule)
 * pairs (`history/runCompare.ts`). A project rule spelled like a pack rule
 * reads as the pack's: unchanged code only, so acceptable.
 *
 * ---- What it never covers -------------------------------------------------
 *
 *   - a finding of any other scanner, or one whose file is not recorded;
 *   - a file whose content changed — committed or not, an index flag or not —
 *     or that is not a regular file (a link, a FIFO), or gone;
 *   - a renamed file: its findings are judged again under the new path;
 *   - no git repository, or git that cannot hash: nothing is recorded, and
 *     nothing is relaxed — "could not compare" is never "unchanged";
 *   - a file written during the scan (its mtime at or after the scan's
 *     start): never recorded, so a recorded blob is one the scan read;
 *   - a record that is not exactly one (`baseline.ts#taintIncompleteRecordsOf`).
 *
 * The one writer who could turn it on a change's own code is one who can
 * already add a baseline entry: a pull request editing the tree's
 * `baseline.json`, which `--baseline-ref` closes — and dev-spec-driven guards
 * that file locally.
 *
 * ---- Cost -----------------------------------------------------------------
 *
 * Recording: one `rev-parse` and `ceil(files / 100)` `hash-object` calls,
 * for the 2-4 files a `--jobs 1` run leaves. At the gate: none unless a
 * Semgrep finding lies in a recorded file — one boolean, no second matcher —
 * then the same, over every record at once.
 */

import { lstatSync } from 'node:fs';
import { join } from 'node:path';
import { git, type GitRunner } from '../runners/git.js';
import { pluginPackRuleIds } from '../runners/semgrepConfigs.js';
import { FIXPOINT_TIMEOUT_PACK_TYPE, FIXPOINT_TIMEOUT_TYPE } from '../runners/semgrepReport.js';
import { SEMGREP_TOOL_NAME } from '../runners/scannerParsers/semgrep.js';
import type { Finding } from '../types.js';
import { isTaintIncompleteFile, taintIncompleteRecordsOf } from './baseline.js';
import { gitBlobsOf } from './changedSince.js';
import { normalizeAcceptedPath } from './gate.js';
import type { ScanStepResult, TaintIncompleteRecord } from './types.js';

/** A file whose taint analysis a Semgrep run of the scan gave up on, and whether only the plugin's packs timed out there. */
export interface TaintIncompleteFile {
  file: string;
  packOnly: boolean;
}

/**
 * What the gate reads against the baseline's records (`GateInput.taintIncomplete`):
 * the recorded files still unchanged, and the plugin's pack rule ids for a
 * `packOnly` one.
 */
export interface GateTaintIncomplete {
  unchanged: readonly TaintIncompleteFile[];
  packRuleIds: ReadonlySet<string>;
}

/** The injected effects, for the tests: git, and a file's mtime (null when it cannot be read). */
export interface TaintIncompleteIo {
  run?: GitRunner;
  mtimeMs?: (absolutePath: string) => number | null;
}

/**
 * Every file a Semgrep run of the scan that ended `ok` named as
 * fixpoint-timed-out — from each step's `tools_run` (a run's whole
 * `partially_parsed`, the pack's own type included, which `partial_parses`
 * leaves out), sorted by path. A file outside the project, or in a spelling
 * that is not one project file, is left out: nothing is recorded for it.
 */
export function taintIncompleteOf(steps: readonly ScanStepResult[]): TaintIncompleteFile[] {
  const packOnly = new Map<string, boolean>();
  for (const step of steps) {
    if (!step.ran) continue;
    for (const run of step.tools_run) {
      if (run.name !== SEMGREP_TOOL_NAME || run.status !== 'ok') continue;
      for (const pp of run.partially_parsed ?? []) {
        const pack = pp.type === FIXPOINT_TIMEOUT_PACK_TYPE;
        if (!pack && pp.type !== FIXPOINT_TIMEOUT_TYPE) continue;
        if (typeof pp.file !== 'string') continue;
        const file = normalizeAcceptedPath(pp.file);
        if (!isTaintIncompleteFile(file)) continue;
        packOnly.set(file, (packOnly.get(file) ?? true) && pack);
      }
    }
  }
  return [...packOnly]
    .map(([file, only]) => ({ file, packOnly: only }))
    .sort((a, b) => (a.file < b.file ? -1 : a.file > b.file ? 1 : 0));
}

/** Whether `projectPath` is inside a git work tree — the only place a blob means "as git stores it". */
async function inWorkTree(projectPath: string, run: GitRunner): Promise<boolean> {
  const r = await run(projectPath, ['rev-parse', '--is-inside-work-tree']);
  return r.exitCode === 0 && r.stdout.trim() === 'true';
}

function defaultMtimeMs(path: string): number | null {
  try {
    return lstatSync(path).mtimeMs;
  } catch {
    return null;
  }
}

/**
 * The records `baseline update` writes for its scan's `steps`
 * ({@link taintIncompleteOf}): each file's blob after the scan, when the
 * file was last written before `scanStartedAtMs` — one written during the
 * scan is left out and named in `changedDuringScan`, since its blob may not
 * be what the scan read. None outside a git work tree, for a file git cannot
 * hash (not a regular file, gone), or when git fails.
 */
export async function recordTaintIncomplete(
  projectPath: string,
  steps: readonly ScanStepResult[],
  scanStartedAtMs: number,
  io: TaintIncompleteIo = {},
): Promise<{ records: TaintIncompleteRecord[]; changedDuringScan: string[] }> {
  const files = taintIncompleteOf(steps);
  const none = { records: [], changedDuringScan: [] };
  if (files.length === 0) return none;
  const run = io.run ?? git;
  if (!(await inWorkTree(projectPath, run))) return none;
  const mtimeMs = io.mtimeMs ?? defaultMtimeMs;
  const stable: TaintIncompleteFile[] = [];
  const changedDuringScan: string[] = [];
  for (const f of files) {
    const mtime = mtimeMs(join(projectPath, f.file));
    if (mtime === null) continue;
    if (mtime >= scanStartedAtMs) changedDuringScan.push(f.file);
    else stable.push(f);
  }
  if (stable.length === 0) return { records: [], changedDuringScan };
  const hashed = await gitBlobsOf(projectPath, stable.map((f) => f.file), run);
  if ('error' in hashed) return { records: [], changedDuringScan };
  const records = stable.flatMap((f): TaintIncompleteRecord[] => {
    const blob = hashed.blobs.get(f.file);
    return typeof blob === 'string' ? [{ tool: 'semgrep', file: f.file, blob, ...(f.packOnly ? { pack_only: true as const } : {}) }] : [];
  });
  // The reader's own test, so a record written is a record read.
  return { records: taintIncompleteRecordsOf(records), changedDuringScan };
}

/**
 * What the gate reads against `records` (the baseline's): the recorded files
 * whose content still hashes to their recorded blob — or undefined, and
 * nothing relaxed, when there are none, when no Semgrep finding lies in a
 * recorded file (nothing to relax, and git is not asked), outside a git work
 * tree, or when git cannot hash.
 */
export async function unchangedTaintIncomplete(
  projectPath: string,
  records: readonly TaintIncompleteRecord[],
  findings: readonly Finding[],
  io: Pick<TaintIncompleteIo, 'run'> = {},
): Promise<GateTaintIncomplete | undefined> {
  if (records.length === 0) return undefined;
  const recorded = new Set(records.map((r) => r.file));
  const inRecorded = findings.some(
    (f) => f.tool === SEMGREP_TOOL_NAME && f.file_path !== undefined && recorded.has(normalizeAcceptedPath(f.file_path)),
  );
  if (!inRecorded) return undefined;
  const run = io.run ?? git;
  if (!(await inWorkTree(projectPath, run))) return undefined;
  const hashed = await gitBlobsOf(projectPath, [...recorded], run);
  if ('error' in hashed) return undefined;
  const unchanged = records
    .filter((r) => hashed.blobs.get(r.file) === r.blob)
    .map((r) => ({ file: r.file, packOnly: r.pack_only === true }));
  return unchanged.length > 0 ? { unchanged, packRuleIds: pluginPackRuleIds() } : undefined;
}
