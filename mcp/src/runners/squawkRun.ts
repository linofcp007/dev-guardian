/**
 * squawk over the changed `.sql` files of a review whose reviewed tree opts in with a ROOT `.squawk.toml`
 * (`tools/reviewPr.ts`): squawk lints Postgres migrations for locks and rewrites that block a table that holds data.
 * Opt-in only, by squawk's own file: a migration folder's name or another tool's dialect setting is no reason to
 * read every `.sql` file as Postgres, and a generated migration (Prisma's, drizzle's) is what squawk's style rules
 * flag first. Without the file, no squawk entry anywhere: a review is what it was.
 *
 * Read from squawk 2.71.0's own source (crates/squawk/src: main.rs, cmd.rs, file_finding.rs, reporter.rs):
 *
 *   - `--reporter json` writes ONE JSON array of violations to stdout — `{ file, line, column, level, message, note,
 *     help, rule_name, column_end, line_end }`, `line` counted from 0 (`scannerParsers/squawk.ts`).
 *   - Exit 0 is no violation, 1 is violations — and also an error (an unreadable file, a broken config), which
 *     writes no report to stdout. A run is therefore judged by its stdout: a JSON array is a report, anything else
 *     a failure, named by its first stderr line.
 *   - Each path is a glob pattern (`glob::glob`): a file name holding `*`, `?`, `[` or `]` is handed escaped
 *     (`[*]`), so it names only itself.
 *   - The config's `excluded_paths` apply to the files handed too, so `--no-error-on-unmatched-pattern`: a batch
 *     whose every file is excluded exits 0 and prints nothing — no violation.
 *   - `--config <root .squawk.toml>`: without it squawk looks for one from its working directory upwards, past the
 *     project. A nested `.squawk.toml` is never read.
 *   - A file it could not parse is a `syntax-error` violation: never a finding — the rest of the file was not
 *     checked —, the file is named partial and the run is a gap.
 *
 * Its environment is the test command's allowlist (`fixpr/testCommandEnv.ts`), `extendEnv: false`: no token
 * reaches it (its `upload-to-github` command reads one; it is never run here).
 */

import type { PartialParse, ToolRun } from '../types.js';
import { testCommandEnv } from '../fixpr/testCommandEnv.js';
import { projectPathKind } from '../platform/projectFs.js';
import { batchArgs } from './argBatches.js';
import { git, parseNameStatus } from './git.js';
import { runProcess } from './processRunner.js';
import { nameRepoConfig } from './repoConfig.js';
import { asArray, getString, parseInputAsJson } from './scannerParsers/index.js';
import { SQUAWK_SYNTAX_ERROR_RULE } from './scannerParsers/squawk.js';

/** The `tools_run` name of the squawk pass. */
export const SQUAWK = 'squawk';

/** squawk's own configuration file — the opt-in, at the root of the reviewed tree only. */
const SQUAWK_CONFIG = '.squawk.toml';

/** A changed file squawk is handed (with the opt-in). */
export function isSqlFile(path: string): boolean {
  return /\.sql$/i.test(path);
}

/**
 * Whether the reviewed tree opts in: `absent` (no root `.squawk.toml`: no squawk), `file`, or `unusable` (a
 * link out of the project, a directory, a FIFO — named, never read).
 */
export function squawkOptIn(scanRoot: string): 'absent' | 'file' | 'unusable' {
  const kind = projectPathKind(scanRoot, SQUAWK_CONFIG);
  return kind === 'absent' ? 'absent' : kind === 'file' ? 'file' : 'unusable';
}

/** A path as squawk's glob reads it literally: each of `*`, `?`, `[`, `]` in a class of its own. */
function globLiteral(path: string): string {
  return path.replace(/[*?[\]]/g, (c) => `[${c}]`);
}

interface SquawkPass {
  toolRun: ToolRun;
  /** A gap too (`missing_tools`): a file squawk could not parse, or a run that failed. */
  missing: boolean;
  /** Each batch's JSON report (stdout), when it wrote one. */
  reports: string[];
  cancelled: boolean;
}

/** Bytes of one batch's report kept: a violation is a few hundred bytes. */
const REPORT_CAP_BYTES = 50 * 1024 * 1024;

/**
 * squawk over `files` (project-relative `.sql` files present in `scanRoot`, which opts in), one run per
 * command-line batch, `cwd` the reviewed tree.
 */
export async function squawkMigrations(args: {
  scanRoot: string;
  files: readonly string[];
  signal: AbortSignal;
  onLog?: (line: string) => void;
}): Promise<SquawkPass> {
  const fixed = ['--reporter', 'json', '--config', SQUAWK_CONFIG, '--no-error-on-unmatched-pattern', '--'];
  const batches = batchArgs(args.files.map(globLiteral), { command: SQUAWK, fixedArgs: fixed });
  const env = testCommandEnv();
  const reports: string[] = [];
  const failures: string[] = [];
  const partial: PartialParse[] = [];
  let cancelled = false;
  for (const [i, batch] of batches.entries()) {
    if (args.signal.aborted) {
      cancelled = true;
      break;
    }
    const run = await runProcess({
      command: 'squawk',
      args: [...fixed, ...batch],
      cwd: args.scanRoot,
      env,
      extendEnv: false,
      signal: args.signal,
      ...(args.onLog ? { onLog: args.onLog } : {}),
      stdoutCapBytes: REPORT_CAP_BYTES,
    });
    const at = batches.length > 1 ? `batch ${String(i + 1)}/${String(batches.length)}: ` : '';
    if (run.outcome === 'cancelled') {
      cancelled = true;
      break;
    }
    if (run.outcome !== 'completed' && run.outcome !== 'failed') {
      failures.push(`${at}did not finish (${run.outcome})`);
      continue;
    }
    const report = judgeSquawk(run);
    if ('failure' in report) {
      failures.push(`${at}${report.failure}`);
      continue;
    }
    if (report.text !== null) reports.push(report.text);
    for (const p of report.partial) if (!partial.some((q) => q.file === p.file)) partial.push(p);
  }
  const described = `${String(args.files.length)} changed .sql file(s)${batches.length > 1 ? ` in ${String(batches.length)} batches` : ''}`;
  if (failures.length > 0 || cancelled) {
    return {
      toolRun: { name: SQUAWK, status: 'failed', reason: cancelled && failures.length === 0 ? 'cancelled' : `${described}: ${failures.join('; ')}` },
      missing: true,
      reports,
      cancelled,
    };
  }
  const toolRun: ToolRun = { name: SQUAWK, status: 'ok', reason: `${described} checked` };
  if (partial.length > 0) {
    const shown = partial.slice(0, 5).map((p) => p.file).join(', ');
    toolRun.reason += `; partial: ${String(partial.length)} file(s) squawk could not parse past an error (${shown}${partial.length > 5 ? ', …' : ''})`;
    toolRun.partially_parsed = partial;
  }
  // The root .squawk.toml it was handed, named (`runners/repoConfig.ts`).
  return { toolRun: await nameRepoConfig(toolRun, args.scanRoot, SQUAWK), missing: partial.length > 0, reports, cancelled };
}

/** One batch's run: its report (null: every file excluded, nothing printed) and the files it could not parse, or why it failed. */
function judgeSquawk(run: { exitCode: number | null; stdout: string; stderr: string }): { text: string | null; partial: PartialParse[] } | { failure: string } {
  const why = (): string => run.stderr.split(/\r?\n/).map((l) => l.trim()).find((l) => l !== '') ?? 'no report was written';
  if (run.exitCode !== 0 && run.exitCode !== 1) return { failure: `exit ${String(run.exitCode)}: ${why()}` };
  if (run.stdout.trim() === '') return run.exitCode === 0 ? { text: null, partial: [] } : { failure: `exit 1: ${why()}` };
  const parsed = parseInputAsJson(run.stdout);
  if (!Array.isArray(parsed)) return { failure: `exit ${String(run.exitCode)}: no readable report (${why()})` };
  const partial: PartialParse[] = [];
  for (const v of asArray(parsed)) {
    if (getString(v, 'rule_name') !== SQUAWK_SYNTAX_ERROR_RULE) continue;
    const file = getString(v, 'file');
    if (file !== undefined && !partial.some((p) => p.file === file)) {
      partial.push({ file, type: 'Syntax error', message: getString(v, 'message') ?? 'could not parse' });
    }
  }
  return { text: run.stdout, partial };
}

/**
 * What this diff does to the opt-in, said where a quiet result is read: an edit of the root `.squawk.toml` decides
 * what squawk reports (an exclusion added there hides a finding), and a deletion turns squawk off — the reverse of
 * `.trivyignore`, whose deletion means more scanning. A deletion is invisible to the changed-file list (added,
 * copied, modified and renamed only), so the change is read from git's own listing of `base...head`.
 */
export async function squawkConfigWarning(cwd: string, base: string, head: string): Promise<string | null> {
  const r = await git(cwd, ['diff', '-z', '--name-status', '--relative', '--no-renames', `${base}...${head}`, '--', SQUAWK_CONFIG]);
  if (r.exitCode !== 0) return null;
  const entry = parseNameStatus(r.stdout).find((e) => e.path === SQUAWK_CONFIG);
  if (entry === undefined) return null;
  if (entry.status === 'deleted') {
    return (
      `This diff removes ${SQUAWK_CONFIG}, which turns squawk on: after it, no review runs squawk over this project's ` +
      'migrations. Review that change: a removal hides every lock and rewrite squawk would report, it does not fix them.'
    );
  }
  return (
    `This diff changes ${SQUAWK_CONFIG}, which squawk honours: a rule or path it excludes is not reported (this review ` +
    "applied the reviewed tree's copy). Review that change before trusting a quiet migration result: an exclusion " +
    'added there hides a finding, it does not fix it.'
  );
}
