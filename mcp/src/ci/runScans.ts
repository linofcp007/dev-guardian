/**
 * Ordered scan pipeline for the headless CI entry point.
 *
 * Builds an ephemeral `PluginContext` — a throwaway SQLite database under a
 * fresh `mkdtemp` directory, a probed shell, a no-op progress notifier — and
 * drives it through the SAME tool handlers `server.ts` registers for an
 * interactive MCP session (`TOOLS.find(t => t.name === …).handler(...)`).
 * That is `host-rules/AGENTS.md`'s own rule — "invoke the MCP tools rather
 * than shelling out to the scanners" — applied to the CLI itself: there is
 * no second implementation of any scan, so when e.g. `scan_sast` changes, CI
 * changes with it (design doc §3).
 *
 * Order is not cosmetic (design doc §3): `map_attack_surface` persists the
 * route inventory that `scan_dast` and `validate_finding` both refuse
 * without. `SCAN_SEQUENCE` documents the full order; `scan_dast` is included
 * only when the caller supplies a base url (design doc §7 — starting the
 * application is a separate, explicit capability, deliberately withheld from
 * the MCP tool itself).
 *
 * A step that refuses (`ok: false`), throws, or names a tool this build does
 * not register is RECORDED, never allowed to abort the run: the remaining
 * steps still execute, and the gap feeds the coverage signal `gate.ts`
 * reads. Stopping at the first gap would report less than continuing and
 * saying what was missed.
 *
 * Findings are read back OUT of the ephemeral database after every step has
 * run, never out of a step's own return payload — the tools that produce
 * findings (`security_scan_full`, `scan_dast`) already persist them as a
 * side effect of their own handlers, the same way they do for an
 * interactive MCP session.
 */

import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { PluginContext } from '../context.js';
import { resolveScriptsDir } from '../platform/scriptsDir.js';
import { probeShell } from '../platform/shellProbe.js';
import { GuardianDatabase } from '../storage/db.js';
import { runMigrations } from '../storage/migrations/runner.js';
import { Storage } from '../storage/index.js';
import { TOOLS } from '../tools/index.js';
import type { Finding, ToolRun } from '../types.js';
import type { ScanStepResult } from './types.js';

// Side-effect registration of every tool — populates TOOLS. See
// registerAll.ts's own doc comment; server.ts imports it for the same reason,
// and this module needs the same full registry to look tools up by name.
import '../registerAll.js';

/**
 * The full documented order (design doc §3). `scan_dast` always appears
 * here: it is `buildSequence` below that removes it for a run with no base
 * url, never this constant — so `SCAN_SEQUENCE` always names "the order" in
 * full, and any given run's actual sequence is a sub-sequence of it.
 *
 * Exported so the test asserts the implementation and the test share one
 * constant, but the ORDER test itself must assert a literal expected array,
 * not this constant — asserting against `SCAN_SEQUENCE` would pass even if
 * this were defined in the wrong order.
 */
export const SCAN_SEQUENCE: readonly string[] = [
  'detect_stack',
  'security_scan_full',
  'license_compatibility',
  'map_attack_surface',
  'scan_dast',
  'validate_finding',
];

/** Far more than the at-most-two scan rows (security_scan_full, scan_dast)
 *  this pipeline can create in one run — generous on purpose so a future
 *  step that persists additional scan rows doesn't silently truncate. */
const SCAN_HISTORY_LIMIT = 50;

const TEMP_DIR_PREFIX = 'dev-guardian-ci-';

export interface RunScansOptions {
  projectPath: string;
  /** Passed to scan_dast when present; absent means the DAST step is skipped. */
  baseUrl?: string;
  authorizedTarget?: boolean;
}

export interface RunScansResult {
  findings: Finding[];
  steps: ScanStepResult[];
}

export async function runScans(opts: RunScansOptions): Promise<RunScansResult> {
  const tmpDir = await mkdtemp(join(tmpdir(), TEMP_DIR_PREFIX));
  try {
    const db = new GuardianDatabase(join(tmpDir, 'guardian.db'));
    try {
      runMigrations(db);
      const storage = new Storage(db);
      const shell = await probeShell(storage.runtimeMeta);
      const ctx: PluginContext = {
        storage,
        shell,
        scriptsDir: resolveScriptsDir(),
        // CI has no progress channel to report to — a no-op sink, same
        // ProgressNotifier shape server.ts wires to the real MCP transport.
        progressNotifier: { send: () => {} },
      };

      const steps: ScanStepResult[] = [];
      for (const name of buildSequence(opts)) {
        steps.push(await runStep(name, buildInput(name, opts), ctx));
      }

      return { findings: collectFindings(storage), steps };
    } finally {
      try {
        db.close();
      } catch {
        /* already closed, or never fully opened — nothing left to release */
      }
    }
  } finally {
    try {
      await rm(tmpDir, { recursive: true, force: true });
    } catch {
      /* best-effort cleanup; a stray temp dir is a leak, not a correctness bug */
    }
  }
}

/** `SCAN_SEQUENCE`, minus `scan_dast` when the caller gave no base url. */
function buildSequence(opts: RunScansOptions): readonly string[] {
  if (opts.baseUrl !== undefined) return SCAN_SEQUENCE;
  return SCAN_SEQUENCE.filter((name) => name !== 'scan_dast');
}

/** Every step shares `project_path`; `scan_dast` additionally needs the
 *  target it is meant to probe. */
function buildInput(name: string, opts: RunScansOptions): Record<string, unknown> {
  if (name !== 'scan_dast') return { project_path: opts.projectPath };

  const input: Record<string, unknown> = {
    project_path: opts.projectPath,
    base_url: opts.baseUrl,
  };
  if (opts.authorizedTarget !== undefined) input.authorized_target = opts.authorizedTarget;
  return input;
}

/**
 * Run one step. Every way it can end up NOT contributing a result —
 * refusal (`ok: false`), an unregistered name, or a thrown exception — is
 * turned into `ran: false` with a `reason` and returned rather than thrown,
 * so the caller's loop never has to special-case this step to keep going.
 */
async function runStep(
  name: string,
  input: Record<string, unknown>,
  ctx: PluginContext,
): Promise<ScanStepResult> {
  const tool = TOOLS.find((t) => t.name === name);
  if (!tool) {
    return refusedStep(name, `no tool named '${name}' is registered`);
  }

  try {
    const result = await tool.handler(input, ctx);
    if (!result.ok) {
      return refusedStep(name, `${result.error.code}: ${result.error.message}`);
    }
    return {
      tool: name,
      ran: true,
      tools_run: toToolRunArray(result.tools_run),
      missing_tools: toStringArray(result.missing_tools),
    };
  } catch (e) {
    return refusedStep(name, e instanceof Error ? e.message : String(e));
  }
}

function refusedStep(tool: string, reason: string): ScanStepResult {
  return { tool, ran: false, reason, tools_run: [], missing_tools: [] };
}

function toToolRunArray(value: unknown): ToolRun[] {
  return Array.isArray(value) ? (value as ToolRun[]) : [];
}

function toStringArray(value: unknown): string[] {
  return Array.isArray(value) ? (value as string[]) : [];
}

/**
 * Findings this run actually persisted, read back out of the ephemeral
 * database rather than out of any step's return payload (see the module doc
 * comment). The database was created moments ago in a fresh `mkdtemp`
 * directory, so every scan row it holds belongs to this one run — no
 * project-path or "latest scan" filtering is needed to keep another run's
 * data out, unlike the equivalent reads inside an interactive MCP session.
 *
 * Deduplicated by fingerprint across scan rows (`security_scan_full` and
 * `scan_dast` each create their own): fingerprints are shared/stable across
 * scans by design (`findingsRepo.ts`'s own doc comment), so the same issue
 * reported by two steps must not be double-counted by the gate.
 */
function collectFindings(storage: Storage): Finding[] {
  const byFingerprint = new Map<string, Finding>();
  for (const scan of storage.scans.listHistory(SCAN_HISTORY_LIMIT)) {
    for (const finding of storage.findings.listByScan(scan.scan_id)) {
      byFingerprint.set(finding.fingerprint, finding);
    }
  }
  return [...byFingerprint.values()];
}
