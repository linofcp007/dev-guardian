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
import { isScopedScan } from '../history/scanRoles.js';
import { canonicalPath, resolveProjectPath } from '../platform/projectPath.js';
import { resolveScriptsDir } from '../platform/scriptsDir.js';
import { dedupeFindings } from '../runners/findingMerge.js';
import { probeShell } from '../platform/shellProbe.js';
import { GuardianDatabase } from '../storage/db.js';
import { runMigrations } from '../storage/migrations/runner.js';
import { Storage } from '../storage/index.js';
import { TOOLS } from '../tools/index.js';
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
export const SCAN_SEQUENCE = [
    'detect_stack',
    'security_scan_full',
    'license_compatibility',
    'map_attack_surface',
    'scan_dast',
    'validate_finding',
];
const TEMP_DIR_PREFIX = 'dev-guardian-ci-';
export async function runScans(opts) {
    const tmpDir = await mkdtemp(join(tmpdir(), TEMP_DIR_PREFIX));
    try {
        const db = new GuardianDatabase(join(tmpDir, 'guardian.db'));
        try {
            runMigrations(db);
            const storage = new Storage(db);
            const shell = await probeShell(storage.runtimeMeta);
            const ctx = {
                storage,
                shell,
                scriptsDir: resolveScriptsDir(),
                // CI has no progress channel to report to — a no-op sink, same
                // ProgressNotifier shape server.ts wires to the real MCP transport.
                progressNotifier: { send: () => { } },
            };
            const steps = [];
            for (const name of buildSequence(opts)) {
                steps.push(await runStep(name, buildInput(name, opts), ctx));
            }
            return { findings: collectFindings(storage, opts.projectPath), steps };
        }
        finally {
            try {
                db.close();
            }
            catch {
                /* already closed, or never fully opened — nothing left to release */
            }
        }
    }
    finally {
        try {
            await rm(tmpDir, { recursive: true, force: true });
        }
        catch {
            /* best-effort cleanup; a stray temp dir is a leak, not a correctness bug */
        }
    }
}
/** `SCAN_SEQUENCE`, minus `scan_dast` when the caller gave no base url. */
function buildSequence(opts) {
    if (opts.baseUrl !== undefined)
        return SCAN_SEQUENCE;
    return SCAN_SEQUENCE.filter((name) => name !== 'scan_dast');
}
/** Every step shares `project_path`; `scan_dast` additionally needs the
 *  target it is meant to probe, and `security_scan_full` `local_only`. */
function buildInput(name, opts) {
    if (name === 'security_scan_full' && opts.localOnly === true) {
        return { project_path: opts.projectPath, local_only: true };
    }
    if (name !== 'scan_dast')
        return { project_path: opts.projectPath };
    const input = {
        project_path: opts.projectPath,
        base_url: opts.baseUrl,
    };
    if (opts.authorizedTarget !== undefined)
        input.authorized_target = opts.authorizedTarget;
    return input;
}
/**
 * Run one step. Every way it can end up NOT contributing a result —
 * refusal (`ok: false`), an unregistered name, or a thrown exception — is
 * turned into `ran: false` with a `reason` and returned rather than thrown,
 * so the caller's loop never has to special-case this step to keep going.
 */
async function runStep(name, input, ctx) {
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
    }
    catch (e) {
        return refusedStep(name, e instanceof Error ? e.message : String(e));
    }
}
function refusedStep(tool, reason) {
    return { tool, ran: false, reason, tools_run: [], missing_tools: [] };
}
function toToolRunArray(value) {
    return Array.isArray(value) ? value : [];
}
function toStringArray(value) {
    return Array.isArray(value) ? value : [];
}
/**
 * Every finding this run persisted for the scanned project, read back out of
 * the ephemeral database rather than out of any step's return payload (see
 * the module doc comment): each UNSCOPED row of THIS project, whatever its
 * status.
 *
 * - Project-scoped (Task 24): it used to be every row of `listHistory(50)`,
 *   whatever project each belonged to. The database being fresh narrows what
 *   can be in it, not what a step may write there — a row filed under
 *   another path is not this project's measurement. Resolved the way every
 *   step resolved the `project_path` it was given, so both sides compare the
 *   same spelling.
 * - Never a scoped row (`meta.scope`): part of the project, whose silence
 *   about the rest is not evidence — and whose findings the whole-project
 *   rows already hold.
 * - Status-agnostic, deliberately NOT the interactive open set (fix round 1,
 *   I1): the open set reads completed rows only and falls back to an older
 *   one, which a throwaway database never has. A `failed` row often carries
 *   real findings — scan_iac fails the whole row when one pass exits
 *   non-zero, yet keeps Trivy's results — and `gate.ts`'s rule is that a
 *   real regression (GATE_FAILED) outranks a coverage gap (INCOMPLETE_SCAN),
 *   never hides behind it. The gap itself still reaches the gate through
 *   each step's `tools_run` / `missing_tools`.
 *
 * Deduplicated across rows by `runners/findingMerge.ts` (an orchestrated
 * `security_full` parent repeats its children's findings; two scanners can
 * report one issue): the same issue must not be counted twice by the gate.
 */
function collectFindings(storage, projectPath) {
    const project = scannedProject(projectPath);
    const rows = storage.scans.listHistoryForProject(project, storage.scans.countForProject(project));
    const all = [];
    for (const scan of rows) {
        if (isScopedScan(scan))
            continue;
        all.push(...storage.findings.listByScan(scan.scan_id));
    }
    return dedupeFindings(all);
}
/** `resolveProjectPath`'s spelling of `projectPath`, or its canonical form when it no longer resolves. */
function scannedProject(projectPath) {
    try {
        return resolveProjectPath(projectPath).path;
    }
    catch {
        return canonicalPath(projectPath);
    }
}
//# sourceMappingURL=runScans.js.map