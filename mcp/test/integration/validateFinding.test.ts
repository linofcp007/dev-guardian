/**
 * Integration tests for `validate_finding` — the orchestrator, its refusals,
 * its persistence and its summary contract.
 *
 * The refusal paths are the highest-value tests here. "This project is not a
 * usable path", "no surface snapshot exists", "the fingerprint you named is
 * not open" and "there are no open findings at all" are FOUR different facts
 * and must read as four different results. Every one of them collapses into
 * the same shape under the plausible-wrong implementation — an empty batch —
 * and an empty batch reads as "nothing to worry about", which is the exact
 * falsehood this feature exists to prevent.
 *
 * Two tests carry more weight than the rest:
 *
 *   - the path-convention end-to-end (`describe('path conventions')`). The
 *     snapshot's `routes[].file` is absolute + native-separator while its
 *     `imports[]` are project-relative POSIX. An orchestrator that does not
 *     hand the provider a project root leaves those two sides incomparable,
 *     no root matches any graph node, and EVERY finding comes back negative —
 *     universally, silently, with no error anywhere. That bug has already
 *     appeared twice in this feature.
 *
 *   - the staleness test (`describe('staleness')`). A verdict computed
 *     against tree N says nothing once the code moves. The wrong
 *     implementation stamps the CURRENT working-tree hash on the row, which
 *     makes a verdict derived from a stale snapshot read as fresh forever.
 */

import { afterAll, afterEach, beforeEach, describe, expect, it } from 'vitest';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import type { PluginContext } from '../../src/context.js';
import { GuardianDatabase as Database } from '../../src/storage/db.js';
import { Storage } from '../../src/storage/index.js';
import { makeTempDir, cleanupTempDirs } from '../helpers/tempDir.js';

afterAll(cleanupTempDirs);
import { runMigrations } from '../../src/storage/migrations/runner.js';
import { TOOLS } from '../../src/tools/index.js';
import { computeTreeHash } from '../../src/treeHash/computeTreeHash.js';
import type {
  AttackSurfaceSnapshot,
  CoverageEntry,
  Finding,
  RouteRecord,
  ScanType,
} from '../../src/types.js';
import type { FindingValidation } from '../../src/validate/types.js';
import '../../src/tools/validateFinding.js';

/* ------------------------------------------------------------------ */
/* Harness                                                             */
/* ------------------------------------------------------------------ */

let projectPath = '';
let ctx: PluginContext;
let scanSeq = 0;

function makeCtx(): PluginContext {
  const db = new Database(':memory:');
  runMigrations(db);
  return {
    storage: new Storage(db),
    shell: null,
    scriptsDir: join(process.cwd(), '..', 'scripts'),
    progressNotifier: { notify: async () => {} } as unknown as PluginContext['progressNotifier'],
  };
}

function tool() {
  const found = TOOLS.find((t) => t.name === 'validate_finding');
  if (!found) throw new Error('validate_finding is not registered');
  return found;
}

function route(over: Partial<RouteRecord> = {}): RouteRecord {
  return {
    method: 'GET',
    provenance: 'code',
    path_raw: '/users',
    path_resolved: '/users',
    path_partial: false,
    // Absolute + native separators, exactly what `toRoute` (surface/extract.ts)
    // assigns from Semgrep's own output. NOT the relative POSIX form
    // `imports` below carries — the mismatch is the point.
    file: join(projectPath, 'src', 'routes.ts'),
    line: 10,
    framework: 'express',
    language: 'typescript',
    auth_hint: 'unknown',
    params: [],
    confidence: 'high',
    ...over,
  };
}

function coverage(over: Partial<CoverageEntry> = {}): CoverageEntry {
  return {
    language: 'typescript',
    detected: true,
    routes_found: 1,
    unreadable_matches: 0,
    unresolved_imports: 0,
    status: 'ok',
    ...over,
  };
}

function snapshotOf(over: Partial<AttackSurfaceSnapshot> = {}): AttackSurfaceSnapshot {
  return {
    routes: [route()],
    env_vars: [],
    ports: [],
    webhooks: [],
    coverage: [coverage()],
    tools_run: [],
    missing_tools: [],
    spec_files: [],
    spec_diff: null,
    // Project-relative POSIX — the convention `mapAttackSurface.buildSnapshot`
    // relativizes these to before persisting.
    imports: [{ file: 'src/routes.ts', module_file: 'src/db.ts' }],
    ...over,
  };
}

function seedSnapshot(over: Partial<AttackSurfaceSnapshot> = {}, treeHash = 'snapshot-tree'): number {
  return ctx.storage.surface.insert({
    project_path: projectPath,
    tree_hash: treeHash,
    snapshot: snapshotOf(over),
  }).id;
}

function finding(over: Partial<Finding> = {}): Finding {
  return {
    fingerprint: 'fp1',
    tool: 'semgrep',
    severity: 'high',
    category: 'security',
    title: 'SQL injection',
    file_path: 'src/db.ts',
    line_start: 88,
    fix_available: false,
    ...over,
  };
}

/**
 * One completed scan carrying `findings`. Returns the scan id.
 *
 * `listOpen()` reads the LATEST completed scan, so a test that needs both a
 * DAST scan and a batch of open findings must seed the DAST scan FIRST — the
 * later insert wins the `started_at DESC, rowid DESC` tie-break.
 */
function seedScan(findings: Finding[], scanType: ScanType = 'sast'): string {
  const scanId = `scan-${(scanSeq += 1)}`;
  ctx.storage.scans.insert({
    scan_id: scanId,
    scan_type: scanType,
    project_path: projectPath,
    tree_hash: 'scan-tree',
  });
  if (findings.length > 0) {
    ctx.storage.findings.bulkInsert(findings.map((f) => ({ ...f, scan_id: scanId })));
  }
  ctx.storage.scans.finalize({
    scan_id: scanId,
    status: 'completed',
    tools_run: [],
    missing_tools: [],
  });
  return scanId;
}

interface Summary {
  findings_selected: number;
  counts_by_verdict: Record<string, number>;
  coverage_gaps: string[];
  snapshot: {
    id: number;
    tree_hash: string;
    captured_at: string;
    routes_total: number;
    root_files: number;
    spec_routes_excluded: number;
    import_records: number;
  };
  findings_from_scan: {
    scan_id: string;
    scan_type: string;
    tree_hash: string;
    finished_at: string | null;
    matches_snapshot_tree: boolean;
  } | null;
  working_tree_hash: string;
  snapshot_stale: boolean;
  graph: { files: number; edges: number; truncated: boolean };
  snapshot_coverage: CoverageEntry[];
  dast: {
    available: boolean;
    scan_id: string | null;
    finished_at: string | null;
    age_hours: number | null;
    anonymous_exposure_files: number;
    scans_searched: number;
  };
  providers_run: string[];
}

interface ValidateOk {
  ok: true;
  validations: Array<FindingValidation & { stale: boolean }>;
  summary: Summary;
  note?: string;
}

interface ValidateErr {
  ok: false;
  error: { code: string; message: string };
}

async function run(input: Record<string, unknown> = {}): Promise<ValidateOk | ValidateErr> {
  const result = await tool().handler({ project_path: projectPath, ...input }, ctx);
  return result as unknown as ValidateOk | ValidateErr;
}

function expectOk(r: ValidateOk | ValidateErr): ValidateOk {
  if (!r.ok) throw new Error(`expected ok, got ${r.error.code}: ${r.error.message}`);
  return r;
}

function expectErr(r: ValidateOk | ValidateErr): ValidateErr {
  if (r.ok) throw new Error(`expected a refusal, got ok with ${r.validations.length} validation(s)`);
  return r;
}

/** Every row of a table, raw, so nothing a repo mapper hides can slip past. */
function rawRows(table: string): Record<string, unknown>[] {
  return ctx.storage.rawHandle().prepare(`SELECT * FROM ${table}`).all() as Record<string, unknown>[];
}

/** The one validation a single-finding run produces. */
function only(r: ValidateOk): FindingValidation & { stale: boolean } {
  const first = r.validations[0];
  if (first === undefined) throw new Error('expected exactly one validation, got none');
  return first;
}

beforeEach(() => {
  ctx = makeCtx();
  projectPath = makeTempDir('guardian-validate-');
  scanSeq = 0;
});

afterEach(() => {
  ctx.storage.close();
});

/* ------------------------------------------------------------------ */
/* Discovery surface                                                   */
/* ------------------------------------------------------------------ */

describe('validate_finding — the tool description', () => {
  it('states the dynamic-import limitation in plain words', () => {
    // Design §5.4, amended after implementation: nothing in this tool detects
    // import(expr) or require(variable), so in a codebase using them
    // `unreachable` can be wrong and the tool cannot say when. The description
    // is an agent's only discovery surface — if the caveat is not here, it
    // reaches nobody who needs it.
    const description = tool().description;
    expect(description).toMatch(/dynamic import/i);
    expect(description).toMatch(/cannot tell you when/i);
  });

  it('states its precondition, its report-only contract and where unreachable is unavailable', () => {
    const description = tool().description;
    expect(description).toMatch(/map_attack_surface/);
    expect(description).toMatch(/never suppresses/i);
    expect(description).toMatch(/severity/i);
    // The four runtime-resolution stacks, named — §5.3.
    expect(description).toMatch(/Ruby/);
    expect(description).toMatch(/Java/);
    expect(description).toMatch(/C#/);
    expect(description).toMatch(/PHP/);
  });
});

/* ------------------------------------------------------------------ */
/* Refusals — four facts, four different results                       */
/* ------------------------------------------------------------------ */

describe('validate_finding refusals', () => {
  it('refuses an unusable project_path with not_a_git_repo, before reading storage', async () => {
    // No snapshot is seeded either, so an implementation that read storage
    // first would answer `no_surface_snapshot` here — a caller would then go
    // run map_attack_surface against a path that does not exist.
    const r = expectErr(await run({ project_path: join(projectPath, 'does-not-exist') }));
    expect(r.error.code).toBe('not_a_git_repo');
    expect(rawRows('finding_validations')).toHaveLength(0);
  });

  it('refuses with no_surface_snapshot, naming map_attack_surface', async () => {
    seedScan([finding()]);
    const r = expectErr(await run());
    expect(r.error.code).toBe('no_surface_snapshot');
    expect(r.error.message).toMatch(/map_attack_surface/);
    expect(rawRows('finding_validations')).toHaveLength(0);
  });

  it('refuses when the only snapshot belongs to a DIFFERENT project', async () => {
    // The snapshot read used to be "newest row in the database", from any
    // project, while everything downstream is keyed to THIS project_path:
    // routes and findings relativized against it, verdicts persisted under
    // it, the DAST search filtered by it. A snapshot of another tree
    // relativizes into a foreign key space, so no root matches any graph
    // node — and because the graph is non-empty, gate 1 passes and every
    // finding comes back `unreachable`. Silent, universal, and in the
    // direction that hides real findings. The wrong implementation returns
    // `ok` here with a batch of confident negatives.
    ctx.storage.surface.insert({
      project_path: join(projectPath, 'some-other-project'),
      tree_hash: 'other-tree',
      snapshot: snapshotOf(),
    });
    seedScan([finding()]);

    const r = expectErr(await run());
    expect(r.error.code).toBe('no_surface_snapshot');
    expect(rawRows('finding_validations')).toHaveLength(0);
  });

  it('reads THIS project’s snapshot even when another project was mapped more recently', async () => {
    // The other half of the same defect, and the one a "just take the newest
    // row" implementation fails on while still passing the refusal test
    // above: a correct snapshot EXISTS for this project, but a newer row for
    // another project shadows it.
    const mine = seedSnapshot();
    ctx.storage.surface.insert({
      project_path: join(projectPath, 'some-other-project'),
      tree_hash: 'other-tree',
      snapshot: snapshotOf({ routes: [], imports: [] }),
    });
    seedScan([finding()]);

    const r = expectOk(await run());
    expect(r.summary.snapshot.id).toBe(mine);
    // And the verdict is the real one, computed against this project's graph.
    expect(only(r).verdict).toBe('reachable');
  });

  it('errors on an unknown fingerprint rather than returning an empty batch', async () => {
    seedSnapshot();
    seedScan([finding({ fingerprint: 'fp1' })]);

    const r = expectErr(await run({ fingerprint: 'nope' }));

    // The wrong implementation filters the open list, finds nothing and
    // returns `ok: true, validations: []` — which a caller reads as "that
    // finding is fine". `expectErr` above already fails against it; these pin
    // the diagnosis a caller actually needs.
    expect(r.error.message).toMatch(/nope/);
    expect(r.error.message).toMatch(/suppressed/i);
    expect(rawRows('finding_validations')).toHaveLength(0);
  });

  it('reports no open findings as its own result, never as a bare empty batch', async () => {
    seedSnapshot();
    seedScan([]);

    const r = expectOk(await run());

    expect(r.validations).toHaveLength(0);
    expect(r.summary.findings_selected).toBe(0);
    // The distinguishing assertion: a bare `validations: []` with no note is
    // indistinguishable from "everything came back clean".
    expect(r.note).toMatch(/no open findings/i);
    expect(r.note).toMatch(/not.*(clean|statement)/i);
    expect(rawRows('finding_validations')).toHaveLength(0);
  });
});

/* ------------------------------------------------------------------ */
/* Selection — batch is the default                                    */
/* ------------------------------------------------------------------ */

describe('validate_finding selection', () => {
  it('validates every open finding when no fingerprint is given', async () => {
    seedSnapshot();
    seedScan([
      finding({ fingerprint: 'fp1' }),
      finding({ fingerprint: 'fp2', file_path: 'src/other.ts' }),
      finding({ fingerprint: 'fp3', file_path: 'src/routes.ts' }),
    ]);

    const r = expectOk(await run());

    expect(r.validations.map((v) => v.fingerprint).sort()).toEqual(['fp1', 'fp2', 'fp3']);
    expect(r.summary.findings_selected).toBe(3);
  });

  it('validates exactly the named fingerprint when one is given', async () => {
    seedSnapshot();
    seedScan([finding({ fingerprint: 'fp1' }), finding({ fingerprint: 'fp2' })]);

    const r = expectOk(await run({ fingerprint: 'fp2' }));

    // An implementation that accepted the argument and ignored it returns 2.
    expect(r.validations.map((v) => v.fingerprint)).toEqual(['fp2']);
    expect(r.summary.findings_selected).toBe(1);
  });
});

/* ------------------------------------------------------------------ */
/* Project scoping — open findings must not leak across projects       */
/* ------------------------------------------------------------------ */

describe('validate_finding project scoping', () => {
  it('validates only THIS project’s open findings, not a newer scan belonging to another project', async () => {
    // findings.listOpen() used to select the latest completed scan in the
    // WHOLE database, no project filter — the same class of bug the surface
    // snapshot read already had (see the refusal test above). Project A
    // (this test's `projectPath`) gets a snapshot and one open finding;
    // project B's scan is seeded AFTER — so it wins the unscoped "latest"
    // ordering — and belongs to a completely different project_path. The
    // plausible-wrong implementation validates B's finding under A's run.
    seedSnapshot();
    const mineScanId = seedScan([finding({ fingerprint: 'mine' })]);

    const otherProject = makeTempDir('guardian-validate-other-');
    ctx.storage.scans.insert({
      scan_id: 'scan-other-project',
      scan_type: 'sast',
      project_path: otherProject,
      tree_hash: 'other-tree',
    });
    ctx.storage.findings.bulkInsert([
      { ...finding({ fingerprint: 'theirs' }), scan_id: 'scan-other-project' },
    ]);
    ctx.storage.scans.finalize({
      scan_id: 'scan-other-project',
      status: 'completed',
      tools_run: [],
      missing_tools: [],
    });

    const r = expectOk(await run());

    expect(r.validations.map((v) => v.fingerprint)).toEqual(['mine']);
    expect(r.summary.findings_selected).toBe(1);
    // sourceScanOf must move in lockstep with the findings.listOpen() ->
    // listOpenForProject() fix above, per that function's own doc comment —
    // otherwise the summary NAMES the other project's scan as the source of
    // findings that did not come from it, which is worse than naming none.
    expect(r.summary.findings_from_scan?.scan_id).toBe(mineScanId);
  });
});

/* ------------------------------------------------------------------ */
/* Path conventions — the load-bearing one                             */
/* ------------------------------------------------------------------ */

describe('validate_finding path conventions', () => {
  it('reaches a file imported by an absolute-native route file through relative-POSIX imports', async () => {
    // The real shapes: routes[].file absolute + native separators,
    // imports[] project-relative POSIX. The wrong implementation compares
    // them unconverted, finds no root in the graph, and answers the NEGATIVE
    // verdict for every finding in the project.
    seedSnapshot();
    seedScan([finding({ file_path: 'src/db.ts' })]);

    const v = only(expectOk(await run()));

    expect(v.verdict).toBe('reachable');
    expect(v.evidence.map((e) => e.detail).join(' | ')).toMatch(/1 hop via GET \/users/);
  });

  it('reports 0 hops for a finding in the route file itself', async () => {
    seedSnapshot();
    seedScan([finding({ file_path: 'src/routes.ts' })]);

    const v = only(expectOk(await run()));

    expect(v.verdict).toBe('reachable');
    expect(v.confidence).toBe('high');
  });

  it('answers unreachable for an orphan file no route imports', async () => {
    // The other direction, measured rather than reasoned about: the same
    // snapshot that yields `reachable` above must yield `unreachable` for a
    // file that genuinely has no path from any route.
    seedSnapshot();
    seedScan([finding({ file_path: 'src/orphan.ts' })]);

    const v = only(expectOk(await run()));

    expect(v.verdict).toBe('unreachable');
  });
});

/* ------------------------------------------------------------------ */
/* Persistence and staleness                                           */
/* ------------------------------------------------------------------ */

describe('validate_finding persistence', () => {
  it('persists one row per returned verdict, readable back through the repo', async () => {
    seedSnapshot();
    seedScan([
      finding({ fingerprint: 'fp1' }),
      finding({ fingerprint: 'fp2', file_path: 'src/orphan.ts' }),
    ]);

    const r = expectOk(await run());

    expect(rawRows('finding_validations')).toHaveLength(r.validations.length);
    const stored = ctx.storage.validations.getByFingerprint(projectPath, 'fp2');
    expect(stored?.verdict).toBe('unreachable');
    expect(stored?.provider).toBe('static');
  });

  it('stamps every row with the snapshot id and the snapshot tree hash it was computed against', async () => {
    const snapshotId = seedSnapshot({}, 'snapshot-tree-a');
    seedScan([finding()]);

    const v = only(expectOk(await run()));

    expect(v.snapshot_id).toBe(snapshotId);
    // NOT the working tree's hash. A verdict derived from a snapshot of tree
    // N describes tree N; stamping the current hash instead would make it
    // read as fresh forever, which is the staleness test's whole subject.
    expect(v.tree_hash).toBe('snapshot-tree-a');
  });

  it('uses one computed_at for the whole batch', async () => {
    seedSnapshot();
    seedScan([finding({ fingerprint: 'fp1' }), finding({ fingerprint: 'fp2' })]);

    const r = expectOk(await run());

    const stamps = new Set(r.validations.map((v) => v.computed_at));
    expect(stamps.size).toBe(1);
  });
});

describe('validate_finding staleness', () => {
  it('is not stale while the snapshot matches the working tree, and is once the tree moves', async () => {
    writeFileSync(join(projectPath, 'a.txt'), 'one');
    const treeHash = await computeTreeHash(projectPath);
    seedSnapshot({}, treeHash);
    seedScan([finding()]);

    const fresh = only(expectOk(await run()));
    expect(fresh.stale).toBe(false);
    expect(expectOk(await run()).summary.snapshot_stale).toBe(false);

    // The code moves; the snapshot does not.
    writeFileSync(join(projectPath, 'b.txt'), 'two');

    const second = expectOk(await run());
    const stale = only(second);
    // The wrong implementation stamps the CURRENT working-tree hash on the
    // row, so this reads `false` and a verdict computed against a snapshot
    // that no longer describes the code is served as current.
    expect(stale.stale).toBe(true);
    expect(second.summary.snapshot_stale).toBe(true);
    expect(second.summary.working_tree_hash).not.toBe(treeHash);
    // The stored row keeps the tree it was computed against — the staleness
    // flag is derived at read time, never frozen into the row.
    expect(ctx.storage.validations.getByFingerprint(projectPath, 'fp1')?.tree_hash).toBe(treeHash);
  });
});

/* ------------------------------------------------------------------ */
/* The DAST cross-reference                                            */
/* ------------------------------------------------------------------ */

describe('validate_finding and the DAST cross-reference', () => {
  it('says a DAST scan was unavailable, and never lets that read as "nothing is exposed"', async () => {
    seedSnapshot();
    seedScan([finding()]);

    const r = expectOk(await run());

    expect(r.summary.dast.available).toBe(false);
    expect(r.summary.dast.anonymous_exposure_files).toBe(0);
    expect(r.summary.dast.scan_id).toBeNull();
    // The distinguishing assertion. Without it, `anonymous_exposure_files: 0`
    // is byte-identical to a DAST scan that ran and found nothing exposed.
    expect(r.summary.coverage_gaps.join(' | ')).toMatch(/scan_dast/);
    expect(r.summary.coverage_gaps.join(' | ')).toMatch(/not evidence that nothing is exposed/i);
  });

  it('distinguishes a DAST scan that ran and found nothing from no DAST scan at all', async () => {
    seedSnapshot();
    const dastScan = seedScan([], 'dast');
    seedScan([finding()]);

    const r = expectOk(await run());

    expect(r.summary.dast.available).toBe(true);
    expect(r.summary.dast.scan_id).toBe(dastScan);
    expect(r.summary.dast.anonymous_exposure_files).toBe(0);
    expect(typeof r.summary.dast.age_hours).toBe('number');
    // The same count as the test above — separated only by these two facts.
    expect(r.summary.coverage_gaps.join(' | ')).not.toMatch(/not evidence that nothing is exposed/i);
  });

  it('carries a confirmed anonymous exposure into the evidence, absolute route path and all', async () => {
    seedSnapshot();
    // dast/analyze.ts sets a route-derived finding's file_path to route.file
    // VERBATIM — absolute, native separators. Passing it through unchanged is
    // what the provider's internal relativization expects; an orchestrator
    // that pre-mangled it (or a provider fed the wrong root) never matches.
    seedScan(
      [
        finding({
          fingerprint: 'dast1',
          tool: 'dast',
          subcategory: 'anonymous_exposure',
          file_path: join(projectPath, 'src', 'routes.ts'),
        }),
      ],
      'dast',
    );
    seedScan([finding()]);

    const r = expectOk(await run());

    expect(r.summary.dast.anonymous_exposure_files).toBe(1);
    expect(only(r).evidence.map((e) => e.detail).join(' | ')).toMatch(/anonymously exposed/i);
  });

  it('ignores DAST findings that are not anonymous exposures', async () => {
    seedSnapshot();
    seedScan(
      [
        finding({
          fingerprint: 'dast2',
          tool: 'dast',
          subcategory: 'security_headers',
          file_path: join(projectPath, 'src', 'routes.ts'),
        }),
      ],
      'dast',
    );
    seedScan([finding()]);

    const r = expectOk(await run());

    // A wrong implementation that took every DAST finding's file_path would
    // report 1 here and claim a confirmed anonymous exposure on evidence that
    // says nothing of the kind.
    expect(r.summary.dast.anonymous_exposure_files).toBe(0);
    expect(only(r).evidence.map((e) => e.detail).join(' | ')).not.toMatch(/anonymously exposed/i);
  });
});

/* ------------------------------------------------------------------ */
/* The summary contract                                                */
/* ------------------------------------------------------------------ */

describe('validate_finding summary', () => {
  it('reports provider-level coverage gaps, not only per-finding ones', async () => {
    seedSnapshot({
      coverage: [
        coverage({ unresolved_imports: 3 }),
        // A language with no rules and NO finding in it. Per-finding gaps can
        // never mention it — only a provider-level report can.
        coverage({ language: 'go', routes_found: 0, status: 'no_rules' }),
      ],
    });
    seedScan([finding()]);

    const r = expectOk(await run());

    const perFinding = only(r).coverage_gaps;
    expect(perFinding.join(' | ')).toMatch(/3 import\(s\) for 'typescript'/);
    // The union: every per-finding gap is also visible at the summary level.
    expect(r.summary.coverage_gaps).toEqual(expect.arrayContaining(perFinding));
    // And the language nobody had a finding in is still reported.
    expect(r.summary.snapshot_coverage.find((c) => c.language === 'go')?.status).toBe('no_rules');
  });

  it('counts every verdict, including the ones this provider can never produce', async () => {
    seedSnapshot();
    seedScan([
      finding({ fingerprint: 'fp1', file_path: 'src/db.ts' }),
      finding({ fingerprint: 'fp2', file_path: 'src/orphan.ts' }),
      finding({ fingerprint: 'fp3', file_path: undefined }),
    ]);

    const r = expectOk(await run());

    expect(r.summary.counts_by_verdict).toEqual({
      reachable: 1,
      unreachable: 1,
      unknown: 1,
      // Present and zero, not absent: `confirmed` is not producible by
      // `static`, and a reader must see that rather than infer it.
      confirmed: 0,
    });
  });

  it('answers unknown, not unreachable, for a snapshot carrying no import edges', async () => {
    // A snapshot captured before import edges were persisted (or by a run
    // where Semgrep matched no imports) carries `imports: []` — and
    // `surfaceRepo`'s EMPTY_SNAPSHOT backfills exactly that onto every
    // pre-Task-3b row. The graph then has no paths at all, so every file
    // outside a route file is unreached BY CONSTRUCTION rather than by
    // evidence. Before the provider's first gate existed this returned
    // `unreachable` for the whole project, confidently, on no data. The
    // end-to-end assertion that it now returns `unknown` is the one that
    // matters: the verdict field is what consumers key on, and a gap beside
    // an `unreachable` would not have stopped anyone.
    seedSnapshot({ imports: [] });
    seedScan([finding({ file_path: 'src/db.ts' })]);

    const r = expectOk(await run());

    expect(only(r).verdict).toBe('unknown');
    expect(only(r).coverage_gaps.join(' | ')).toMatch(/holds no import edges at all/);
    expect(r.summary.graph).toEqual({ files: 0, edges: 0, truncated: false });
    expect(r.summary.coverage_gaps.join(' | ')).toMatch(/0 resolved import edge/i);
  });

  it('counts only the routes that were roots, and names the spec routes it excluded', async () => {
    // A spec-provenance route's `file` is the OpenAPI document, which the
    // provider never roots at. Counting it in `routes_total` put a number
    // beside verdicts nothing in it produced — a spec-only project read
    // `routes_total: N` next to `unreachable` verdicts computed from zero
    // roots — and disagreed with map_attack_surface's own code-only
    // `routes_total`.
    seedSnapshot({
      routes: [
        route(),
        route({ provenance: 'spec', file: join(projectPath, 'openapi.yaml'), path_resolved: '/documented' }),
      ],
    });
    seedScan([finding()]);

    const r = expectOk(await run());

    expect(r.summary.snapshot.routes_total).toBe(1);
    expect(r.summary.snapshot.root_files).toBe(1);
    expect(r.summary.snapshot.spec_routes_excluded).toBe(1);
    // The per-finding evidence quotes the same population, so the two must
    // agree — "1 of 1", never "1 of 2".
    expect(only(r).evidence.map((e) => e.detail).join(' | ')).toMatch(/reached by 1 of 1 known route/);
  });

  it('names the scan its findings came from, and whether it describes the snapshot’s tree', async () => {
    // The documented hazard made detectable: this tool validates whatever the
    // LATEST COMPLETED scan left open, so running it right after scan_dast
    // validates the DAST findings. Nothing here changes that behaviour — it
    // reports which scan was used, so a caller can see it happened.
    seedSnapshot({}, 'snapshot-tree');
    const scanId = seedScan([finding()]);

    const r = expectOk(await run());

    expect(r.summary.findings_from_scan).toEqual({
      scan_id: scanId,
      scan_type: 'sast',
      tree_hash: 'scan-tree',
      finished_at: expect.any(String),
      // 'scan-tree' !== 'snapshot-tree' — the findings and the map describe
      // different trees, and that must be visible rather than inferred.
      matches_snapshot_tree: false,
    });
  });

  it('names the DAST scan when that is the one whose findings got validated', async () => {
    // The exact confusion the field exists for: a scan_dast run finishing
    // last makes ITS findings the open list, so these verdicts are about DAST
    // findings even though the caller may have meant the SAST ones.
    seedSnapshot();
    const dastScan = seedScan([finding({ fingerprint: 'dast-fp' })], 'dast');

    const r = expectOk(await run());

    expect(r.summary.findings_from_scan?.scan_id).toBe(dastScan);
    expect(r.summary.findings_from_scan?.scan_type).toBe('dast');
  });

  it('names the providers that ran and the ones this version cannot offer', async () => {
    seedSnapshot();
    seedScan([finding()]);

    const r = expectOk(await run({ providers: ['static'] }));

    expect(r.summary.providers_run).toEqual(['static']);
    expect(r.summary.coverage_gaps.join(' | ')).toMatch(/runtime/);
    expect(r.summary.coverage_gaps.join(' | ')).toMatch(/dependency/);
  });
});

/* ------------------------------------------------------------------ */
/* The standing prohibition                                            */
/* ------------------------------------------------------------------ */

describe('validate_finding never suppresses and never mutates severity', () => {
  it('leaves the findings rows byte-identical and the suppressions table untouched', async () => {
    seedSnapshot();
    seedScan([
      finding({ fingerprint: 'fp1', severity: 'critical', file_path: 'src/orphan.ts' }),
      finding({ fingerprint: 'fp2', severity: 'high', file_path: 'src/db.ts' }),
    ]);

    const findingsBefore = rawRows('findings');
    const suppressionsBefore = rawRows('suppressions');

    const r = expectOk(await run());

    // The verdicts really were computed — otherwise this test passes for a
    // tool that does nothing at all.
    expect(r.validations).toHaveLength(2);
    expect(rawRows('findings')).toEqual(findingsBefore);
    expect(rawRows('suppressions')).toEqual(suppressionsBefore);
    expect(rawRows('suppressions')).toHaveLength(0);
  });
});
