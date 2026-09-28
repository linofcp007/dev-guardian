/**
 * Remaining `guardian://...` resources, each answering for the server's
 * working-directory project (`paging.ts#serverProjectPath`):
 *   - guardian://cves/active        → CVE rows of the newest deps scan, with
 *     `kev`/`epss_score`/`epss_percentile` when the `cve_intel` cache
 *     (Task 19) has a row — CACHE ONLY, never a live network call: a
 *     resource read stays fast and side-effect-free. A CVE with no cached
 *     row carries no `kev`/`epss_*` keys at all, never a fabricated
 *     `kev: false` — see `intel/enrich.ts`'s own header for why that
 *     distinction matters, and `tools/prioritizeFindings.ts` / `riskScore.ts`
 *     for where the actual (network-capable) refresh happens.
 *   - guardian://sbom               → most-recent SBOM produced by generate_sbom
 *   - guardian://stack              → latest stack snapshot
 *   - guardian://compliance/status  → extras from the latest compliance_check
 *   - guardian://baseline           → active baseline or `{ active: false }`
 *
 * Each "latest of a type" is a project-scoped SQL query
 * (`history/openSet.ts#findLatestUsable`). They used to search the 50 newest
 * scans of the WHOLE database — another project's scan answered, and a scan
 * 51 rows back was "not found" — and the baseline was the newest row in the
 * database, whatever project had set it.
 *
 * All return `{}` / nulled shapes when no underlying data exists yet — per
 * US-7 AC-2, missing data is not an error.
 */

import { findLatestUsable } from '../history/openSet.js';
import { CVE_SOURCE_SCAN_TYPES, type Cve } from '../types.js';
import { registerResourceModule } from './index.js';
import { serverProjectPath } from './paging.js';

registerResourceModule({
  name: 'guardian-cves-active',
  uri: 'guardian://cves/active',
  description:
    "CVEs of the server's working-directory project, from its newest deps-flavoured scan " +
    '(deps / deps_audit / security_full) that actually ran a dependency scanner, each with ' +
    '`kev`/`epss_score`/`epss_percentile` when already cached (cache only — call ' +
    'prioritize_findings or risk_score first to refresh). Returns `{ cves: [] }` when no deps ' +
    'scan has run.',
  handler: async (_uri, _params, ctx) => {
    const found = findLatestUsable(ctx.storage, serverProjectPath(), CVE_SOURCE_SCAN_TYPES, { slot: 'deps' });
    const latestDeps = found.scan;
    if (!latestDeps) return { json: { cves: [], last_run: null, skipped: found.skipped } };
    const cves = ctx.storage.cves.listActive(latestDeps.scan_id);
    const cached = ctx.storage.cveIntel.getMany(cves.map((c) => c.cve_id));
    return {
      json: {
        cves: cves.map((c) => withCachedIntel(c, cached)),
        last_run: latestDeps.started_at,
        scan_id: latestDeps.scan_id,
        ...(found.skipped.count > 0 ? { skipped: found.skipped } : {}),
      },
    };
  },
});

/**
 * `cve` plus whatever `kev`/`epss_*` the `cve_intel` cache already has for
 * it — cache-only, no refresh, no freshness check: this resource shows
 * whatever the last `prioritize_findings`/`risk_score` call already fetched,
 * never blocking a resource read on the network. A `cve_id` with no cached
 * row (never enriched yet, or every fetch attempt so far failed) gets NO
 * `kev`/`epss_*` keys at all — see this module's header for why a fabricated
 * `kev: false` would be worse than an absent key here. */
function withCachedIntel(
  cve: Cve,
  cached: ReadonlyMap<string, { kev: boolean; kev_date_added: string | null; epss_score: number | null; epss_percentile: number | null }>,
): Cve & { kev?: boolean; kev_date_added?: string; epss_score?: number; epss_percentile?: number } {
  const row = cached.get(cve.cve_id);
  if (row === undefined) return cve;
  return {
    ...cve,
    kev: row.kev,
    ...(row.kev_date_added !== null ? { kev_date_added: row.kev_date_added } : {}),
    ...(row.epss_score !== null ? { epss_score: row.epss_score } : {}),
    ...(row.epss_percentile !== null ? { epss_percentile: row.epss_percentile } : {}),
  };
}

registerResourceModule({
  name: 'guardian-sbom',
  uri: 'guardian://sbom',
  description:
    "Metadata for the server's working-directory project's most recent SBOM produced by " +
    '`generate_sbom`: format, produced_by, file path on disk, component count, top packages. ' +
    'Inline payload omitted — read the file or call generate_sbom for the full document.',
  handler: async (_uri, _params, ctx) => {
    const latest = findLatestUsable(ctx.storage, serverProjectPath(), ['sbom']).scan;
    if (!latest) return { json: { last_sbom: null } };
    return {
      json: {
        scan_id: latest.scan_id,
        captured_at: latest.started_at,
        ...(latest.meta ?? {}),
      },
    };
  },
});

registerResourceModule({
  name: 'guardian-stack',
  uri: 'guardian://stack',
  description:
    "Latest stack snapshot of the server's working-directory project, produced by " +
    '`detect_stack`. Returns `{ snapshot: null }` when no snapshot exists yet.',
  handler: async (_uri, _params, ctx) => {
    const snap = ctx.storage.stack.getLatestForProject(serverProjectPath());
    if (!snap) return { json: { snapshot: null } };
    return {
      json: {
        captured_at: snap.captured_at,
        snapshot: snap.snapshot,
      },
    };
  },
});

registerResourceModule({
  name: 'guardian-compliance-status',
  uri: 'guardian://compliance/status',
  description:
    "Compliance status of the server's working-directory project from its most recent " +
    'compliance_check: licenses_summary, risky_licenses, and policy_documents_found. Returns ' +
    '`{ last_run: null }` when no compliance scan exists.',
  handler: async (_uri, _params, ctx) => {
    // Policy documents are read from files, not from a scanner, so a run
    // whose scanners were missing still reports them.
    const latest = findLatestUsable(ctx.storage, serverProjectPath(), ['compliance'], {
      skipCoverageNone: false,
    }).scan;
    if (!latest) return { json: { last_run: null } };
    return {
      json: {
        last_run: latest.started_at,
        scan_id: latest.scan_id,
        ...(latest.meta ?? {}),
      },
    };
  },
});

registerResourceModule({
  name: 'guardian-baseline',
  uri: 'guardian://baseline',
  description:
    "Active regression baseline of the server's working-directory project: `{ baseline_id, " +
    'scan_id, scan_type, set_at, note? }` — never another project\'s. Returns `{ active: false }` ' +
    'when this project has no baseline.',
  handler: async (_uri, _params, ctx) => {
    const projectPath = serverProjectPath();
    const baseline = ctx.storage.baselines.getActiveForProject(projectPath);
    if (!baseline) return { json: { active: false, project_path: projectPath } };
    return {
      json: {
        active: true,
        project_path: projectPath,
        baseline_id: baseline.id,
        scan_id: baseline.scan_id,
        scan_type: baseline.scan_type,
        set_at: baseline.set_at,
        ...(baseline.note !== undefined ? { note: baseline.note } : {}),
      },
    };
  },
});
