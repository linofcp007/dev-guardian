/**
 * Remaining `guardian://...` resources:
 *   - guardian://cves/active        → CVE rows pinned to the latest deps scan
 *   - guardian://sbom               → most-recent SBOM produced by generate_sbom
 *   - guardian://stack              → latest stack snapshot
 *   - guardian://compliance/status  → extras from the latest compliance_check
 *   - guardian://baseline           → active baseline or `{ active: false }`
 *
 * All return `{}` / nulled shapes when no underlying data exists yet — per
 * US-7 AC-2, missing data is not an error.
 */

import type { PluginContext } from '../context.js';
import { registerResourceModule } from './index.js';

registerResourceModule({
  name: 'guardian-cves-active',
  uri: 'guardian://cves/active',
  description:
    'CVEs pinned to the most recent deps-flavoured scan (deps / deps_audit / security_full). ' +
    'Returns `{ cves: [] }` when no deps scan has run.',
  handler: async (_uri, _params, ctx) => {
    const latestDeps = findLatestOfType(ctx, ['deps', 'security_full']);
    if (!latestDeps) return { json: { cves: [], last_run: null } };
    const cves = ctx.storage.cves.listActive(latestDeps.scan_id);
    return { json: { cves, last_run: latestDeps.started_at, scan_id: latestDeps.scan_id } };
  },
});

registerResourceModule({
  name: 'guardian-sbom',
  uri: 'guardian://sbom',
  description:
    'Metadata for the most recent SBOM produced by `generate_sbom`: format, produced_by, file ' +
    'path on disk, component count, top packages. Inline payload omitted — call generate_sbom ' +
    'directly for the full document.',
  handler: async (_uri, _params, ctx) => {
    const latest = findLatestOfType(ctx, ['sbom']);
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
    'Latest stack snapshot produced by `detect_stack`. Returns `{ snapshot: null }` when no ' +
    'snapshot exists yet.',
  handler: async (_uri, _params, ctx) => {
    const snap = ctx.storage.stack.getLatest();
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
    'Compliance status from the most recent compliance_check: licenses_summary, risky_licenses, ' +
    'and policy_documents_found. Returns `{ last_run: null }` when no compliance scan exists.',
  handler: async (_uri, _params, ctx) => {
    const latest = findLatestOfType(ctx, ['compliance']);
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
    'Active regression baseline: `{ baseline_id, scan_id, set_at, note? }`. Returns ' +
    '`{ active: false }` when no baseline has been set.',
  handler: async (_uri, _params, ctx) => {
    const baseline = ctx.storage.baselines.getActive();
    if (!baseline) return { json: { active: false } };
    return {
      json: {
        active: true,
        baseline_id: baseline.id,
        scan_id: baseline.scan_id,
        set_at: baseline.set_at,
        ...(baseline.note !== undefined ? { note: baseline.note } : {}),
      },
    };
  },
});

function findLatestOfType(
  ctx: PluginContext,
  acceptedTypes: string[],
): ReturnType<typeof ctx.storage.scans.getById> {
  const history = ctx.storage.scans.listHistory(50);
  const found = history.find(
    (s) => s.status === 'completed' && acceptedTypes.includes(s.scan_type),
  );
  return found ? ctx.storage.scans.getById(found.scan_id) : null;
}
