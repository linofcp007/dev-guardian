/**
 * Attack-surface resources:
 *   - guardian://surface/latest → the server's project's most recent
 *                                 snapshot, bounded
 *   - guardian://surface/{id}   → a specific snapshot, whole
 *
 * The full route list lives here rather than in the tool result: a project
 * with hundreds of routes would exhaust the agent's context window if every
 * `map_attack_surface` call returned them all.
 *
 * `latest` is bounded all the same: every list carries at most
 * {@link SURFACE_ITEM_CAP} entries, `totals` holds the true counts and
 * `truncated` names the lists that were cut; the import edges (thousands in
 * a real project, and only `validate_finding` consumes them — from storage)
 * are counted, never inlined. It used to inline everything, and it used to
 * be whichever project was mapped last.
 *
 * Missing data is not an error — both return `{ snapshot: null }`.
 */

import type { AttackSurfaceSnapshot } from '../types.js';
import { registerResourceModule } from './index.js';
import { serverProjectPath } from './paging.js';

/** Entries per list in `guardian://surface/latest`. */
export const SURFACE_ITEM_CAP = 200;

registerResourceModule({
  name: 'guardian-surface-latest',
  uri: 'guardian://surface/latest',
  description:
    "Latest attack-surface snapshot of the server's working-directory project, from " +
    '`map_attack_surface`: routes (code- and spec-provenance) with resolved path, method, params ' +
    'and auth hint, env vars, declared ports, per-language coverage, spec_files and the spec_diff ' +
    `(matched, code_only, spec_only, unmatchable). Each list is capped at ${SURFACE_ITEM_CAP} ` +
    'entries — `totals` has the true counts, `truncated` names what was cut, and ' +
    'guardian://surface/{snapshot_id} returns the whole snapshot. Import edges and third-party ' +
    'imports are counted, not inlined. Returns `{ snapshot: null }` when none exists yet.',
  handler: async (_uri, _params, ctx) => {
    const latest = ctx.storage.surface.getLatestForProject(serverProjectPath());
    if (!latest) return { json: { snapshot: null } };
    const { snapshot, totals, truncated } = boundSnapshot(latest.snapshot);
    return {
      json: {
        snapshot_id: latest.id,
        captured_at: latest.captured_at,
        snapshot,
        totals,
        truncated,
        ...(truncated.length > 0 ? { full_snapshot: `guardian://surface/${latest.id}` } : {}),
      },
    };
  },
});

registerResourceModule({
  name: 'guardian-surface-by-id',
  uri: 'guardian://surface/{id}',
  isTemplate: true,
  description:
    'A specific attack-surface snapshot by id, as returned in `snapshot_id` by ' +
    '`map_attack_surface`, in full. Returns `{ snapshot: null }` for an unknown id.',
  handler: async (_uri, params, ctx) => {
    const rawId = Array.isArray(params['id']) ? params['id'][0] : params['id'];
    const id = Number.parseInt(String(rawId ?? ''), 10);
    if (Number.isNaN(id)) return { json: { snapshot: null } };

    const found = ctx.storage.surface.getById(id);
    if (!found) return { json: { snapshot: null } };
    return {
      json: {
        snapshot_id: found.id,
        captured_at: found.captured_at,
        snapshot: found.snapshot,
      },
    };
  },
});

function boundSnapshot(s: AttackSurfaceSnapshot): {
  snapshot: Record<string, unknown>;
  totals: Record<string, unknown>;
  truncated: string[];
} {
  const truncated: string[] = [];
  // Stored snapshots are tolerated, never trusted: a field that is not an
  // array (an older or corrupted row) reads as empty rather than throwing.
  const list = <T>(items: readonly T[] | null | undefined): readonly T[] => (Array.isArray(items) ? items : []);
  const cap = <T>(name: string, items: readonly T[] | null | undefined): T[] => {
    const all = list(items);
    if (all.length > SURFACE_ITEM_CAP) truncated.push(name);
    return all.slice(0, SURFACE_ITEM_CAP);
  };

  // Both import lists are counted, never inlined: a project of any size has
  // thousands of them, and the dependency provider reads them from storage.
  const { imports, external_imports, spec_diff, ...rest } = s;
  const diff = spec_diff ?? null;
  const snapshot: Record<string, unknown> = {
    ...rest,
    routes: cap('routes', s.routes),
    webhooks: cap('webhooks', s.webhooks),
    env_vars: cap('env_vars', s.env_vars),
    ports: cap('ports', s.ports),
    spec_files: cap('spec_files', s.spec_files),
    spec_diff:
      diff === null
        ? null
        : {
            ...diff,
            matched: cap('spec_diff.matched', diff.matched),
            code_only: cap('spec_diff.code_only', diff.code_only),
            spec_only: cap('spec_diff.spec_only', diff.spec_only),
            unmatchable: cap('spec_diff.unmatchable', diff.unmatchable),
          },
  };
  const totals: Record<string, unknown> = {
    routes: list(s.routes).length,
    webhooks: list(s.webhooks).length,
    env_vars: list(s.env_vars).length,
    ports: list(s.ports).length,
    spec_files: list(s.spec_files).length,
    imports: list(imports).length,
    // Null, not 0, for a snapshot mapped before they were recorded.
    external_imports: external_imports === undefined ? null : list(external_imports).length,
    ...(diff === null
      ? {}
      : {
          spec_diff: {
            matched: list(diff.matched).length,
            code_only: list(diff.code_only).length,
            spec_only: list(diff.spec_only).length,
            unmatchable: list(diff.unmatchable).length,
          },
        }),
  };
  return { snapshot, totals, truncated };
}
