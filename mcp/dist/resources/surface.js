/**
 * Attack-surface resources:
 *   - guardian://surface/latest → the most recent snapshot
 *   - guardian://surface/{id}   → a specific snapshot
 *
 * The full route list lives here rather than in the tool result: a project
 * with hundreds of routes would exhaust the agent's context window if every
 * `map_attack_surface` call returned them all.
 *
 * Missing data is not an error — both return `{ snapshot: null }`.
 */
import { registerResourceModule } from './index.js';
registerResourceModule({
    name: 'guardian-surface-latest',
    uri: 'guardian://surface/latest',
    description: 'Latest attack-surface snapshot from `map_attack_surface`: every route (code- and ' +
        'spec-provenance) with its resolved path, method, params and auth hint, plus env ' +
        'vars, declared ports, per-language coverage, the discovered spec_files, and the ' +
        'full spec_diff — matched pairs, code_only (shadow endpoints), spec_only (dead ' +
        'documentation) and unmatchable. Returns `{ snapshot: null }` when none exists yet.',
    handler: async (_uri, _params, ctx) => {
        const latest = ctx.storage.surface.getLatest();
        if (!latest)
            return { json: { snapshot: null } };
        return {
            json: {
                snapshot_id: latest.id,
                captured_at: latest.captured_at,
                snapshot: latest.snapshot,
            },
        };
    },
});
registerResourceModule({
    name: 'guardian-surface-by-id',
    uri: 'guardian://surface/{id}',
    isTemplate: true,
    description: 'A specific attack-surface snapshot by id, as returned in `snapshot_id` by ' +
        '`map_attack_surface`. Returns `{ snapshot: null }` for an unknown id.',
    handler: async (_uri, params, ctx) => {
        const rawId = Array.isArray(params['id']) ? params['id'][0] : params['id'];
        const id = Number.parseInt(String(rawId ?? ''), 10);
        if (Number.isNaN(id))
            return { json: { snapshot: null } };
        const found = ctx.storage.surface.getById(id);
        if (!found)
            return { json: { snapshot: null } };
        return {
            json: {
                snapshot_id: found.id,
                captured_at: found.captured_at,
                snapshot: found.snapshot,
            },
        };
    },
});
//# sourceMappingURL=surface.js.map