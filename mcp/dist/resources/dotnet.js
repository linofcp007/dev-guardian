/**
 * .NET-specific resources.
 *
 * - guardian://dotnet/target-frameworks  — most recent dotnet_target_framework_check
 * - guardian://dotnet/efcore             — most recent dotnet_efcore_audit
 *
 * Both answer for the server's working-directory project.
 */
import { findLatestUsable } from '../history/openSet.js';
import { registerResourceModule } from './index.js';
import { serverProjectPath } from './paging.js';
registerResourceModule({
    name: 'guardian-dotnet-target-frameworks',
    uri: 'guardian://dotnet/target-frameworks',
    description: 'Latest dotnet_target_framework_check: per-project target framework moniker + EOL/legacy status.',
    handler: async (_uri, _params, ctx) => {
        const scan = findLatestOfType(ctx, 'dotnet_target_framework');
        if (!scan)
            return { json: { last_run: null } };
        return {
            json: {
                scan_id: scan.scan_id,
                captured_at: scan.started_at,
                ...(scan.meta ?? {}),
            },
        };
    },
});
registerResourceModule({
    name: 'guardian-dotnet-efcore',
    uri: 'guardian://dotnet/efcore',
    description: 'Latest dotnet_efcore_audit: dangerous migration patterns detected (DropTable, DropColumn, ' +
        'AlterColumn nullable=false without defaultValue, raw SQL with credentials).',
    handler: async (_uri, _params, ctx) => {
        const scan = findLatestOfType(ctx, 'dotnet_efcore_audit');
        if (!scan)
            return { json: { last_run: null } };
        return {
            json: {
                scan_id: scan.scan_id,
                captured_at: scan.started_at,
                ...(scan.meta ?? {}),
            },
        };
    },
});
/**
 * The server's project's newest completed scan of `type` — a project-scoped
 * SQL query, not a search of the 50 newest scans of the whole database. Both
 * report through `meta`, so a run's scanner coverage does not disqualify it.
 */
function findLatestOfType(ctx, type) {
    return findLatestUsable(ctx.storage, serverProjectPath(), [type], { skipCoverageNone: false }).scan;
}
//# sourceMappingURL=dotnet.js.map