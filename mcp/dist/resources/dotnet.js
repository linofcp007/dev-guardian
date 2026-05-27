/**
 * .NET-specific resources.
 *
 * - guardian://dotnet/target-frameworks  — most recent dotnet_target_framework_check
 * - guardian://dotnet/efcore             — most recent dotnet_efcore_audit
 */
import { registerResourceModule } from './index.js';
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
function findLatestOfType(ctx, type) {
    const history = ctx.storage.scans.listHistory(50);
    const row = history.find((s) => s.scan_type === type && s.status === 'completed');
    return row ? ctx.storage.scans.getById(row.scan_id) : null;
}
//# sourceMappingURL=dotnet.js.map