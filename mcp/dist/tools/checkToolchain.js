/**
 * `check_toolchain` — surface installed / missing scanner state.
 *
 * Invokes `scripts/scan/check-tools.sh`, which already returns a JSON map
 * of `{toolName: versionString}`. We enrich each entry with:
 *   - `installed` (bool)
 *   - `version` (string from check-tools or "")
 *   - `expected_version_floor` (from the catalogue)
 *   - `required_by` (which MCP tools need it)
 *   - `install_command` (string suggestion per current OS)
 *
 * No installation happens here — that's `install_toolchain`'s job. This
 * tool is read-only.
 */
import { join } from 'node:path';
import { detectOs } from '../platform/osDetect.js';
import { meetsFloor } from '../platform/semverCompare.js';
import { runShellScript } from '../runners/shellRunner.js';
import { TOOL_CATALOG, suggestedInstallCommandString, } from '../runners/installCatalog.js';
import { registerToolModule } from './index.js';
const SCRIPT_REL_PATH = ['scan', 'check-tools.sh'];
const tool = {
    name: 'check_toolchain',
    title: 'Check toolchain status',
    description: 'Run scripts/scan/check-tools.sh and report per-scanner status: installed, version, expected ' +
        'version floor, the MCP tools that depend on it, and the suggested install command for this OS.',
    inputSchema: {},
    handler: async (_input, ctx) => handler(ctx),
};
registerToolModule(tool);
async function handler(ctx) {
    if (ctx.shell === null) {
        return failDomain('no_bash_shell', 'No usable bash shell found. Install Git Bash or WSL, then restart.');
    }
    const scriptPath = join(ctx.scriptsDir, ...SCRIPT_REL_PATH);
    const result = await runShellScript({
        shell: ctx.shell,
        scriptPath,
        cwd: ctx.scriptsDir,
    });
    if (result.outcome !== 'completed') {
        return failDomain('scanner_failed', `check-tools.sh exited with outcome=${result.outcome}: ${result.stderr.split(/\r?\n/)[0] ?? ''}`);
    }
    let parsed;
    try {
        parsed = JSON.parse(result.stdout);
    }
    catch (e) {
        return failDomain('scanner_failed', `check-tools.sh output not JSON: ${e.message}`);
    }
    const os = detectOs();
    const tools = [];
    // Cover every catalog entry plus anything check-tools surfaced that we
    // do not know about — the latter is informational only.
    const seen = new Set();
    for (const [toolName, meta] of Object.entries(TOOL_CATALOG)) {
        const version = (parsed[toolName] ?? '').trim();
        const installed = version.length > 0;
        tools.push({
            name: toolName,
            installed,
            version,
            expected_version_floor: meta.version_floor,
            meets_version_floor: installed ? meetsFloor(version, meta.version_floor) : null,
            required_by: meta.required_by,
            install_command: suggestedInstallCommandString(toolName, os),
        });
        seen.add(toolName);
    }
    for (const [toolName, versionRaw] of Object.entries(parsed)) {
        if (seen.has(toolName))
            continue;
        const version = (versionRaw ?? '').trim();
        tools.push({
            name: toolName,
            installed: version.length > 0,
            version,
            expected_version_floor: '',
            meets_version_floor: null,
            required_by: [],
            install_command: null,
        });
    }
    // Sort: missing required tools first, then everything else, alphabetical.
    tools.sort((a, b) => {
        const aRequired = a.required_by.length > 0 ? 0 : 1;
        const bRequired = b.required_by.length > 0 ? 0 : 1;
        const aMissing = a.installed ? 1 : 0;
        const bMissing = b.installed ? 1 : 0;
        return (aMissing - bMissing ||
            aRequired - bRequired ||
            a.name.localeCompare(b.name));
    });
    return {
        ok: true,
        os,
        tools,
        summary: {
            total_catalogued: Object.keys(TOOL_CATALOG).length,
            installed: tools.filter((t) => t.installed && TOOL_CATALOG[t.name]).length,
            missing: tools.filter((t) => !t.installed && TOOL_CATALOG[t.name]).length,
            below_floor: tools.filter((t) => t.meets_version_floor === false).length,
        },
    };
}
function failDomain(code, message) {
    return { ok: false, error: { code, message } };
}
//# sourceMappingURL=checkToolchain.js.map