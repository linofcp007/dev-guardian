/**
 * `generate_sbom` — produce an SBOM (CycloneDX or SPDX, JSON).
 *
 * Standalone tool (not via the scan-tool factory) because SBOM data is not
 * a Finding stream — it is a structured artefact about installed packages.
 *
 * Source preference:
 *   1. Syft (`anchore/syft`) — emits both CycloneDX and SPDX natively.
 *   2. Trivy fs `--format cyclonedx` / `--format spdx-json` — fallback when
 *      Syft is not installed; Trivy supports both formats too.
 *
 * The full SBOM is always persisted to `.guardian/reports/sbom-<scan>/`.
 * It is also inlined in the response when the file size is ≤ `inline_max_kb`
 * (default 256 KB) — bigger SBOMs are referenced by path only so the MCP
 * channel never carries a huge blob.
 */
import { existsSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { z } from 'zod';
import { runProcess } from '../runners/processRunner.js';
import { summarize as summariseSbom } from '../runners/scannerParsers/syft.js';
import { ProjectPath } from '../schemas.js';
import { resolveProjectPath } from '../platform/projectPath.js';
import { ensureReportDir, scannerAvailable, } from './scanHelpers.js';
import { registerToolModule } from './index.js';
const inputSchema = {
    project_path: ProjectPath,
    format: z
        .enum(['cyclonedx-json', 'spdx-json'])
        .optional()
        .describe('SBOM output format. Default: cyclonedx-json.'),
    inline_max_kb: z
        .number()
        .int()
        .min(0)
        .max(8192)
        .optional()
        .describe('Inline the SBOM document in the response when its size is below this many KB. Default: 256.'),
};
const tool = {
    name: 'generate_sbom',
    title: 'Generate SBOM (Syft / Trivy)',
    description: 'Produce a Software Bill of Materials (CycloneDX or SPDX JSON). Prefers Syft; falls back to ' +
        'Trivy fs --format. The full SBOM is always written to .guardian/reports/sbom-<scan>/. The ' +
        'response inlines the document when its size is below inline_max_kb (default 256).',
    inputSchema,
    handler: async (input, ctx) => handler(input, ctx),
};
registerToolModule(tool);
async function handler(input, ctx) {
    const inp = input;
    let projectPath;
    try {
        projectPath = resolveProjectPath(inp.project_path).path;
    }
    catch (e) {
        return failDomain('not_a_git_repo', e.message);
    }
    const format = inp.format ?? 'cyclonedx-json';
    const inlineMaxBytes = (inp.inline_max_kb ?? 256) * 1024;
    const scanId = randomUUID();
    const reportDir = ensureReportDir(projectPath, scanId, 'sbom');
    const outFile = join(reportDir, `sbom.${format === 'cyclonedx-json' ? 'cdx' : 'spdx'}.json`);
    const syftBin = await scannerAvailable('syft');
    let producedBy = null;
    if (syftBin) {
        const syftFormat = format === 'cyclonedx-json' ? 'cyclonedx-json' : 'spdx-json';
        const result = await runProcess({
            command: 'syft',
            args: [projectPath, '-o', `${syftFormat}=${outFile}`, '--quiet'],
            cwd: projectPath,
        });
        if (result.outcome === 'completed' && existsSync(outFile)) {
            producedBy = 'syft';
        }
    }
    if (!producedBy) {
        const trivyBin = await scannerAvailable('trivy');
        if (trivyBin) {
            const trivyFormat = format === 'cyclonedx-json' ? 'cyclonedx' : 'spdx-json';
            const result = await runProcess({
                command: 'trivy',
                args: ['fs', '--format', trivyFormat, '--output', outFile, '--quiet', projectPath],
                cwd: projectPath,
            });
            if (result.outcome === 'completed' && existsSync(outFile)) {
                producedBy = 'trivy';
            }
        }
    }
    if (!producedBy) {
        return {
            ok: false,
            error: {
                code: 'missing_scanner',
                message: 'Neither Syft nor Trivy is installed. Install one of them via `install_toolchain` ' +
                    'or refer to https://github.com/anchore/syft.',
            },
        };
    }
    const stat = statSync(outFile);
    const raw = readFileSync(outFile, 'utf8');
    const summary = summariseSbom(raw);
    // Persist a scan row so `guardian://sbom` can find the latest output
    // without touching the filesystem.
    ctx.storage.scans.insert({
        scan_id: scanId,
        scan_type: 'sbom',
        project_path: projectPath,
        tree_hash: '',
        report_dir: outFile,
    });
    ctx.storage.scans.finalize({
        scan_id: scanId,
        status: 'completed',
        tools_run: [{ name: producedBy, status: 'ok' }],
        missing_tools: [],
        report_dir: outFile,
        meta: {
            format,
            produced_by: producedBy,
            file_path: outFile,
            size_bytes: stat.size,
            components_count: summary.components_count,
            top_packages: summary.top_packages,
        },
    });
    const payload = {
        ok: true,
        scan_id: scanId,
        format,
        produced_by: producedBy,
        file_path: outFile,
        size_bytes: stat.size,
        components_count: summary.components_count,
        top_packages: summary.top_packages,
    };
    if (stat.size <= inlineMaxBytes) {
        try {
            payload['inline'] = JSON.parse(raw);
        }
        catch {
            // SBOM file unparseable — keep the path, drop the inline.
        }
    }
    return payload;
}
function failDomain(code, message) {
    return { ok: false, error: { code, message } };
}
//# sourceMappingURL=generateSbom.js.map