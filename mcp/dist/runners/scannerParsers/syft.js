/**
 * Syft SBOM summariser.
 *
 * Syft emits multi-megabyte SBOM documents in either CycloneDX or SPDX
 * JSON format. The MCP `generate_sbom` tool stores the full document on
 * disk and only inlines it when small (≤ 256 KB); for everything else
 * consumers receive a summary so the model can reason about the SBOM
 * without ingesting the whole thing.
 *
 * This module is intentionally NOT a `ScannerParser`: SBOM data does not
 * map to Finding / Cve. It exports its own `summarize()` that returns a
 * `SbomSummary` value for the tool to embed in its response.
 */
import { parseInputAsJson, getProp, getString, asArray } from './index.js';
export function detectFormat(input) {
    const root = parseInputAsJson(input);
    if (!root || typeof root !== 'object')
        return 'unknown';
    // CycloneDX: bomFormat="CycloneDX" or specVersion present.
    const bomFormat = getString(root, 'bomFormat');
    if (bomFormat && bomFormat.toLowerCase() === 'cyclonedx')
        return 'cyclonedx-json';
    if (getString(root, 'specVersion') && getProp(root, 'components'))
        return 'cyclonedx-json';
    // SPDX: SPDXID + spdxVersion present.
    if (getString(root, 'SPDXID') || getString(root, 'spdxVersion'))
        return 'spdx-json';
    return 'unknown';
}
export function summarize(input, topN = 25) {
    const raw = typeof input === 'string' ? input : JSON.stringify(input ?? {});
    const inline_size_bytes = Buffer.byteLength(raw, 'utf8');
    const root = parseInputAsJson(input);
    const format = detectFormat(root);
    const components = format === 'cyclonedx-json'
        ? extractCycloneDx(root)
        : format === 'spdx-json'
            ? extractSpdx(root)
            : [];
    const top = components.slice(0, topN);
    return {
        format,
        components_count: components.length,
        top_packages: top,
        inline_size_bytes,
    };
}
function extractCycloneDx(root) {
    const out = [];
    for (const c of asArray(getProp(root, 'components'))) {
        const name = getString(c, 'name');
        if (!name)
            continue;
        const comp = { name };
        const version = getString(c, 'version');
        const type = getString(c, 'type');
        if (version !== undefined)
            comp.version = version;
        if (type !== undefined)
            comp.type = type;
        out.push(comp);
    }
    return out;
}
function extractSpdx(root) {
    const out = [];
    for (const p of asArray(getProp(root, 'packages'))) {
        const name = getString(p, 'name');
        if (!name)
            continue;
        const comp = { name };
        const version = getString(p, 'versionInfo');
        if (version !== undefined)
            comp.version = version;
        out.push(comp);
    }
    return out;
}
//# sourceMappingURL=syft.js.map