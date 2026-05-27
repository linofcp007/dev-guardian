/**
 * WPScan JSON output parser.
 *
 * WPScan emits a top-level object with:
 *   - `version`         — core WP version + its vulnerabilities[]
 *   - `main_theme`      — active theme + its vulnerabilities[]
 *   - `plugins`         — { slug: { version, vulnerabilities[], … } }
 *   - `themes`          — same shape as plugins
 *   - `interesting_findings` — informational (config exposes, etc.)
 *
 * Every `vulnerability` entry yields one Finding (category=security,
 * subcategory={wordpress-core|wordpress-plugin|wordpress-theme}) and, when
 * the vuln carries a `references.cve` list, one ParserCveInput per CVE.
 *
 * Severity is derived from the CVSS score when present, otherwise we map
 * the WPScan severity label (when present), otherwise default to medium.
 */
import { asArray, getNumber, getProp, getString, makeFinding, parseInputAsJson, } from './index.js';
export const WPSCAN_TOOL_NAME = 'wpscan';
export const wpscanParser = {
    name: WPSCAN_TOOL_NAME,
    parse(input, _ctx = {}) {
        const root = parseInputAsJson(input);
        const findings = [];
        const cves = [];
        // Core
        const coreVersion = getProp(root, 'version');
        const coreVersionStr = getString(coreVersion, 'number') ?? 'unknown';
        for (const v of asArray(getProp(coreVersion, 'vulnerabilities'))) {
            pushVuln(v, 'wordpress-core', `wordpress:core@${coreVersionStr}`, findings, cves);
        }
        // Main theme
        const mainTheme = getProp(root, 'main_theme');
        if (mainTheme) {
            const slug = getString(mainTheme, 'slug') ?? 'main_theme';
            const ver = getString(mainTheme, 'version') ?? 'unknown';
            for (const v of asArray(getProp(mainTheme, 'vulnerabilities'))) {
                pushVuln(v, 'wordpress-theme', `${slug}@${ver}`, findings, cves);
            }
        }
        // Plugins: { slug: { version: {number}, vulnerabilities[] } }
        const plugins = getProp(root, 'plugins');
        if (plugins && typeof plugins === 'object') {
            for (const [slug, raw] of Object.entries(plugins)) {
                const ver = getString(getProp(raw, 'version'), 'number') ?? 'unknown';
                for (const v of asArray(getProp(raw, 'vulnerabilities'))) {
                    pushVuln(v, 'wordpress-plugin', `${slug}@${ver}`, findings, cves);
                }
            }
        }
        // Additional themes (non-main): { slug: { version, vulnerabilities[] } }
        const themes = getProp(root, 'themes');
        if (themes && typeof themes === 'object') {
            for (const [slug, raw] of Object.entries(themes)) {
                const ver = getString(getProp(raw, 'version'), 'number') ?? 'unknown';
                for (const v of asArray(getProp(raw, 'vulnerabilities'))) {
                    pushVuln(v, 'wordpress-theme', `${slug}@${ver}`, findings, cves);
                }
            }
        }
        return { findings, cves };
    },
};
function pushVuln(raw, subcategory, componentLabel, findings, cves) {
    const title = getString(raw, 'title') ?? 'WordPress vulnerability';
    const refs = getProp(raw, 'references');
    const cveList = asArray(getProp(refs, 'cve'))
        .filter((v) => typeof v === 'string')
        .map((v) => (v.startsWith('CVE-') ? v : `CVE-${v}`));
    const fixedIn = getString(raw, 'fixed_in');
    const severity = severityFromVuln(raw);
    const cveForRule = cveList[0] ?? title.slice(0, 64);
    const finding = makeFinding({
        tool: WPSCAN_TOOL_NAME,
        rule_id: cveForRule,
        severity,
        category: 'security',
        subcategory,
        title,
        fix_available: fixedIn !== undefined && fixedIn.length > 0,
        file_path: componentLabel,
        snippet: `component:${componentLabel}`,
    });
    findings.push(finding);
    for (const cveId of cveList) {
        // Each CVE row also gets persisted to the cves table.
        const [pkgName, installedVersion] = componentLabel.split('@');
        const cveEntry = {
            cve_id: cveId,
            package_name: pkgName ?? componentLabel,
            severity,
        };
        if (installedVersion !== undefined)
            cveEntry.installed_version = installedVersion;
        if (fixedIn !== undefined)
            cveEntry.fixed_version = fixedIn;
        cves.push(cveEntry);
    }
}
function severityFromVuln(raw) {
    // WPScan sometimes carries `references.cvss` with a numeric score.
    const refs = getProp(raw, 'references');
    const cvss = getProp(refs, 'cvss');
    const score = getNumber(cvss, 'score');
    if (score !== undefined) {
        if (score >= 9)
            return 'critical';
        if (score >= 7)
            return 'high';
        if (score >= 4)
            return 'medium';
        return 'low';
    }
    // Fall back to the textual severity field that newer WPScan output has.
    const label = getString(raw, 'severity')?.toLowerCase();
    if (label === 'critical')
        return 'critical';
    if (label === 'high')
        return 'high';
    if (label === 'medium')
        return 'medium';
    if (label === 'low')
        return 'low';
    return 'medium';
}
//# sourceMappingURL=wpscan.js.map