/**
 * SARIF 2.1.0 serializer.
 *
 * Converts canonical `Finding`s into the OASIS SARIF format consumed by CI
 * (GitHub code scanning, GitLab) and IDEs (the SARIF Viewer extensions).
 * This is the interchange format that lets dev-guardian findings show up as
 * inline annotations in a PR or squiggles in an editor without bespoke glue.
 *
 * Pure function: Findings + metadata in, JSON string out. `toSarif` itself
 * performs no I/O and is deterministic in every argument it's given. The one
 * exception is `opts.toolVersion`'s own default, which is resolved from disk
 * ONCE at module load (see `DEFAULT_TOOL_VERSION` below) rather than derived
 * from any argument — fixed for the life of the process, and overridable
 * per call via `opts.toolVersion` for a caller (e.g. a test) that needs to.
 */
import { sarifTaxonomyTags } from '../frameworks/taxonomy.js';
import { resolveVersion } from '../platform/version.js';
// Resolved once per process, at module load — same "read once, reuse many
// times" shape `server.ts` already applies to its own `SERVER_VERSION`, and
// cheaper than re-reading two small JSON files on every `toSarif` call (the
// interactive `report_export`/`scan_skill` tools can call this repeatedly in
// one long-lived MCP server session).
const DEFAULT_TOOL_VERSION = resolveVersion();
export function toSarif(findings, opts = {}) {
    const suppressed = opts.suppressed ?? [];
    const rulesById = new Map();
    for (const f of [...findings, ...suppressed.map((s) => s.finding)]) {
        const id = f.rule_id ?? `${f.tool}/${f.category}`;
        if (!rulesById.has(id)) {
            const rule = { id };
            rule.name = f.subcategory ?? f.category;
            rule.shortDescription = { text: f.title };
            if (f.message)
                rule.fullDescription = { text: f.message };
            rule.defaultConfiguration = { level: levelFor(f.severity) };
            rulesById.set(id, rule);
        }
        // A rule is tagged with every CWE/OWASP 2025 tag any of its findings
        // carries — `external/cwe/cwe-89` is what GitHub code scanning reads.
        // Only a REAL rule: findings with no rule_id share the synthetic
        // `tool/category` id, and unioning their tags would tag that "rule"
        // with every weakness of every one of them. Their results keep their
        // own tags.
        const tags = f.rule_id === undefined ? [] : sarifTaxonomyTags(f);
        const rule = rulesById.get(id);
        if (tags.length > 0 && rule !== undefined) {
            rule.properties = { tags: [...new Set([...(rule.properties?.tags ?? []), ...tags])].sort() };
        }
    }
    const toResult = (f) => {
        const ruleId = f.rule_id ?? `${f.tool}/${f.category}`;
        const tags = sarifTaxonomyTags(f);
        const result = {
            ruleId,
            level: levelFor(f.severity),
            message: { text: f.message ? `${f.title} — ${f.message}` : f.title },
            properties: {
                severity: f.severity,
                category: f.category,
                ...(f.subcategory ? { subcategory: f.subcategory } : {}),
                ...(f.fingerprint ? { fingerprint: f.fingerprint } : {}),
                ...(tags.length > 0 ? { tags } : {}),
            },
        };
        if (f.file_path) {
            const region = {};
            // `endLine` only ever accompanies `startLine` — a `Finding` can carry
            // `line_end` with no `line_start` (both are independently optional on
            // the type; a hand-built or DB-round-tripped `Finding` can hold
            // exactly that combination), and a region with `endLine` alone is not
            // one the SARIF schema recognises as meaningful.
            if (f.line_start) {
                region.startLine = f.line_start;
                if (f.line_end)
                    region.endLine = f.line_end;
            }
            result.locations = [
                {
                    physicalLocation: {
                        artifactLocation: { uri: toUri(f.file_path) },
                        ...(Object.keys(region).length > 0 ? { region } : {}),
                    },
                },
            ];
        }
        // `devGuardianIdentity` is the stable identity (64 hex) — what `import_sarif`
        // adopts as is, so a baseline or suppression keeps recognising the finding.
        if (f.fingerprint || f.identity) {
            result.partialFingerprints = {
                ...(f.fingerprint ? { devGuardian: f.fingerprint } : {}),
                ...(f.identity ? { devGuardianIdentity: f.identity } : {}),
            };
        }
        return result;
    };
    const results = [
        ...findings.map(toResult),
        ...suppressed.map((s) => ({ ...toResult(s.finding), suppressions: [{ kind: 'external', justification: s.justification }] })),
    ];
    const sarif = {
        $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
        version: '2.1.0',
        runs: [
            {
                tool: {
                    driver: {
                        name: opts.toolName ?? 'dev-guardian',
                        informationUri: opts.informationUri ?? 'https://github.com/linofcp007/dev-guardian',
                        version: opts.toolVersion ?? DEFAULT_TOOL_VERSION,
                        rules: [...rulesById.values()],
                    },
                },
                results,
            },
        ],
    };
    return JSON.stringify(sarif, null, 2);
}
/**
 * Every `Severity` mapped explicitly, as a `Record` rather than a switch
 * with a `default` fallback. A switch's default would let a `Severity`
 * added later compile silently into 'warning' — hiding a critical the same
 * way an unrecognised finding severity would. `Record<Severity, SarifLevel>`
 * makes that a compile-time error instead: TypeScript rejects this object
 * literal itself the day `SEVERITIES` (`../types.ts`) grows a case this file
 * has not been told how to map. Behaviour for today's five severities is
 * unchanged from the switch it replaces.
 */
const SARIF_LEVEL_BY_SEVERITY = {
    critical: 'error',
    high: 'error',
    medium: 'warning',
    low: 'note',
    info: 'note',
};
function levelFor(sev) {
    return SARIF_LEVEL_BY_SEVERITY[sev];
}
/**
 * `artifactLocation.uri` must be a legal `uri-reference` (schema
 * `format: "uri-reference"`) and must never let a literal `#` reach the
 * output. Measured, not assumed: a bare space or `%` FAILS that format
 * check under `ajv-formats` (`test/unit/ci/report.test.ts` enables it), but
 * a bare `#` does not — it is syntactically legal, since `#` is what STARTS
 * the fragment component of a URI. That makes it a silent-corruption bug
 * rather than a validation failure: a file literally named `notes#3.md`
 * would read back, to any SARIF consumer, as artifact `notes` with fragment
 * `3.md`.
 *
 * Encoded per PATH SEGMENT (`encodeURIComponent`, never the whole string in
 * one call) so the `/` separators stay literal separators — encoding the
 * whole string would turn every `/` into `%2F` and collapse the path into
 * one unreadable segment.
 */
function toUri(p) {
    return p
        .replace(/\\/g, '/')
        .split('/')
        .map((segment) => encodeURIComponent(segment))
        .join('/');
}
//# sourceMappingURL=sarif.js.map