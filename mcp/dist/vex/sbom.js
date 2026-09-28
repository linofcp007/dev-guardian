/**
 * A `generate_sbom` document read back as the purls `export_vex` names its
 * product and subcomponents by. Pure: the caller reads the file.
 *
 * Two shapes, the two `generate_sbom` writes:
 *   - CycloneDX JSON: `components[]` with `name`, `version`, `purl`, and the
 *     product in `metadata.component`;
 *   - SPDX 2.x JSON: `packages[]` with `name`, `versionInfo` and the purl in
 *     `externalRefs[]` (`referenceType: 'purl'`), the product being the
 *     package `documentDescribes` names.
 *
 * Deliberately separate from `sbom_diff`'s own reader, which keys by
 * ecosystem and never needed the purl itself.
 */
export function parseSbomInventory(raw) {
    let root;
    try {
        root = JSON.parse(raw);
    }
    catch {
        return null;
    }
    if (root === null || typeof root !== 'object')
        return null;
    const doc = root;
    if (Array.isArray(doc['components']) || doc['bomFormat'] === 'CycloneDX')
        return fromCycloneDx(doc);
    if (Array.isArray(doc['packages']))
        return fromSpdx(doc);
    return null;
}
function fromCycloneDx(doc) {
    const product = record(record(doc['metadata'])?.['component']);
    const components = (Array.isArray(doc['components']) ? doc['components'] : []).flatMap((c) => {
        const component = record(c);
        const name = text(component?.['name']);
        if (component === null || name === null)
            return [];
        return [withOptional({ name }, text(component['version']), text(component['purl']))];
    });
    return {
        product_purl: text(product?.['purl']),
        product_name: text(product?.['name']),
        components,
    };
}
function fromSpdx(doc) {
    const described = new Set((Array.isArray(doc['documentDescribes']) ? doc['documentDescribes'] : []).filter((id) => typeof id === 'string'));
    let product = null;
    const components = [];
    for (const p of Array.isArray(doc['packages']) ? doc['packages'] : []) {
        const pkg = record(p);
        const name = text(pkg?.['name']);
        if (pkg === null || name === null)
            continue;
        const purl = spdxPurl(pkg['externalRefs']);
        const id = text(pkg['SPDXID']);
        if (product === null && id !== null && described.has(id)) {
            product = { name, purl };
            continue;
        }
        components.push(withOptional({ name }, text(pkg['versionInfo']), purl));
    }
    return { product_purl: product?.purl ?? null, product_name: product?.name ?? null, components };
}
function spdxPurl(refs) {
    if (!Array.isArray(refs))
        return null;
    for (const ref of refs) {
        const r = record(ref);
        if (r?.['referenceType'] === 'purl')
            return text(r['referenceLocator']);
    }
    return null;
}
/**
 * The purls of one package version in the SBOM. With `ecosystem` known, only
 * purls of that type; unknown, and the SBOM holds the name in more than one
 * ecosystem (an npm `requests` beside the PyPI one), NONE — `ambiguous` —
 * because naming the wrong component in a VEX statement is a statement about
 * the wrong software.
 */
export function purlsFor(inventory, name, version, ecosystem) {
    const wanted = name.toLowerCase();
    const matching = [
        ...new Set(inventory.components
            .filter((c) => c.name.toLowerCase() === wanted && (version === null || c.version === version))
            .flatMap((c) => (c.purl === undefined ? [] : [c.purl]))),
    ];
    if (ecosystem !== null) {
        return { purls: matching.filter((purl) => purlType(purl) === ecosystem), ambiguous: false };
    }
    const types = new Set(matching.map(purlType));
    return types.size > 1 ? { purls: [], ambiguous: true } : { purls: matching, ambiguous: false };
}
/** `pkg:npm/lodash@4` → `npm`; null for anything that is not a purl. */
export function purlType(purl) {
    return /^pkg:([^/]+)\//.exec(purl)?.[1]?.toLowerCase() ?? null;
}
function record(value) {
    return value !== null && typeof value === 'object' && !Array.isArray(value)
        ? value
        : null;
}
function text(value) {
    return typeof value === 'string' && value.length > 0 ? value : null;
}
function withOptional(base, version, purl) {
    return { ...base, ...(version !== null ? { version } : {}), ...(purl !== null ? { purl } : {}) };
}
//# sourceMappingURL=sbom.js.map