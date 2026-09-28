/**
 * A finding's weakness taxonomy: its CWEs and its OWASP Top 10:2025
 * categories, as every parser and renderer reads them.
 *
 * `cwe` and `owasp` on a `Finding` are ANNOTATIONS. They are part of neither
 * the fingerprint nor the identity (`runners/scannerParsers/index.ts`
 * `makeFinding`, `fingerprint/findingIdentity.ts`), so a scanner that starts
 * or stops reporting a CWE — or this mapping learning a new one — never
 * turns a finding into a new one, and suppressions and baselines keep
 * matching.
 *
 * Absent means UNKNOWN, never "no category": a row stored before schema 13
 * has neither field, and neither does a finding whose scanner gave no CWE.
 * Renderers count those as unmapped and never file them under a category.
 */
import { owaspCategoryOfCwe, parseOwasp2025Label, OWASP_2025_IDS } from './owaspTop10_2025.js';
/**
 * `CWE-<n>` from what scanners put in their output: Semgrep's
 * `"CWE-89: Improper Neutralization …"`, Trivy's `"CWE-79"`, Bandit's numeric
 * `issue_cwe.id`. Null for anything else, and for 0 — Bandit's "no CWE".
 */
export function normalizeCwe(raw) {
    let digits;
    if (typeof raw === 'number') {
        if (!Number.isInteger(raw) || raw <= 0)
            return null;
        digits = String(raw);
    }
    else if (typeof raw === 'string') {
        const m = /^\s*(?:CWE\s*[-_ ]?\s*)?(\d+)\b/i.exec(raw);
        if (m === null || m[1] === undefined)
            return null;
        // "CWE-89: …" and a bare "89" are CWEs; "89 ms" is not.
        if (!/^\s*CWE/i.test(raw) && raw.trim() !== m[1])
            return null;
        digits = m[1];
    }
    else {
        return null;
    }
    const n = Number.parseInt(digits, 10);
    return Number.isSafeInteger(n) && n > 0 ? `CWE-${n}` : null;
}
function asList(value) {
    if (Array.isArray(value))
        return value;
    return value === undefined || value === null ? [] : [value];
}
function cweNumber(cwe) {
    return Number.parseInt(cwe.slice(4), 10);
}
/**
 * The taxonomy fields for a finding, from whatever its scanner said.
 *
 * `cwe`: every value {@link normalizeCwe} accepts, de-duplicated, ascending.
 * `owasp`: the union of the scanner's own 2025 labels
 * ({@link parseOwasp2025Label} — a 2017/2021 label, or a 2025 id under
 * another category's title, is dropped) and the categories OWASP maps the
 * CWEs to. A rule's author and OWASP's CWE list can disagree (the registry
 * files CWE-732 container rules under A02, OWASP lists CWE-732 under A01);
 * both are kept, because each is a statement someone accountable made.
 *
 * Each field is present only when non-empty: unknown stays absent.
 */
export function classifyTaxonomy(input) {
    const cwes = [
        ...new Set(asList(input.cwe).map(normalizeCwe).filter((c) => c !== null)),
    ].sort((a, b) => cweNumber(a) - cweNumber(b));
    const categories = new Set();
    for (const label of asList(input.owasp)) {
        const id = parseOwasp2025Label(label);
        if (id !== null)
            categories.add(id);
    }
    for (const cwe of cwes) {
        const id = owaspCategoryOfCwe(cwe);
        if (id !== null)
            categories.add(id);
    }
    const out = {};
    if (cwes.length > 0)
        out.cwe = cwes;
    if (categories.size > 0)
        out.owasp = OWASP_2025_IDS.filter((id) => categories.has(id));
    return out;
}
/**
 * SARIF `properties.tags` for a finding: `external/cwe/cwe-89` (the form
 * GitHub code scanning reads off a rule) and `owasp-2025-a05`. Empty when
 * the finding's taxonomy is unknown.
 */
export function sarifTaxonomyTags(f) {
    const tags = [];
    for (const c of f.cwe ?? []) {
        const cwe = normalizeCwe(c);
        if (cwe !== null)
            tags.push(`external/cwe/${cwe.toLowerCase()}`);
    }
    for (const id of f.owasp ?? []) {
        const m = /^A(\d{2}):2025$/.exec(id);
        if (m !== null && m[1] !== undefined)
            tags.push(`owasp-2025-a${m[1]}`);
    }
    return [...new Set(tags)].sort();
}
//# sourceMappingURL=taxonomy.js.map