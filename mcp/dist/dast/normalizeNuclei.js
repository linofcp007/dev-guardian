/**
 * Turn nuclei's JSONL output into findings. Pure — no I/O, no clock, no
 * randomness — mirroring the pure/impure split the rest of `dast/` holds:
 * `nuclei.ts` spawns the process and knows nothing about what its output
 * means; this module reads that output and decides, and nothing in between
 * reads input and decides at the same time. Every fabrication defect in this
 * project's history was born in a layer that blurred that boundary.
 *
 * Two rules matter most here, both about NOT inventing what a line does not
 * say:
 *   - a line nuclei did not finish writing, that is not JSON, or that parses
 *     but names no template, is skipped — never thrown, and never allowed to
 *     lose every finding after it.
 *   - a `matched-at` that names no route in the inventory leaves `file_path`
 *     undefined. Attaching the first route, or any route, would hand the
 *     reader a source location that has nothing to do with the finding.
 */
import { dastFingerprint } from './analyze.js';
import { substituteParams } from './plan.js';
/**
 * nuclei's own severity words, lower-cased, mapped onto the repo's five-value
 * scale. `unknown` — and anything nuclei ever emits that is not one of these
 * five recognised words — falls through to `'info'` rather than being
 * dropped: an unrecognised severity is reported at its most conservative
 * reading, never discarded, so a finding never disappears because of a
 * template metadata field this map does not yet know.
 */
const SEVERITY_MAP = {
    critical: 'critical',
    high: 'high',
    medium: 'medium',
    low: 'low',
    info: 'info',
};
function mapSeverity(value) {
    if (typeof value === 'string') {
        const mapped = SEVERITY_MAP[value.toLowerCase()];
        if (mapped !== undefined)
            return mapped;
    }
    return 'info';
}
function isRecord(value) {
    return typeof value === 'object' && value !== null && !Array.isArray(value);
}
/**
 * `matched-at`'s pathname, or the raw string when it does not parse as a URL
 * — never a thrown error. A malformed `matched-at` still leaves every other
 * field of the line usable; only route matching (which needs a real
 * pathname) degrades, and it degrades to "no match" rather than a guess.
 */
function pathnameOf(matchedAt) {
    if (matchedAt === '')
        return '';
    try {
        return new URL(matchedAt).pathname;
    }
    catch {
        return matchedAt;
    }
}
/**
 * The same comparison `analyze.ts#knownMethodsForPath` uses for the method-
 * surface check: run each candidate route's resolved path through the same
 * `substituteParams` the planner used to build requests, so a literal hit at
 * `/users/1` matches an inventory entry declared as `/users/{id}`.
 * `path_partial` routes are never comparable — their `path_resolved` is not
 * a real path — so they are skipped, the same carve-out `knownMethodsForPath`
 * applies. First match wins; nuclei findings are not tied to one HTTP method,
 * so there is no further tiebreak to make.
 */
function matchRoute(pathname, routes) {
    if (pathname === '')
        return undefined;
    return routes.find((r) => !r.path_partial && substituteParams(r.path_resolved).path === pathname);
}
function buildMessage(templateId, matchedAt, description) {
    const where = matchedAt === '' ? '(no matched-at reported)' : matchedAt;
    const base = `nuclei template '${templateId}' matched ${where}.`;
    return description === undefined || description === '' ? base : `${base} ${description}`;
}
/** One JSONL line → one finding, or `null` when the line cannot be attributed to anything real. */
function normalizeLine(line, routes) {
    let parsed;
    try {
        parsed = JSON.parse(line);
    }
    catch {
        return null;
    }
    if (!isRecord(parsed))
        return null;
    // template-id is the one field that says WHAT matched. Without it there is
    // nothing to attribute a finding to, and inventing a placeholder rule_id
    // would fabricate an identity nuclei never reported.
    const templateId = parsed['template-id'];
    if (typeof templateId !== 'string' || templateId === '')
        return null;
    const info = isRecord(parsed['info']) ? parsed['info'] : undefined;
    const nameValue = info !== undefined ? info['name'] : undefined;
    const title = typeof nameValue === 'string' && nameValue !== '' ? nameValue : templateId;
    const descriptionValue = info !== undefined ? info['description'] : undefined;
    const description = typeof descriptionValue === 'string' ? descriptionValue : undefined;
    const severity = mapSeverity(info !== undefined ? info['severity'] : undefined);
    const matchedAtValue = parsed['matched-at'];
    const matchedAt = typeof matchedAtValue === 'string' ? matchedAtValue : '';
    const pathname = pathnameOf(matchedAt);
    const route = matchRoute(pathname, routes);
    const finding = {
        // `dastFingerprint`'s `method` slot plays the role of "the specific
        // signal at this path" — an HTTP verb for the own engine's checks, the
        // template-id here. Two different templates matching the SAME path must
        // never collide into one fingerprint (one would silently overwrite the
        // other in storage), and the template-id is what keeps them apart.
        // `line_start`/`line_end` are excluded from the hash the same way
        // `dastFingerprint` already excludes them for route-scoped own-engine
        // findings — see that function's doc comment — so an unrelated edit that
        // shifts a route's line number does not make this finding look new.
        fingerprint: dastFingerprint('nuclei', templateId, pathname, route?.file),
        tool: 'nuclei',
        rule_id: templateId,
        severity,
        category: 'security',
        subcategory: 'nuclei',
        title,
        message: buildMessage(templateId, matchedAt, description),
        fix_available: false,
        check: 'nuclei',
        // No `ProbeRequest` exists for a nuclei hit to borrow an id from — this is
        // the closest analogue: a deterministic string identifying which nuclei
        // hit produced this finding, for whichever evidence file later gets
        // written against it.
        evidence_id: `nuclei ${templateId} ${matchedAt}`,
    };
    // Set only when a route actually matched — never a default/first route.
    // Leaving these two fields absent (not merely `undefined`-valued) is what
    // "no route matched" looks like on a `Finding`, and the caller must be able
    // to tell that apart from "this route's file happens to be at line 0" or
    // any other guessed placeholder.
    if (route !== undefined) {
        finding.file_path = route.file;
        finding.line_start = route.line;
    }
    return finding;
}
/**
 * One JSONL line is one finding, or none — never more, never a thrown error.
 * A line nuclei was still writing when the process was killed, a stray blank
 * line, or a line some future nuclei version shapes differently, must not
 * cost every finding that came before or after it.
 */
export function normalizeNucleiJsonl(jsonl, routes) {
    const findings = [];
    for (const line of jsonl.split(/\r?\n/)) {
        const trimmed = line.trim();
        if (trimmed === '')
            continue;
        const finding = normalizeLine(trimmed, routes);
        if (finding !== null)
            findings.push(finding);
    }
    return findings;
}
//# sourceMappingURL=normalizeNuclei.js.map