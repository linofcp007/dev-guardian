/**
 * Typosquat suspicion: is a name a near-miss of a popular package?
 *
 * Only ever produces a WARNING — a near-miss is a reason to look twice, not
 * proof of anything — and it is built to stay quiet, because a hook that
 * warns on every install is a hook people learn to ignore. Every rule below
 * exists to cut noise, and each one is measured by running the committed
 * lists against themselves (see `configs/popular-packages/README.md`):
 *
 *   - **Distance by length.** Damerau-Levenshtein (optimal string alignment:
 *     a transposition is one edit) ≤ 2 only for names of 8+ characters, ≤ 1
 *     for 5–7, and no check at all below 5 — at `ms`/`qs`/`ws` length every
 *     name is one edit from another. The length used is the SHORTER of the
 *     two names.
 *   - **Normalized names.** PyPI compares PEP 503 forms (`Typing_Extensions`
 *     is `typing-extensions`); npm, Packagist and NuGet compare lower case.
 *   - **A popular name is never flagged**, even when it is close to another
 *     popular name (`preact` / `react`).
 *   - **Namespaces an attacker cannot publish into are not compared.** An
 *     npm scope and a Packagist vendor belong to whoever registered them, so
 *     `@aws-sdk/client-sts` next to `@aws-sdk/client-s3` is the same owner's
 *     second package, never a squat. A scoped npm name is compared, as a
 *     whole, only against scoped popular names in OTHER scopes (that is how
 *     `@typse/node` is caught); an unscoped name only against unscoped ones.
 *
 * Pure functions. No I/O.
 */
/**
 * Optimal-string-alignment distance, computed only inside the diagonal band
 * `|i - j| <= max` and abandoned as soon as a whole row exceeds `max`.
 * Returns `max + 1` for anything farther than `max` — callers only ever ask
 * "within the threshold or not", and the band keeps a full-list scan cheap.
 */
export function damerauLevenshtein(a, b, max) {
    if (a === b)
        return 0;
    const la = a.length;
    const lb = b.length;
    if (Math.abs(la - lb) > max)
        return max + 1;
    const INF = max + 1;
    // Three rolling rows: two back (for transpositions), previous, current.
    let prev2 = new Array(lb + 1).fill(INF);
    let prev = new Array(lb + 1).fill(INF);
    let cur = new Array(lb + 1).fill(INF);
    for (let j = 0; j <= Math.min(lb, max); j += 1)
        prev[j] = j;
    for (let i = 1; i <= la; i += 1) {
        cur.fill(INF);
        if (i <= max)
            cur[0] = i;
        const from = Math.max(1, i - max);
        const to = Math.min(lb, i + max);
        let rowMin = cur[0] ?? INF;
        for (let j = from; j <= to; j += 1) {
            const cost = a.charCodeAt(i - 1) === b.charCodeAt(j - 1) ? 0 : 1;
            let v = Math.min((prev[j] ?? INF) + 1, (cur[j - 1] ?? INF) + 1, (prev[j - 1] ?? INF) + cost);
            if (i > 1 && j > 1 && a.charCodeAt(i - 1) === b.charCodeAt(j - 2) && a.charCodeAt(i - 2) === b.charCodeAt(j - 1)) {
                v = Math.min(v, (prev2[j - 2] ?? INF) + 1);
            }
            if (v > INF)
                v = INF;
            cur[j] = v;
            if (v < rowMin)
                rowMin = v;
        }
        if (rowMin > max)
            return INF;
        const recycled = prev2;
        prev2 = prev;
        prev = cur;
        cur = recycled;
    }
    const d = prev[lb] ?? INF;
    return d > max ? INF : d;
}
/** The largest edit distance still reported for a name of this length (0 = never). */
export function typoThreshold(length) {
    if (length < 5)
        return 0;
    if (length < 8)
        return 1;
    return 2;
}
/** The form two names are compared in. PyPI: PEP 503. Everything else: lower case. */
export function normalizePackageName(ecosystem, name) {
    const lower = name.trim().toLowerCase();
    return ecosystem === 'pypi' ? lower.replace(/[-_.]+/g, '-') : lower;
}
/**
 * The owner namespace of a name, when the registry enforces one: an npm
 * `@scope` or a Packagist `vendor`. `null` means the name has none (every
 * unscoped npm name, every PyPI and NuGet name).
 */
function ownerOf(ecosystem, normalized) {
    if (ecosystem === 'npm') {
        if (!normalized.startsWith('@'))
            return null;
        const slash = normalized.indexOf('/');
        return slash > 1 ? normalized.slice(1, slash) : null;
    }
    if (ecosystem === 'packagist') {
        const slash = normalized.indexOf('/');
        return slash > 0 ? normalized.slice(0, slash) : null;
    }
    return null;
}
const SEGMENT_SPLIT = /[-_./@]+/;
const DIGIT_RUN = /[0-9]+/g;
/**
 * Two names within the edit threshold that are nonetheless not a
 * misspelling of one another — each shape below was found by running the
 * lists against themselves and is a family of legitimate siblings:
 *
 *   - **only the numbers changed** — every run of digits in one name sits
 *     where a run of digits sits in the other: `nvidia-nccl-cu12` /
 *     `nvidia-nccl-cu13`, `…manifest-8.0.100` / `…manifest-9.0.100`,
 *     `…referenceassemblies.net472` / `.net48`, `uuid6` / `uuid7`. That is
 *     a version or variant, not a slip of the finger. A number INSERTED
 *     where there was none is not covered: `python3-dateutil` against
 *     `python-dateutil` is a real, historical PyPI typosquat and stays
 *     flagged.
 *   - **one short code swapped** — every other segment identical and the
 *     one that differs is at most 2 characters on both sides:
 *     `humanizer.core.uk` / `humanizer.core.sk`, `devexpress.xpo.de` /
 *     `.ja`. Those are locale / architecture codes.
 *   - **one word swapped for another** at distance 2 — every other segment
 *     identical, and the differing segment changed by at least 40% of its
 *     length: `is-stream` / `zip-stream`, `pytest-cov` / `pytest-env`,
 *     `mypy-boto3-s3` / `mypy-boto3-sqs`, `tree-sitter-ruby` / `-rust`.
 *     That is a different word, i.e. a different package. A one-edit
 *     change is never excused this way — `set-proto` / `get-proto` is the
 *     kind of near-miss the check is for.
 */
function isSiblingNotTypo(a, b, distance) {
    if (a.replace(DIGIT_RUN, '#') === b.replace(DIGIT_RUN, '#'))
        return true;
    const sa = a.split(SEGMENT_SPLIT);
    const sb = b.split(SEGMENT_SPLIT);
    if (sa.length < 2 || sa.length !== sb.length)
        return false;
    let differing = -1;
    for (let i = 0; i < sa.length; i += 1) {
        if (sa[i] === sb[i])
            continue;
        if (differing !== -1)
            return false;
        differing = i;
    }
    if (differing === -1)
        return false; // only separators differ: `camelcase` vs `camel-case` style
    const x = sa[differing] ?? '';
    const y = sb[differing] ?? '';
    const longest = Math.max(x.length, y.length);
    if (longest <= 2)
        return true;
    if (distance < 2)
        return false;
    return damerauLevenshtein(x, y, longest) * 5 >= longest * 2;
}
export function buildPopularIndex(ecosystem, names) {
    const ordered = [];
    const set = new Set();
    const byLength = new Map();
    for (const raw of names) {
        const n = normalizePackageName(ecosystem, raw);
        if (n.length === 0 || set.has(n))
            continue;
        set.add(n);
        ordered.push(n);
        const bucket = byLength.get(n.length);
        if (bucket === undefined)
            byLength.set(n.length, [n]);
        else
            bucket.push(n);
    }
    return { ecosystem, names: ordered, set, byLength };
}
export function findTyposquatTarget(index, name, opts = {}) {
    const eco = index.ecosystem;
    const cand = normalizePackageName(eco, name);
    if (cand.length === 0)
        return null;
    if ((opts.exemptPopular ?? true) && index.set.has(cand))
        return null;
    if (typoThreshold(cand.length) === 0)
        return null;
    const candOwner = ownerOf(eco, cand);
    const candScoped = eco === 'npm' && cand.startsWith('@');
    let best = null;
    let bestRank = Number.POSITIVE_INFINITY;
    for (let len = cand.length - 2; len <= cand.length + 2; len += 1) {
        const bucket = index.byLength.get(len);
        if (bucket === undefined)
            continue;
        for (const target of bucket) {
            if (target === cand)
                continue;
            if (eco === 'npm') {
                const targetScoped = target.startsWith('@');
                if (candScoped !== targetScoped)
                    continue;
            }
            if (candOwner !== null && candOwner === ownerOf(eco, target))
                continue;
            const max = typoThreshold(Math.min(cand.length, target.length));
            if (max === 0)
                continue;
            const d = damerauLevenshtein(cand, target, max);
            if (d === 0 || d > max)
                continue;
            if (isSiblingNotTypo(cand, target, d))
                continue;
            const rank = index.names.indexOf(target);
            if (best === null || d < best.distance || (d === best.distance && rank < bestRank)) {
                best = { similar_to: target, distance: d };
                bestRank = rank;
            }
        }
    }
    return best;
}
//# sourceMappingURL=typosquat.js.map