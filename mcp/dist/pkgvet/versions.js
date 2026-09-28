/**
 * "Which version would this install?" — just enough version-range logic to
 * name the version a package manager would pick, so the malware, advisory
 * and publish-age checks look at THAT version rather than at the package in
 * general.
 *
 * Why it matters: OSV records a compromised release as a `MAL-` advisory on
 * the affected versions only (the 2025 npm worm shipped as patch releases of
 * otherwise-healthy packages). Asking about the package without a version
 * would deny every future install of a package that was compromised once;
 * asking about the wrong version would miss the bad one.
 *
 * Not a full implementation of node-semver, PEP 440, Composer or NuGet
 * ranges — the common operators of each (`^ ~ >= > <= < = x *`, hyphen
 * ranges and `||` for npm/Composer; `== != ~= >= <= > <` and `.*` for PyPI;
 * interval notation for NuGet). Anything it cannot parse returns
 * `undefined`, and the caller reports the version as unresolved — it never
 * guesses.
 *
 * Pure functions. No I/O.
 */
const POST_REST = /^[-._]?(?:post|rev|r|p|patch|pl)[-._]?\d*$/i;
const DEV_REST = /(?:^|[-._])dev/i;
function parse(version) {
    let s = version.trim().replace(/^[vV=]+/, '');
    const plus = s.indexOf('+');
    if (plus >= 0)
        s = s.slice(0, plus);
    const m = /^(\d+(?:\.\d+)*)(.*)$/.exec(s);
    if (m === null)
        return null;
    const releaseText = m[1] ?? '';
    const rest = m[2] ?? '';
    const release = releaseText.split('.').map((x) => Number(x));
    if (release.some((n) => !Number.isFinite(n)))
        return null;
    let stage = 2;
    if (rest !== '') {
        if (POST_REST.test(rest))
            stage = 3;
        else if (DEV_REST.test(rest))
            stage = 0;
        else
            stage = 1;
    }
    return { release, stage, rest };
}
function compareRelease(a, b) {
    const n = Math.max(a.length, b.length);
    for (let i = 0; i < n; i += 1) {
        const d = (a[i] ?? 0) - (b[i] ?? 0);
        if (d !== 0)
            return d;
    }
    return 0;
}
function compareRest(a, b) {
    const ta = a.split(/[-._]|(?<=\d)(?=\D)|(?<=\D)(?=\d)/).filter(Boolean);
    const tb = b.split(/[-._]|(?<=\d)(?=\D)|(?<=\D)(?=\d)/).filter(Boolean);
    const n = Math.max(ta.length, tb.length);
    for (let i = 0; i < n; i += 1) {
        const x = ta[i];
        const y = tb[i];
        if (x === undefined)
            return -1;
        if (y === undefined)
            return 1;
        const nx = Number(x);
        const ny = Number(y);
        if (Number.isFinite(nx) && Number.isFinite(ny)) {
            if (nx !== ny)
                return nx - ny;
        }
        else if (x.toLowerCase() !== y.toLowerCase()) {
            return x.toLowerCase() < y.toLowerCase() ? -1 : 1;
        }
    }
    return 0;
}
/** Negative, zero or positive, like a sort comparator. Unparseable sorts first. */
export function compareVersions(a, b) {
    const pa = parse(a);
    const pb = parse(b);
    if (pa === null || pb === null)
        return pa === null ? (pb === null ? 0 : -1) : 1;
    const r = compareRelease(pa.release, pb.release);
    if (r !== 0)
        return r;
    if (pa.stage !== pb.stage)
        return pa.stage - pb.stage;
    return compareRest(pa.rest, pb.rest);
}
export function isPrerelease(version) {
    const p = parse(version);
    return p === null || p.stage < 2;
}
const gte = (x) => (v) => compareVersions(v, x) >= 0;
const gt = (x) => (v) => compareVersions(v, x) > 0;
const lt = (x) => (v) => compareVersions(v, x) < 0;
const lte = (x) => (v) => compareVersions(v, x) <= 0;
const eq = (x) => (v) => compareVersions(v, x) === 0;
const ANY = () => true;
const WILD = /^[xX*]$/;
/** `1`, `1.2`, `1.2.3-beta`, `1.x`, `1.2.*` → the concrete leading numbers (wildcards end it). */
function partial(text) {
    const t = text.trim().replace(/^[vV]/, '');
    if (t === '' || WILD.test(t))
        return { nums: [], pre: '' };
    const plus = t.indexOf('+');
    const noBuild = plus >= 0 ? t.slice(0, plus) : t;
    const dash = noBuild.search(/-/);
    const core = dash >= 0 ? noBuild.slice(0, dash) : noBuild;
    const pre = dash >= 0 ? noBuild.slice(dash) : '';
    const nums = [];
    for (const part of core.split('.')) {
        if (WILD.test(part))
            break;
        if (!/^\d+$/.test(part))
            return null;
        nums.push(Number(part));
    }
    return { nums, pre };
}
const fmt = (nums) => [0, 1, 2].map((i) => nums[i] ?? 0).join('.');
/** The first version after every version with this prefix: `1.2` → `1.3.0`. */
function bump(nums) {
    const next = nums.slice();
    const last = next.length - 1;
    next[last] = (next[last] ?? 0) + 1;
    return fmt(next);
}
/** One npm/Composer comparator → predicates. `tilde` differs: npm `~1.2` is `<1.3`, Composer `~1.2` is `<2.0`. */
function comparator(op, text, composerTilde) {
    const p = partial(text);
    if (p === null)
        return null;
    const { nums, pre } = p;
    const full = nums.length >= 3;
    const exact = full ? fmt(nums) + pre : fmt(nums);
    switch (op) {
        case '':
        case '=':
        case '==':
            if (nums.length === 0)
                return [ANY];
            if (full)
                return [eq(exact)];
            return [gte(fmt(nums)), lt(bump(nums))];
        case '^': {
            if (nums.length === 0)
                return [ANY];
            const [major = 0, minor, patch] = nums;
            if (major > 0 || nums.length === 1)
                return [gte(exact), lt(bump([major]))];
            if ((minor ?? 0) > 0 || nums.length === 2)
                return [gte(exact), lt(bump([0, minor ?? 0]))];
            return [gte(exact), lt(bump([0, 0, patch ?? 0]))];
        }
        case '~':
        case '~>': {
            if (nums.length === 0)
                return [ANY];
            if (nums.length === 1)
                return [gte(exact), lt(bump(nums))];
            if (composerTilde && nums.length === 2)
                return [gte(exact), lt(bump(nums.slice(0, 1)))];
            return [gte(exact), lt(bump(nums.slice(0, 2)))];
        }
        case '>=':
            return [gte(exact)];
        case '>':
            return full ? [gt(exact)] : nums.length === 0 ? [() => false] : [gte(bump(nums))];
        case '<':
            return [lt(exact)];
        case '<=':
            return full ? [lte(exact)] : nums.length === 0 ? [ANY] : [lt(bump(nums))];
        case '!=':
            return [(v) => !eq(exact)(v)];
        default:
            return null;
    }
}
const COMPARATOR = /^(\^|~>|~|>=|<=|>|<|==|=|!=)?\s*(.*)$/;
/** npm and Composer: `||` (Composer also `|`) of space- (Composer also comma-) separated comparators. */
function semverishRange(range, composer) {
    const alternatives = range.split(composer ? /\s*\|\|?\s*/ : /\s*\|\|\s*/);
    const out = [];
    for (const alt of alternatives) {
        let text = alt.trim();
        if (composer)
            text = text.replace(/@[a-zA-Z]+$/, '').trim();
        if (text === '' || text === '*' || WILD.test(text)) {
            out.push([ANY]);
            continue;
        }
        const hyphen = /^(\S+)\s+-\s+(\S+)$/.exec(text);
        if (hyphen !== null) {
            const lo = comparator('>=', hyphen[1] ?? '', composer);
            const hiPartial = partial(hyphen[2] ?? '');
            if (lo === null || hiPartial === null)
                return null;
            const hi = hiPartial.nums.length >= 3 ? [lte(fmt(hiPartial.nums) + hiPartial.pre)] : hiPartial.nums.length === 0 ? [ANY] : [lt(bump(hiPartial.nums))];
            out.push([...lo, ...hi]);
            continue;
        }
        // Glue a detached operator to its operand: `>= 1.2` -> `>=1.2`.
        const tokens = text.replace(/(\^|~>|~|>=|<=|>|<|==|=|!=)\s+/g, '$1').split(composer ? /[\s,]+/ : /\s+/);
        const preds = [];
        for (const token of tokens) {
            if (token === '')
                continue;
            const m = COMPARATOR.exec(token);
            if (m === null)
                return null;
            const c = comparator(m[1] ?? '', m[2] ?? '', composer);
            if (c === null)
                return null;
            preds.push(...c);
        }
        out.push(preds);
    }
    return out;
}
const PEP440 = /^\s*(~=|===|==|!=|<=|>=|<|>)\s*([^\s,]+)\s*$/;
function pep440Range(range) {
    const preds = [];
    for (const spec of range.split(',')) {
        if (spec.trim() === '')
            continue;
        const m = PEP440.exec(spec);
        if (m === null)
            return null;
        const op = m[1] ?? '';
        const ver = m[2] ?? '';
        if (op === '===') {
            preds.push((v) => v === ver);
            continue;
        }
        if (ver.endsWith('.*')) {
            const prefix = partial(ver.slice(0, -2));
            if (prefix === null || prefix.nums.length === 0)
                return null;
            const inPrefix = (v) => {
                const p = parse(v);
                return p !== null && prefix.nums.every((n, i) => (p.release[i] ?? 0) === n);
            };
            if (op === '==')
                preds.push(inPrefix);
            else if (op === '!=')
                preds.push((v) => !inPrefix(v));
            else
                return null;
            continue;
        }
        if (parse(ver) === null)
            return null;
        switch (op) {
            case '==':
                preds.push(eq(ver));
                break;
            case '!=':
                preds.push((v) => !eq(ver)(v));
                break;
            case '>=':
                preds.push(gte(ver));
                break;
            case '<=':
                preds.push(lte(ver));
                break;
            case '>':
                preds.push(gt(ver));
                break;
            case '<':
                preds.push(lt(ver));
                break;
            case '~=': {
                const p = parse(ver);
                if (p === null || p.release.length < 2)
                    return null;
                const prefix = p.release.slice(0, -1);
                preds.push(gte(ver), (v) => {
                    const q = parse(v);
                    return q !== null && prefix.every((n, i) => (q.release[i] ?? 0) === n);
                });
                break;
            }
            default:
                return null;
        }
    }
    return [preds];
}
/** NuGet interval notation: `[1.0,2.0)`, `(,2.0]`, `[1.0]`; a bare version is exact. */
function nugetRange(range) {
    const r = range.trim();
    const m = /^([[(])\s*([^,\])]*?)\s*(?:,\s*([^\])]*?)\s*)?([\])])$/.exec(r);
    if (m === null)
        return parse(r) === null ? null : [[eq(r)]];
    const open = m[1];
    const lo = m[2] ?? '';
    const hasComma = r.includes(',');
    const hi = m[3] ?? '';
    const close = m[4];
    if (!hasComma)
        return lo === '' ? null : [[eq(lo)]];
    const preds = [];
    if (lo !== '')
        preds.push(open === '[' ? gte(lo) : gt(lo));
    if (hi !== '')
        preds.push(close === ']' ? lte(hi) : lt(hi));
    return [preds];
}
const EXACT_SEMVER = /^[vV=]?\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;
/**
 * True when `range` names one specific version rather than a set — so a
 * miss is "that version is not published" rather than "nothing matches".
 */
export function isExactVersion(ecosystem, range) {
    if (range === undefined)
        return false;
    const r = range.trim();
    switch (ecosystem) {
        case 'npm':
            return EXACT_SEMVER.test(r);
        case 'pypi':
            return /^(?:===?)\s*[^*,<>=!~\s]+$/.test(r) || (/^\d/.test(r) && parse(r) !== null && !/[,<>=!~*]/.test(r));
        case 'packagist':
            return /^[vV]?\d+(?:\.\d+){0,3}(?:-[0-9A-Za-z.]+)?$/.test(r);
        case 'nuget':
            return parse(r) !== null && !/[[\](),]/.test(r);
        default:
            return false;
    }
}
function highest(versions) {
    let best;
    for (const v of versions)
        if (best === undefined || compareVersions(v, best) > 0)
            best = v;
    return best;
}
/**
 * The version the package manager would install for `range`, among
 * `ctx.versions`. `undefined` when the range is unparseable, matches
 * nothing, or names a version that is not published.
 */
export function resolveVersion(ecosystem, range, ctx) {
    const stable = ctx.versions.filter((v) => !isPrerelease(v));
    const r = range?.trim() ?? '';
    if (r === '' || (ecosystem === 'npm' && r === 'latest')) {
        if (ctx.latest !== undefined && ctx.versions.includes(ctx.latest))
            return ctx.latest;
        return highest(stable);
    }
    if (ecosystem === 'npm') {
        const tagged = ctx.tags?.[r];
        if (tagged !== undefined)
            return ctx.versions.includes(tagged) ? tagged : undefined;
    }
    if (ecosystem === 'packagist' && /^dev-|-dev$/i.test(r))
        return undefined;
    if (isExactVersion(ecosystem, r)) {
        const wanted = r.replace(/^===?\s*/, '');
        return ctx.versions.find((v) => v === wanted) ?? ctx.versions.find((v) => compareVersions(v, wanted) === 0);
    }
    let alternatives;
    switch (ecosystem) {
        case 'npm':
            alternatives = semverishRange(r, false);
            break;
        case 'packagist':
            alternatives = semverishRange(r, true);
            break;
        case 'pypi':
            // Poetry accepts npm-style `^1.2` / `~1.2` / `1.*` constraints as well as PEP 440.
            alternatives = /^(?:\^|~(?!=)|\*$|\d+(?:\.\d+)*\.\*$)/.test(r) ? semverishRange(r, false) : pep440Range(r);
            break;
        case 'nuget':
            alternatives = nugetRange(r);
            break;
        default:
            alternatives = null;
    }
    if (alternatives === null)
        return undefined;
    const matching = stable.filter((v) => alternatives.some((preds) => preds.every((p) => p(v))));
    if (ecosystem === 'npm' && ctx.latest !== undefined && matching.includes(ctx.latest))
        return ctx.latest;
    return highest(matching);
}
//# sourceMappingURL=versions.js.map