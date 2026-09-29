/**
 * The id a local Semgrep rule's findings are stored under.
 *
 * Semgrep names a rule loaded from a local file by that file's DIRECTORY,
 * dotted, plus the rule's own `id` — Python's
 * `".".join(Path(config).parts[:-1]).lstrip("./").lstrip(".")`, every
 * character outside `[A-Za-z0-9._-]` dropped, the config path first made
 * relative to Semgrep's WORKING DIRECTORY when it lies under it (measured on
 * 1.176.1, and read in its `rule_lang.py`; cwd = the project):
 *
 *   `<project>\.semgrep.yml`, rule `r`         → `r`
 *   `<project>\rules\team.yml`                 → `rules.r`
 *   `<project>\.guardian\rules\r.yml`          → `guardian.rules.r`
 *   `<project>\my rules.d\x.yml`               → `myrules.d.r`
 *   `C:\Users\ADMINI~1\…\cfg dir\v2.0.1\x.yml` → `C.Users.ADMINI1.….cfgdir.v2.0.1.r`
 *     (outside the working directory: the whole absolute path)
 *
 * The fingerprint and the identity (`fingerprint/findingIdentity.ts`) both
 * hash `rule_id`. The plugin's own packs (`configs/semgrep/*.yml`: bug_hunt's
 * bugfix packs, compliance_check's RGPD pack) live under the plugin's
 * install — a new path with every version — so every one of their findings
 * changed identity on each update: baselines stopped matching, suppressions
 * stopped applying (fix round 2). A project's own rules changed whenever
 * Semgrep ran from anywhere but the project (review_pr runs from a
 * temporary tree).
 *
 * The parser stores one id per rule (`scannerParsers/semgrep.ts#semgrepParserFor`):
 *   - a rule of a file INSIDE the project: the id Semgrep gives it from the
 *     project root (`rules.r`, `configs.semgrep.r`) — what every scan run
 *     from the project always stored, so nothing stored changes;
 *   - a rule of one of the PLUGIN's own packs — a file directly in the
 *     plugin's own `configs/semgrep/`, found from the plugin's root
 *     (`platform/configsDir.ts`), never from a path segment of that name:
 *     the rule's own id;
 *   - a rule of any other file (a rule directory registered outside the
 *     project): Semgrep's own id, the absolute path prefixed — stable while
 *     that directory stays where it is, and two files that define the same
 *     rule id in two directories stay two rules (fix round 3, I-2: stripping
 *     the path merged `team/js/no-eval` and `team/v2/no-eval` into one).
 * Stored plugin-pack rows are re-keyed at startup (`storage/localRuleIds.ts`).
 * Registry configs (`auto`, `p/php`, `r/…`, a URL) carry no path prefix and
 * are left alone. `fixpr/semgrepFix.ts#checkIdMatches` reads every spelling.
 */
import { readdirSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { parse as parseYaml } from 'yaml';
import { resolveConfigsDir } from '../platform/configsDir.js';
/** Python's `Path(p).parts` for the strings a `--config` holds: the anchor (drive, UNC share, `/`) is one part. */
function pathParts(p) {
    const rest = (s) => s.split(/[\\/]+/).filter((part) => part !== '' && part !== '.');
    const unc = /^[\\/]{2}([^\\/]+)[\\/]+([^\\/]+)[\\/]*/.exec(p);
    if (unc !== null)
        return [`\\\\${unc[1] ?? ''}\\${unc[2] ?? ''}\\`, ...rest(p.slice(unc[0].length))];
    const drive = /^([A-Za-z]:)([\\/]*)/.exec(p);
    if (drive !== null)
        return [`${drive[1] ?? ''}${(drive[2] ?? '').length > 0 ? '\\' : ''}`, ...rest(p.slice(drive[0].length))];
    // Rooted: `/` on POSIX (stripped with the dots below), `\` on Windows (kept, as Python keeps it).
    const root = p[0];
    if (root === '/' || root === '\\')
        return [root, ...rest(p)];
    return rest(p);
}
/** Semgrep's prefix for the rules of the rule FILE `configPath`, spelled as Semgrep was given it. */
export function semgrepConfigPrefix(configPath) {
    const parts = pathParts(configPath);
    parts.pop(); // the file itself
    return parts
        .join('.')
        .replace(/^[./]+/, '')
        .replace(/[^A-Za-z0-9._-]/g, '');
}
/** The plugin's own pack directory: `<plugin root>/configs/semgrep`. */
export function pluginPacksDir() {
    return path.join(resolveConfigsDir(), 'semgrep');
}
/**
 * The path functions for a set of paths: Windows' when any of them is a
 * drive or UNC path, else POSIX's — so a container's `/src` paths read as
 * POSIX on a Windows host, and the answer never depends on the host.
 */
function flavourOf(...paths) {
    return paths.some((p) => p !== undefined && /^([A-Za-z]:[\\/]|[\\/]{2}[^\\/])/.test(p)) ? path.win32 : path.posix;
}
/** `target` relative to `root` when it lies inside it (Windows: case-insensitive), else null. */
function insideRelative(fp, root, target) {
    const rel = fp.relative(root, target);
    if (rel === '' || fp.isAbsolute(rel) || rel === '..' || rel.startsWith(`..${fp.sep}`) || rel.startsWith('../'))
        return null;
    return rel;
}
function samePath(fp, a, b) {
    const x = fp.resolve(a);
    const y = fp.resolve(b);
    return fp === path.win32 ? x.toLowerCase() === y.toLowerCase() : x === y;
}
/** A `--config` that names a local rule file or directory — not a registry pack, `auto` or a URL. */
function localKind(config) {
    if (/^[a-z][a-z0-9+.-]*:\/\//i.test(config))
        return null;
    if (/\.ya?ml$/i.test(config))
        return 'file';
    if (config.startsWith('/') || /^[A-Za-z]:[\\/]/.test(config) || /^[\\/]{2}/.test(config))
        return 'dir';
    return null;
}
/**
 * For one local config: the prefixes Semgrep may have given its rules, and
 * the one they are stored under (see the module comment). A rule DIRECTORY
 * prefixes each file's rules with itself and the subdirectory the file is
 * in; the subdirectory is kept.
 */
function spellingsOf(config, ctx, packsDir) {
    const kind = localKind(config);
    if (kind === null)
        return [];
    const cwd = ctx.cwd ?? ctx.projectPath;
    const fp = flavourOf(config, ctx.projectPath, cwd);
    const absolute = fp.isAbsolute(config) ? config : cwd !== undefined ? fp.resolve(cwd, config) : undefined;
    if (absolute === undefined)
        return [];
    // A directory's rules sit (at least) one level below it: the prefix of a file in it.
    const asFile = kind === 'file' ? absolute : fp.join(absolute, 'x.yml');
    const inProject = ctx.projectPath === undefined ? null : insideRelative(fp, ctx.projectPath, asFile);
    const underCwd = cwd === undefined ? null : insideRelative(fp, cwd, asFile);
    const isPack = inProject === null && samePath(fp, fp.dirname(asFile), packsDir);
    const to = inProject !== null ? semgrepConfigPrefix(inProject) : isPack ? '' : semgrepConfigPrefix(asFile);
    const froms = new Set([semgrepConfigPrefix(asFile), ...(underCwd !== null ? [semgrepConfigPrefix(underCwd)] : [])]);
    return [...froms].filter((from) => from.length > 0 && from !== to).map((from) => ({ from, to }));
}
/**
 * `checkId` as it is stored (the module comment): the path prefix of
 * whichever of `configs` it came from replaced — the longest that matches —
 * or unchanged (a registry rule, a config this scan did not pass, one already
 * in its stored spelling).
 */
export function localRuleIdNormalizer(configs, ctx = {}) {
    const packsDir = ctx.packsDir ?? pluginPacksDir();
    const byFrom = new Map();
    for (const config of configs) {
        for (const { from, to } of spellingsOf(config, ctx, packsDir))
            if (!byFrom.has(from))
                byFrom.set(from, to);
    }
    const spellings = [...byFrom].sort((a, b) => b[0].length - a[0].length);
    if (spellings.length === 0)
        return (checkId) => checkId;
    return (checkId) => {
        for (const [from, to] of spellings) {
            if (checkId.length > from.length + 1 && checkId.startsWith(`${from}.`)) {
                const rest = checkId.slice(from.length + 1);
                return to.length > 0 ? `${to}.${rest}` : rest;
            }
        }
        return checkId;
    };
}
/**
 * Whether NO rule of a run loaded: every config is a local rule file (no
 * registry pack, no directory) and every rule those files declare — named as
 * its findings are stored — is in `failed`. False whenever that cannot be
 * told (a registry pack ran, a file cannot be read or declares nothing): the
 * run then stays a narrower gap (fix round 3, M-1 — a scanner that ran on
 * nothing is never ok). `readAt` maps a config to the file to READ when the
 * run saw it under another name — the Docker fallback passes `/src/…`, the
 * container's view of the project, and the rules are read on the host
 * (round 3's review, I-1: read as `/src/.semgrep.yml` on the host, they were
 * never found, and the run stayed partial).
 */
export function noRuleLoaded(configs, failed, ctx = {}, readAt = (config) => config) {
    if (configs.length === 0 || failed.length === 0)
        return false;
    if (configs.some((c) => localKind(c) !== 'file'))
        return false;
    const normalize = localRuleIdNormalizer(configs, ctx);
    const failedIds = new Set(failed.map((f) => f.rule_id));
    const cwd = ctx.cwd ?? ctx.projectPath;
    for (const config of configs) {
        const fp = flavourOf(config, ctx.projectPath, cwd);
        const file = fp.isAbsolute(config) ? config : cwd !== undefined ? fp.resolve(cwd, config) : config;
        const ids = ruleIdsInFile(readAt(file));
        if (ids.length === 0)
            return false;
        for (const id of ids) {
            const prefix = semgrepConfigPrefix(file);
            if (!failedIds.has(normalize(prefix.length > 0 ? `${prefix}.${id}` : id)))
                return false;
        }
    }
    return true;
}
/** How many YAML files {@link mayHoldTaintRules} reads under one rule directory before it answers "may". */
const TAINT_SCAN_FILE_LIMIT = 500;
/**
 * Whether a run of `configs` can hold a taint rule — what tells a fixpoint
 * timeout that names a plugin-pack rule first of several apart from one that
 * may also be another config's (`semgrepReport.ts`). A config may, unless it
 * is PROVEN not to: a registry pack, `auto` or a URL always may, and so does
 * a local file that cannot be read or parsed, a directory past
 * {@link TAINT_SCAN_FILE_LIMIT} files, and any file whose text names
 * `taint`, `pattern-sources` or `pattern-sinks` anywhere, in any case. The
 * test is on those tokens and never on a key: Semgrep 1.176.1 runs a rule
 * with a `taint:` block and no `mode:` as a taint rule (round 4, A-2: read
 * by its `mode` alone, it read as taint-free and the pack took a group of
 * two rules), and the syntax keeps changing. A directory is read
 * recursively, as Semgrep loads it. `readAt` maps a config to the file to
 * read (the Docker fallback's `/src/…`).
 */
export function mayHoldTaintRules(configs, readAt = (c) => c) {
    for (const config of configs) {
        const kind = localKind(config);
        if (kind === null)
            return true;
        const at = readAt(config);
        if (kind === 'file') {
            if (fileMayHoldTaintRule(at))
                return true;
            continue;
        }
        const files = yamlFilesUnder(at, TAINT_SCAN_FILE_LIMIT);
        if (files === null || files.some((file) => fileMayHoldTaintRule(file)))
            return true;
    }
    return false;
}
/** Tokens any spelling of a taint rule has used: `mode: taint`, a `taint:` block, sources and sinks. */
const TAINT_TOKENS = /taint|pattern-sources|pattern-sinks/i;
/** Whether a rule file may hold a taint rule: true unless it reads, parses and names none of {@link TAINT_TOKENS}. */
function fileMayHoldTaintRule(file) {
    let text;
    try {
        text = readFileSync(file, 'utf8');
    }
    catch {
        return true;
    }
    if (TAINT_TOKENS.test(text))
        return true;
    try {
        parseYaml(text);
    }
    catch {
        return true;
    }
    return false;
}
/**
 * Every spelling Semgrep gives, in one run, a rule of the plugin's own packs:
 * `<prefix>.<rule id>`, where the prefix is Semgrep's for the pack file as it
 * was passed (`packConfigs`: the host path natively, `/guardian-packs/…` in
 * the Docker fallback) and, when the file lies under Semgrep's working
 * directory `cwd`, the one relative to it. Never a bare id: a project-root
 * rule named like a pack rule is spelled bare and is NOT the pack's (round 4,
 * A-1: matched through the normalised id, it was). `readAt` maps a config to
 * the file its ids are read from.
 */
export function pluginPackCheckIds(packConfigs, opts = {}) {
    const out = new Set();
    for (const config of packConfigs) {
        const fp = flavourOf(config, opts.cwd);
        const absolute = fp.isAbsolute(config) ? config : opts.cwd !== undefined ? fp.resolve(opts.cwd, config) : config;
        const underCwd = opts.cwd === undefined ? null : insideRelative(fp, opts.cwd, absolute);
        const prefixes = new Set([semgrepConfigPrefix(config), semgrepConfigPrefix(absolute), ...(underCwd !== null ? [semgrepConfigPrefix(underCwd)] : [])]);
        const ids = ruleIdsInFile(opts.readAt !== undefined ? opts.readAt(config) : config);
        for (const prefix of prefixes) {
            if (prefix.length === 0)
                continue;
            for (const id of ids)
                out.add(`${prefix}.${id}`);
        }
    }
    return out;
}
/** Every `.yml`/`.yaml` file under `dir`, recursively; null past `limit` files or when `dir` cannot be read. */
function yamlFilesUnder(dir, limit) {
    const out = [];
    const stack = [dir];
    while (stack.length > 0) {
        const current = stack.pop();
        if (current === undefined)
            break;
        let entries;
        try {
            entries = readdirSync(current, { withFileTypes: true });
        }
        catch {
            return null;
        }
        for (const entry of entries) {
            const full = path.join(current, entry.name);
            if (entry.isDirectory())
                stack.push(full);
            else if (/\.ya?ml$/i.test(entry.name)) {
                out.push(full);
                if (out.length > limit)
                    return null;
            }
        }
    }
    return out;
}
/** Every rule id the YAML rule files of `dir` declare (not recursive); unreadable files are skipped. */
export function ruleIdsInDir(dir) {
    const ids = new Set();
    let names;
    try {
        names = readdirSync(dir);
    }
    catch {
        return ids;
    }
    for (const name of names) {
        if (!/\.ya?ml$/i.test(name))
            continue;
        for (const id of ruleIdsInFile(path.join(dir, name)))
            ids.add(id);
    }
    return ids;
}
/** Every rule id a YAML rule file declares (`rules[].id`); none when it cannot be read or parsed. */
export function ruleIdsInFile(file) {
    let doc;
    try {
        doc = parseYaml(readFileSync(file, 'utf8'));
    }
    catch {
        return [];
    }
    const rules = doc !== null && typeof doc === 'object' ? doc.rules : undefined;
    if (!Array.isArray(rules))
        return [];
    return rules.flatMap((rule) => {
        const id = rule !== null && typeof rule === 'object' ? rule.id : undefined;
        return typeof id === 'string' && id.length > 0 ? [id] : [];
    });
}
/** A version directory as Claude Code's plugin cache names one: `2.0.1`, `3.0.0-rc.1`, or a commit. */
const VERSION_DIR = /^(\d+(\.\d+)*(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?|[0-9a-f]{7,40})$/;
/**
 * Recognises a stored rule id written before fix round 2 for one of the
 * plugin's own packs, installed at `packsDir` (`<root>/configs/semgrep`)
 * now: `<an install of this plugin>.configs.semgrep.<pack rule id>` →
 * `<pack rule id>`, else null. "An install of this plugin" is its root; and
 * when the root is a version directory of Claude Code's cache
 * (`…/<marketplace>/dev-guardian/<version>/`, {@link VERSION_DIR}), exactly
 * one other version directory beside it — never a deeper path, never a
 * sibling of a root that is not a version (`--plugin-dir C:\src\dev-guardian`,
 * a fork's directory: those keep their old ids, by design; round 3's review,
 * M-3/M-4). Identified from the plugin's root, never from a path segment
 * named `configs/semgrep` (a project's or a registered rule directory's of
 * that name keeps its id). The rule id must be one the packs declare. A
 * project rule or a registered rule outside the project is never re-keyed:
 * its stored id is what a scan stores today.
 */
export function pluginPackIdMatcher(packsDir, packRuleIds) {
    const fp = flavourOf(packsDir);
    const root = fp.dirname(fp.dirname(fp.resolve(packsDir)));
    const own = semgrepConfigPrefix(fp.join(root, 'configs', 'semgrep', 'x.yml'));
    const parent = semgrepConfigPrefix(fp.join(fp.dirname(root), 'x.yml'));
    const versioned = VERSION_DIR.test(fp.basename(root)) && parent.length > 0;
    return (ruleId) => {
        const m = /^(.+)\.configs\.semgrep\.([A-Za-z0-9_-]+)$/.exec(ruleId);
        if (m === null)
            return null;
        const installed = m[1] ?? '';
        const id = m[2] ?? '';
        if (!packRuleIds.has(id))
            return null;
        if (`${installed}.configs.semgrep` === own)
            return id;
        if (!versioned || !installed.startsWith(`${parent}.`))
            return null;
        return VERSION_DIR.test(installed.slice(parent.length + 1)) ? id : null;
    };
}
//# sourceMappingURL=semgrepRuleIds.js.map