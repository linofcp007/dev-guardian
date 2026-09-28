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
function pathParts(p: string): string[] {
  const rest = (s: string): string[] => s.split(/[\\/]+/).filter((part) => part !== '' && part !== '.');
  const unc = /^[\\/]{2}([^\\/]+)[\\/]+([^\\/]+)[\\/]*/.exec(p);
  if (unc !== null) return [`\\\\${unc[1] ?? ''}\\${unc[2] ?? ''}\\`, ...rest(p.slice(unc[0].length))];
  const drive = /^([A-Za-z]:)([\\/]*)/.exec(p);
  if (drive !== null) return [`${drive[1] ?? ''}${(drive[2] ?? '').length > 0 ? '\\' : ''}`, ...rest(p.slice(drive[0].length))];
  // Rooted: `/` on POSIX (stripped with the dots below), `\` on Windows (kept, as Python keeps it).
  const root = p[0];
  if (root === '/' || root === '\\') return [root, ...rest(p)];
  return rest(p);
}

/** Semgrep's prefix for the rules of the rule FILE `configPath`, spelled as Semgrep was given it. */
export function semgrepConfigPrefix(configPath: string): string {
  const parts = pathParts(configPath);
  parts.pop(); // the file itself
  return parts
    .join('.')
    .replace(/^[./]+/, '')
    .replace(/[^A-Za-z0-9._-]/g, '');
}

/** The plugin's own pack directory: `<plugin root>/configs/semgrep`. */
export function pluginPacksDir(): string {
  return path.join(resolveConfigsDir(), 'semgrep');
}

/**
 * The path functions for a set of paths: Windows' when any of them is a
 * drive or UNC path, else POSIX's — so a container's `/src` paths read as
 * POSIX on a Windows host, and the answer never depends on the host.
 */
function flavourOf(...paths: ReadonlyArray<string | undefined>): path.PlatformPath {
  return paths.some((p) => p !== undefined && /^([A-Za-z]:[\\/]|[\\/]{2}[^\\/])/.test(p)) ? path.win32 : path.posix;
}

/** `target` relative to `root` when it lies inside it (Windows: case-insensitive), else null. */
function insideRelative(fp: path.PlatformPath, root: string, target: string): string | null {
  const rel = fp.relative(root, target);
  if (rel === '' || fp.isAbsolute(rel) || rel === '..' || rel.startsWith(`..${fp.sep}`) || rel.startsWith('../')) return null;
  return rel;
}

function samePath(fp: path.PlatformPath, a: string, b: string): boolean {
  const x = fp.resolve(a);
  const y = fp.resolve(b);
  return fp === path.win32 ? x.toLowerCase() === y.toLowerCase() : x === y;
}

/** A `--config` that names a local rule file or directory — not a registry pack, `auto` or a URL. */
function localKind(config: string): 'file' | 'dir' | null {
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(config)) return null;
  if (/\.ya?ml$/i.test(config)) return 'file';
  if (config.startsWith('/') || /^[A-Za-z]:[\\/]/.test(config) || /^[\\/]{2}/.test(config)) return 'dir';
  return null;
}

export interface RuleIdContext {
  /**
   * The project the configs were resolved for — create_fix_pr's origin, not
   * its worktree. A rule file inside it keeps the id from its root.
   */
  projectPath?: string;
  /**
   * Semgrep's working directory: a relative config resolves against it, and
   * a rule file under it is reported relative to it. Default: `projectPath`.
   */
  cwd?: string;
  /** The plugin's own pack directory. Default: {@link pluginPacksDir}. */
  packsDir?: string;
}

/**
 * For one local config: the prefixes Semgrep may have given its rules, and
 * the one they are stored under (see the module comment). A rule DIRECTORY
 * prefixes each file's rules with itself and the subdirectory the file is
 * in; the subdirectory is kept.
 */
function spellingsOf(config: string, ctx: RuleIdContext, packsDir: string): Array<{ from: string; to: string }> {
  const kind = localKind(config);
  if (kind === null) return [];
  const cwd = ctx.cwd ?? ctx.projectPath;
  const fp = flavourOf(config, ctx.projectPath, cwd);
  const absolute = fp.isAbsolute(config) ? config : cwd !== undefined ? fp.resolve(cwd, config) : undefined;
  if (absolute === undefined) return [];
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
export function localRuleIdNormalizer(configs: readonly string[], ctx: RuleIdContext = {}): (checkId: string) => string {
  const packsDir = ctx.packsDir ?? pluginPacksDir();
  const byFrom = new Map<string, string>();
  for (const config of configs) {
    for (const { from, to } of spellingsOf(config, ctx, packsDir)) if (!byFrom.has(from)) byFrom.set(from, to);
  }
  const spellings = [...byFrom].sort((a, b) => b[0].length - a[0].length);
  if (spellings.length === 0) return (checkId) => checkId;
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

/** Every rule id the YAML rule files of `dir` declare (not recursive); unreadable files are skipped. */
export function ruleIdsInDir(dir: string): Set<string> {
  const ids = new Set<string>();
  let names: string[];
  try {
    names = readdirSync(dir);
  } catch {
    return ids;
  }
  for (const name of names) {
    if (!/\.ya?ml$/i.test(name)) continue;
    for (const id of ruleIdsInFile(path.join(dir, name))) ids.add(id);
  }
  return ids;
}

/** Every rule id a YAML rule file declares (`rules[].id`); none when it cannot be read or parsed. */
export function ruleIdsInFile(file: string): string[] {
  let doc: unknown;
  try {
    doc = parseYaml(readFileSync(file, 'utf8'));
  } catch {
    return [];
  }
  const rules = doc !== null && typeof doc === 'object' ? (doc as { rules?: unknown }).rules : undefined;
  if (!Array.isArray(rules)) return [];
  return rules.flatMap((rule: unknown) => {
    const id = rule !== null && typeof rule === 'object' ? (rule as { id?: unknown }).id : undefined;
    return typeof id === 'string' && id.length > 0 ? [id] : [];
  });
}

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Recognises a stored rule id written before fix round 2 for one of the
 * plugin's own packs, installed at `packsDir` (`<root>/configs/semgrep`)
 * now: `<an install of this plugin>.configs.semgrep.<pack rule id>` →
 * `<pack rule id>`, else null. "An install of this plugin" is its root, or
 * a sibling of it (Claude Code keeps each version in `…/dev-guardian/<v>/`)
 * — identified from the plugin's root, never from a path segment named
 * `configs/semgrep` (a project's or a registered rule directory's of that
 * name keeps its id). The rule id must be one the packs declare. A project
 * rule or a registered rule outside the project is never re-keyed: its
 * stored id is what a scan stores today.
 */
export function pluginPackIdMatcher(packsDir: string, packRuleIds: ReadonlySet<string>): (ruleId: string) => string | null {
  const fp = flavourOf(packsDir);
  const root = fp.dirname(fp.dirname(fp.resolve(packsDir)));
  const own = semgrepConfigPrefix(fp.join(root, 'configs', 'semgrep', 'x.yml'));
  const parent = semgrepConfigPrefix(fp.join(fp.dirname(root), 'x.yml'));
  const sibling = parent.length > 0 ? new RegExp(`^${escapeRegExp(parent)}\\.[A-Za-z0-9._-]+\\.configs\\.semgrep$`) : null;
  return (ruleId) => {
    const m = /^(.+)\.configs\.semgrep\.([A-Za-z0-9_-]+)$/.exec(ruleId);
    if (m === null) return null;
    const prefix = `${m[1] ?? ''}.configs.semgrep`;
    const id = m[2] ?? '';
    if (!packRuleIds.has(id)) return null;
    return prefix === own || (sibling?.test(prefix) ?? false) ? id : null;
  };
}
