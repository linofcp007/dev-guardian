/**
 * A local Semgrep rule's id, without the path of the machine it ran on.
 *
 * Semgrep names a rule loaded from a local file by that file's DIRECTORY,
 * dotted, plus the rule's own `id` — Python's
 * `".".join(Path(config).parts[:-1]).lstrip("./").lstrip(".")`, every
 * character outside `[A-Za-z0-9._-]` dropped, the config path first made
 * relative to the working directory when it lies under it. Measured on
 * 1.176.1 (cwd = the project):
 *
 *   `<project>\.semgrep.yml`, rule `r`         → `r`
 *   `<project>\rules\team.yml`                 → `rules.r`
 *   `<project>\.guardian\rules\r.yml`          → `guardian.rules.r`
 *   `<project>\my rules.d\x.yml`               → `myrules.d.r`
 *   `C:\Users\ADMINI~1\…\cfg dir\v2.0.1\x.yml` → `C.Users.ADMINI1.….cfgdir.v2.0.1.r`
 *     (outside the working directory: the whole absolute path)
 *
 * The rule's fingerprint and identity (`fingerprint/findingIdentity.ts`)
 * both hash `rule_id`, and the plugin's own packs (`configs/semgrep/*.yml`:
 * bug_hunt's bugfix packs, compliance_check's RGPD pack) live under the
 * plugin's install — a new path with every version, another on every CI
 * runner. So every one of their findings changed identity on each update:
 * baselines stopped matching, suppressions stopped applying (fix round 2).
 * A project's own rules were only safe while Semgrep happened to run from
 * the project (review_pr runs from a temporary tree, create_fix_pr from a
 * worktree: the whole absolute path again).
 *
 * The parser now stores one canonical id per rule
 * (`scannerParsers/semgrep.ts#semgrepParserFor`):
 *   - a rule of one of the plugin's packs — any `configs/semgrep/` file, the
 *     layout they ship in — or of a file outside the project: its own id;
 *   - a rule of a file inside the project: the id Semgrep gives it from the
 *     project root (`rules.r`), which does not move with the checkout.
 * Stored rows are re-keyed once at startup (`storage/localRuleIds.ts`).
 * Registry configs (`auto`, `p/php`, `r/…`, a URL) carry no path prefix and
 * are left alone. `fixpr/semgrepFix.ts#checkIdMatches` reads every spelling.
 */

import { isAbsolute, relative } from 'node:path';

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

/** A `--config` that names a local rule file or directory — not a registry pack, `auto` or a URL. */
function localKind(config: string): 'file' | 'dir' | null {
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(config)) return null;
  if (/\.ya?ml$/i.test(config)) return 'file';
  if (config.startsWith('/') || /^[A-Za-z]:[\\/]/.test(config) || /^[\\/]{2}/.test(config)) return 'dir';
  return null;
}

/** The plugin's pack layout (`configs/semgrep/<pack>.yml`), wherever it is installed. */
function isPackFile(config: string): boolean {
  return /(^|[\\/])configs[\\/]semgrep[\\/][^\\/]+$/i.test(config);
}

/** `path` relative to `root` when it lies inside it (node's own case rule per platform), else null. */
function insideRelative(root: string, path: string): string | null {
  const rel = relative(root, path);
  return rel === '' || rel === '..' || rel.startsWith(`..${'/'}`) || rel.startsWith('..\\') || isAbsolute(rel) ? null : rel;
}

/**
 * For each local config, the prefixes Semgrep may have given its rules and
 * the canonical one (see the module comment). A rule DIRECTORY (an absolute
 * path) prefixes its files' rules with itself and the subdirectory each is
 * in; the subdirectory is kept.
 */
function spellingsOf(config: string, projectPath: string | undefined): Array<{ from: string; to: string }> {
  const kind = localKind(config);
  if (kind === null) return [];
  // A directory's rules sit one level below it: the prefix of a file in it.
  const asFile = kind === 'file' ? config : `${config.replace(/[\\/]+$/, '')}/x.yml`;
  const rel = projectPath === undefined ? null : insideRelative(projectPath, asFile);
  const to = kind === 'file' && isPackFile(config) ? '' : rel === null ? '' : semgrepConfigPrefix(rel);
  const froms = [semgrepConfigPrefix(asFile), ...(rel !== null ? [semgrepConfigPrefix(rel)] : [])];
  return froms.filter((from) => from.length > 0 && from !== to).map((from) => ({ from, to }));
}

/**
 * `checkId` in its canonical spelling (the module comment): the path prefix
 * of whichever of `configs` it came from replaced — the longest that matches
 * — or unchanged (a registry rule, a config this scan did not pass, one
 * already canonical). `projectPath` is the project the configs were resolved
 * for (create_fix_pr: the origin project, not its worktree).
 */
export function localRuleIdNormalizer(
  configs: readonly string[],
  projectPath?: string,
): (checkId: string) => string {
  const byFrom = new Map<string, string>();
  for (const config of configs) {
    for (const { from, to } of spellingsOf(config, projectPath)) if (!byFrom.has(from)) byFrom.set(from, to);
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

/**
 * For a rule id stored before the parser made it canonical: its canonical
 * form when `ruleId` is recognisably a path-prefixed LOCAL id, else null.
 *
 *   - one of the plugin's packs — they live in `configs/semgrep/`, wherever
 *     the plugin is installed: `….configs.semgrep.<id>` → `<id>`;
 *   - a rule file inside the project, reported with the project's absolute
 *     path (Semgrep run from elsewhere): `<project, dotted>.<rest>` → `<rest>`,
 *     the id Semgrep gives it from the project root.
 *
 * Only a pack rule id without dots is taken as the rule's own (the packs'
 * convention). A registry id never contains `configs.semgrep`; and a
 * project prefix of one component (`/python`) could be a registry
 * namespace, so after one only a dotless rest is taken. Anything else is
 * left alone rather than guessed.
 */
export function storedLocalRuleId(ruleId: string, projectPath: string): string | null {
  const pack = /(?:^|\.)configs\.semgrep\.([A-Za-z0-9_-]+)$/.exec(ruleId);
  if (pack?.[1] !== undefined) return pack[1];
  const prefix = semgrepConfigPrefix(`${projectPath.replace(/[\\/]+$/, '')}/x.yml`);
  if (prefix.length === 0 || !ruleId.startsWith(`${prefix}.`)) return null;
  const rest = ruleId.slice(prefix.length + 1).replace(/^\.+/, '');
  if (rest.length === 0) return null;
  const segments = prefix.split('.').filter((s) => s.length > 0).length;
  if (/^[A-Za-z0-9_-]+$/.test(rest) || segments >= 2) return rest;
  return null;
}
