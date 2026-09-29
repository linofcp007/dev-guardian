/**
 * The file a write really reaches, spelled so it can be compared with the
 * files the hooks guard (review M1). On Windows each of these writes the hook
 * configuration itself, and every one got past the three Write/Edit guards
 * (the project's `.guardian/hooks*.json`, the user-level
 * `~/.config/dev-guardian/hooks.json`, Claude Code's `.claude/settings*.json`):
 *
 *   - an NTFS stream suffix — `hooks.config.json::$DATA` is the file's own
 *     content, and Node writes it there; `:name` and `:name:$DATA` are
 *     alternate streams of the same file;
 *   - trailing dots and spaces, which Windows drops from every segment
 *     (`hooks.config.json.`, `.guardian.\hooks.config.json`);
 *   - an 8.3 short name (`HOOKSC~1.JSO`), and a link — resolved with
 *     `fs.realpathSync.native` when the path, or a directory above it, exists.
 *
 * `windowsName` is pure (the shell guard uses it on the paths a command
 * writes); `guardedPath` also reads the filesystem, with `lstat`/`readlink`
 * only until it knows no link on the way leads to a network or device path
 * (see `configFile.ts`), since resolving one could wait on the network past
 * the hook's timeout. Node built-ins only: the dispatcher loads the compiled
 * copy from `mcp/dist/hooks/`.
 */

import { realpathSync } from 'node:fs';
import { basename, dirname, join, parse } from 'node:path';
import { walkLinksUnder } from './configFile.js';

/** One segment as Windows opens it: no stream suffix and — outside `\\?\` paths — no trailing dots or spaces. */
function windowsSegment(segment: string, trim: boolean): string {
  if (segment === '' || segment === '.' || segment === '..') return segment;
  const colon = segment.indexOf(':');
  let named = colon < 0 ? segment : segment.slice(0, colon);
  if (trim) {
    const trimmed = named.replace(/[. ]+$/, '');
    if (trimmed !== '') named = trimmed;
  }
  return named === '' ? segment : named;
}

/**
 * `path` as Windows opens it: in every segment an NTFS stream suffix
 * (`::$DATA`, `:name:$DATA`, `:name`) is dropped, and so are trailing dots and
 * spaces — except in a `\\?\` or `\\.\` path, where Windows keeps them. A
 * leading drive (`C:`) stays. Either separator is accepted and kept.
 */
export function windowsName(path: string): string {
  if (!/[:. ]/.test(path)) return path;
  const device = /^[\\/]{2}[?.][\\/]/.test(path);
  const prefix = /^(?:[\\/]{2}[?.][\\/])?(?:[A-Za-z]:)?/.exec(path)?.[0] ?? '';
  const parts = path.slice(prefix.length).split(/([\\/]+)/);
  return prefix + parts.map((part, i) => (i % 2 === 1 ? part : windowsSegment(part, !device))).join('');
}

export interface GuardedPathOptions {
  /** Default `process.platform`: the Windows spellings are dropped only on `win32`. */
  platform?: NodeJS.Platform;
  /** Default `fs.realpathSync.native` (tests). */
  realpath?: (path: string) => string;
}

/**
 * `abs` resolved as far as it exists: the longest existing prefix through
 * `realpath` (long names, links), the rest appended as written. Unchanged when
 * a link on the way points at a network or device path, or nothing resolves.
 */
function resolveExisting(abs: string, realpath: (path: string) => string): string {
  const root = parse(abs).root;
  if (root === '' || !walkLinksUnder(root, abs).ok) return abs;
  const rest: string[] = [];
  let head = abs;
  for (let i = 0; i < 512; i += 1) {
    try {
      const real = realpath(head);
      return rest.length === 0 ? real : join(real, ...rest.reverse());
    } catch {
      const parent = dirname(head);
      if (parent === head) return abs;
      rest.push(basename(head));
      head = parent;
    }
  }
  return abs;
}

/**
 * The file an absolute path writes, for matching against a guarded file: on
 * Windows its {@link windowsName}, then — everywhere — resolved through the
 * filesystem as far as it exists. Never throws; anything unexpected leaves
 * the path as written.
 */
export function guardedPath(abs: string, opts: GuardedPathOptions = {}): string {
  const named = (opts.platform ?? process.platform) === 'win32' ? windowsName(abs) : abs;
  try {
    return resolveExisting(named, opts.realpath ?? realpathSync.native);
  } catch {
    return named;
  }
}
