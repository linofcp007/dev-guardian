/**
 * Where `pre-commit install` will write its hook scripts, and whether that is
 * a place dev-guardian may let it write — judged BEFORE `precommit_install`
 * runs it, because pre-commit writes wherever the repository's metadata says.
 *
 * pre-commit writes `pre-commit`, `commit-msg` and `pre-push` into the hooks
 * directory of the git directory it finds (`git rev-parse --git-common-dir`).
 * In a directory dev-guardian did not create — an archive, a download, a
 * repository someone else prepared — each piece of that is the directory's to
 * choose:
 *
 *   - `.git/hooks`, or a hook file in it, can be a link (a junction included)
 *     out of the project: the hook script lands at its end, or replaces
 *     whatever file it names;
 *   - `.git` itself can be a link to another repository's git directory;
 *   - `.git` can be a FILE (`gitdir: <path>`) naming any repository the user
 *     owns, and pre-commit then installs hooks into THAT repository.
 *
 * So the hooks directory and every hook file must not be links, and a `.git`
 * file is accepted only for the two layouts git itself writes one for: a
 * linked worktree (the git directory's own `gitdir` file points back at this
 * `.git` file) and a submodule (the git directory sits under an enclosing
 * repository's `.git/modules/`). Anything else is refused with a sentence
 * that says why.
 */

import { lstatSync, type Stats } from 'node:fs';
import { dirname, isAbsolute, join, resolve } from 'node:path';
import { isWithinDir, projectEntryKind, readProjectText } from './projectFs.js';
import { readSmallText } from '../hooks/configFile.js';

/** The hook types `precommit_install` asks pre-commit to install. */
export const PRECOMMIT_HOOK_NAMES = ['pre-commit', 'commit-msg', 'pre-push'] as const;

export type HookInstallTarget = { ok: true; hooksDir: string } | { ok: false; reason: string };

const MAX_GIT_POINTER_BYTES = 64 * 1024;

function lstatOrNull(p: string): Stats | null {
  try {
    return lstatSync(p);
  } catch {
    return null;
  }
}

/** The same path, compared as `isWithinDir` compares (case-insensitive on Windows). */
function samePath(a: string, b: string): boolean {
  return isWithinDir(a, b) && isWithinDir(b, a);
}

/** A small file git itself writes (`gitdir`, `commondir`), trimmed; `null` when unreadable or not regular. */
function readPointer(path: string): string | null {
  const r = readSmallText(path, MAX_GIT_POINTER_BYTES);
  return r.status === 'ok' ? r.text.trim() : null;
}

/**
 * The git directory a `.git` file names, when git itself would have written
 * that file for `projectPath` — a linked worktree or a submodule — or why not.
 */
function gitDirFromFile(projectPath: string): { ok: true; gitDir: string; commonDir: string } | { ok: false; reason: string } {
  const read = readProjectText(projectPath, '.git', MAX_GIT_POINTER_BYTES);
  if (read.status !== 'ok') return { ok: false, reason: '.git is a file that could not be read' };
  const m = /^gitdir:\s*(.+?)\s*$/m.exec(read.text);
  const named = m?.[1];
  if (named === undefined) return { ok: false, reason: '.git is a file without a gitdir: line' };
  const gitDir = resolve(projectPath, named);
  const dotGit = resolve(projectPath, '.git');

  // A linked worktree: `<common>/worktrees/<name>/gitdir` names this `.git` file.
  const back = readPointer(join(gitDir, 'gitdir'));
  if (back !== null && samePath(resolve(gitDir, back), dotGit)) {
    const common = readPointer(join(gitDir, 'commondir'));
    return { ok: true, gitDir, commonDir: common === null ? gitDir : resolve(gitDir, common) };
  }

  // A submodule: the git directory lives in an enclosing repository's
  // `.git/modules/`, and that repository encloses this project.
  for (let dir = dirname(resolve(projectPath)); dir !== dirname(dir); dir = dirname(dir)) {
    const modules = join(dir, '.git', 'modules');
    if (isWithinDir(modules, gitDir) && gitDir !== modules) return { ok: true, gitDir, commonDir: gitDir };
  }
  return {
    ok: false,
    reason:
      `.git is a file naming ${isAbsolute(named) ? named : gitDir}, which is neither a worktree of that repository ` +
      "(its gitdir file does not point back here) nor a submodule of one enclosing this project — pre-commit " +
      'would install hooks into another repository',
  };
}

/** Where pre-commit will write its hooks for `projectPath`, or why it must not run (a full sentence). */
export function hookInstallTarget(projectPath: string): HookInstallTarget {
  const r = judge(projectPath);
  if (r.ok || r.reason.startsWith('pre-commit needs')) return r;
  return { ok: false, reason: `pre-commit install refused: ${r.reason}.` };
}

function judge(projectPath: string): HookInstallTarget {
  const dotGit = join(projectPath, '.git');
  const kind = projectEntryKind(dotGit);
  let commonDir: string;
  if (kind === 'directory') commonDir = dotGit;
  else if (kind === 'file') {
    const g = gitDirFromFile(projectPath);
    if (!g.ok) return g;
    commonDir = g.commonDir;
  } else if (kind === 'link') {
    return { ok: false, reason: '.git is a link (a symlink or a junction); its hooks would be written wherever it leads' };
  } else if (kind === 'absent') {
    return { ok: false, reason: 'pre-commit needs a git repo to install hooks into.' };
  } else {
    return { ok: false, reason: '.git is neither a directory nor a file' };
  }

  const hooksDir = join(commonDir, 'hooks');
  const hooks = lstatOrNull(hooksDir);
  if (hooks !== null && hooks.isSymbolicLink()) {
    return { ok: false, reason: `${hooksDir} is a link (a symlink or a junction); the hooks would be written wherever it leads` };
  }
  if (hooks !== null && !hooks.isDirectory()) return { ok: false, reason: `${hooksDir} is not a directory` };
  for (const name of PRECOMMIT_HOOK_NAMES) {
    const k = projectEntryKind(join(hooksDir, name));
    if (k === 'link') {
      return { ok: false, reason: `the ${name} hook is a link (a symlink or a junction); pre-commit would write through it` };
    }
    if (k === 'directory' || k === 'other') return { ok: false, reason: `the ${name} hook is not a regular file` };
  }
  return { ok: true, hooksDir };
}
