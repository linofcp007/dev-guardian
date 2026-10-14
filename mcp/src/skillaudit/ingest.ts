/**
 * Target ingestion for skill audits.
 *
 * Resolves a "what do you want me to vet?" target into a flat list of text
 * files with content, plus per-file classification (code vs doc, executable
 * or not). Supported target kinds, auto-detected from the spec:
 *
 *   - local directory          → walked in place (no temp, no cleanup)
 *   - local file               → single file
 *   - local .zip               → extracted to a temp dir
 *   - git URL (…/x.git, git@…) → shallow-cloned to a temp dir (needs git)
 *   - http(s) URL to .zip       → downloaded then extracted
 *   - http(s) URL to a file     → downloaded as a single file
 *
 * Network/clone/extract are best-effort: when a tool (git/tar/unzip) or the
 * network is unavailable, ingestion returns a domain-style failure the tool
 * layer maps to `unsupported_target` / `target_not_found` rather than
 * throwing.
 *
 * Binary and oversized files are skipped (with a note) so the analyzer only
 * ever sees reviewable text.
 */

import { runProcess } from '../runners/processRunner.js';
import {
  existsSync,
  lstatSync,
  mkdtempSync,
  readdirSync,
  readlinkSync,
  realpathSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, dirname, isAbsolute, join, relative, resolve } from 'node:path';
import { describeReadRefusal, entryKindAnywhere, readProjectBytes } from '../platform/projectFs.js';
import { execGit } from '../platform/gitSafety.js';
import { networkPathOf, networkPathProblem } from '../platform/projectPath.js';
import { readSmallText } from '../hooks/configFile.js';
// A clone that stalls is stopped with its remote helper (review 10, finding 12).
import '../runners/gitExec.js';

export interface IngestedFile {
  relPath: string;
  absPath: string;
  content: string;
  /** Source/executable → run code rules and apply the executable multiplier. */
  isCode: boolean;
  isExecutable: boolean;
  bytes: number;
}

type TargetKind = 'directory' | 'file' | 'zip' | 'git' | 'url';

/**
 * A link the walk refused to follow — reported instead of read, per the
 * module header's safety rule. `kind: 'symlink'` is `lstat`'s own verdict
 * (a real symlink or, on the platforms/Node versions where `lstat` reports
 * it that way, a Windows junction); `kind: 'escaped_directory'` is the
 * second, independent guard — an ordinary directory whose REALPATH resolves
 * outside the ingestion root even though `lstat` did not flag it as a link
 * at all. `target` is always a plain string: a `readlink` result or a
 * realpath, NEVER file content — the whole point of reporting a link is to
 * name it without reading through it.
 */
export interface SymlinkEntry {
  relPath: string;
  target: string;
  kind: 'symlink' | 'escaped_directory';
}

interface IngestSuccess {
  ok: true;
  root: string;
  kind: TargetKind;
  files: IngestedFile[];
  skipped: number;
  truncated: boolean;
  warnings: string[];
  /** Every link the walk found and refused to follow. Empty for `file`/`url`
   *  kinds, which never walk a directory tree at all. */
  symlinks: SymlinkEntry[];
  cleanup(): void;
}

interface IngestFailure {
  ok: false;
  code: 'target_not_found' | 'unsupported_target';
  message: string;
}

type IngestResult = IngestSuccess | IngestFailure;

const MAX_FILES = 4000;
const MAX_TOTAL_BYTES = 25 * 1024 * 1024;
const MAX_FILE_BYTES = 2 * 1024 * 1024;

const CODE_EXT = new Set([
  '.sh', '.bash', '.zsh', '.ps1', '.bat', '.cmd',
  '.py', '.rb', '.pl', '.lua', '.php',
  '.js', '.mjs', '.cjs', '.jsx', '.ts', '.tsx',
  '.go', '.rs', '.java', '.kt', '.c', '.cc', '.cpp', '.h',
]);
const EXECUTABLE_EXT = new Set([
  '.sh', '.bash', '.zsh', '.ps1', '.bat', '.cmd', '.py', '.rb', '.pl', '.php', '.js', '.mjs', '.cjs',
]);
const DOC_EXT = new Set(['.md', '.markdown', '.txt', '.rst', '.adoc']);
const CONFIG_EXT = new Set(['.json', '.yaml', '.yml', '.toml', '.ini', '.cfg']);

const SKIP_DIRS = new Set([
  'node_modules', '.git', '.svn', '.hg', 'dist', 'build', 'out', 'vendor',
  '.venv', 'venv', '__pycache__', 'target', '.next', '.cache', 'coverage',
]);
const BINARY_EXT = new Set([
  '.png', '.jpg', '.jpeg', '.gif', '.webp', '.ico', '.bmp', '.pdf', '.zip', '.gz',
  '.tar', '.tgz', '.bz2', '.7z', '.rar', '.exe', '.dll', '.so', '.dylib', '.bin',
  '.woff', '.woff2', '.ttf', '.eot', '.mp3', '.mp4', '.mov', '.wav', '.class', '.jar',
  '.pyc', '.o', '.a', '.node', '.wasm', '.db', '.sqlite',
]);

function extOf(name: string): string {
  const dot = name.lastIndexOf('.');
  return dot === -1 ? '' : name.slice(dot).toLowerCase();
}

/**
 * The local path a `file:` URL names, or null when `target` is not one:
 * `file:///C:/x`, `file:/C:/x` and `file://localhost/x` are local;
 * `file://host/x` names a host (returned as `\\host\x`, a network path) and
 * `file:////host/x` a share.
 */
function fileUrlPath(target: string): string | null {
  if (!/^file:/i.test(target)) return null;
  let rest = target.slice('file:'.length);
  try {
    rest = decodeURIComponent(rest);
  } catch {
    /* read as written */
  }
  if (rest.startsWith('//')) {
    const authority = rest.slice(2).split('/')[0] ?? '';
    const path = rest.slice(2 + authority.length);
    if (authority !== '' && authority.toLowerCase() !== 'localhost' && !/^[a-z]:$/i.test(authority)) {
      return `\\\\${authority}${path.split('/').join('\\')}`;
    }
    rest = /^[a-z]:$/i.test(authority) ? `${authority}${path}` : path;
  }
  // `/C:/x` is the drive path `C:/x`; `//host/x` stays a network path.
  return /^\/[a-z]:/i.test(rest) ? rest.slice(1) : rest;
}

/** The objects directories whose `info/alternates` a clone of the local repository `dir` follows. */
function objectsDirsOf(dir: string): string[] {
  const out = [join(dir, 'objects'), join(dir, '.git', 'objects')];
  // A `.git` FILE (`gitdir: <path>`): the repository is elsewhere.
  const gitFile = readSmallText(join(dir, '.git'), 4096, dir);
  if (gitFile.status === 'ok') {
    const m = /^gitdir:\s*(.+?)\s*$/m.exec(gitFile.text);
    if (m?.[1] !== undefined) out.push(join(resolve(dir, m[1]), 'objects'));
  }
  return out;
}

/**
 * Why a local repository cannot be cloned without reaching a share: its
 * `.git` file points at one, or an `objects/info/alternates` entry — followed
 * as git follows them, a few levels deep — names one. Null when none does.
 */
function alternatesProblem(dir: string, depth = 0): string | null {
  if (depth > 5) return null;
  for (const objects of objectsDirsOf(dir)) {
    if (networkPathOf(objects) !== null) return `the repository's objects are on a network path (${objects})`;
    // Read by lstat-walked links only: an alternates file that is itself a link to a share is not opened.
    const alternates = readSmallText(join(objects, 'info', 'alternates'), 64 * 1024, dirname(objects));
    if (alternates.status !== 'ok') continue;
    for (const raw of alternates.text.split(/\r?\n/)) {
      const line = raw.trim();
      if (line === '' || line.startsWith('#')) continue;
      const alternate = resolve(objects, line);
      if (networkPathOf(line) !== null || networkPathOf(alternate) !== null) {
        return `the repository borrows objects from a network path (${line}, in ${join(objects, 'info', 'alternates')})`;
      }
      const deeper = alternatesProblem(dirname(alternate), depth + 1);
      if (deeper !== null) return deeper;
    }
  }
  return null;
}

/**
 * Why `target` would reach a share, or null (see `ingestTarget`): a UNC
 * spelling, a link to one, a `file:` URL naming a host or a share, a local
 * repository whose objects are borrowed from one. A remote URL (`https://`,
 * `git@`) goes over the network by design and is not judged here.
 */
function shareProblem(target: string): string | null {
  const fromUrl = fileUrlPath(target);
  if (fromUrl === null && (/^[a-z][a-z0-9+.-]*:\/\//i.test(target) || /^git@/.test(target))) return null;
  const local = fromUrl ?? target;
  const network = networkPathProblem('target', local);
  if (network !== null) return network;
  if (/\.git$/i.test(local) || fromUrl !== null) {
    const problem = alternatesProblem(resolve(local));
    if (problem !== null) return `target ${JSON.stringify(target)}: ${problem}`;
  }
  return null;
}

export async function ingestTarget(targetRaw: string): Promise<IngestResult> {
  const target = targetRaw.trim();
  if (!target) return { ok: false, code: 'target_not_found', message: 'Empty target.' };

  // A network path is never touched, whether it names a folder or a `.git`
  // to clone — on Windows either is an SMB authentication to the host the
  // caller chose (review 11, finding 8) — nor a `file:` URL that leads to
  // one (`file://host/…`, `file:////host/…`), nor a local repository whose
  // objects git would fetch from a share (review 12, finding 9).
  const share = shareProblem(target);
  if (share !== null) {
    return { ok: false, code: 'unsupported_target', message: `${share}. Vet a local copy, or an https:// URL.` };
  }

  // Remote: git or URL.
  if (/^git@/.test(target) || /\.git($|\?)/.test(target)) {
    return ingestGit(target);
  }
  if (/^https?:\/\//i.test(target)) {
    if (looksLikeGitHost(target)) return ingestGit(target);
    return ingestUrl(target);
  }

  // Local path.
  if (!existsSync(target)) {
    return { ok: false, code: 'target_not_found', message: `Path does not exist: ${target}` };
  }
  const st = statSync(target);
  if (st.isDirectory()) {
    const collected = collectDir(target);
    return {
      ok: true,
      root: target,
      kind: 'directory',
      ...collected,
      cleanup: () => {},
    };
  }
  if (st.isFile()) {
    if (extOf(target) === '.zip') return ingestZip(target, false);
    // The file the user named, wherever a link they named leads: read from
    // its own directory, bounded and on a non-blocking descriptor.
    const real = safeRealpath(target) ?? target;
    const read = readOne(dirname(real), real, basename(target));
    if (read.kind !== 'ok') {
      const why = read.kind === 'refused' ? describeReadRefusal(read.reason) : 'it is binary';
      return { ok: false, code: 'unsupported_target', message: `File not reviewed: ${why}.` };
    }
    const file = read.file;
    return {
      ok: true,
      root: target,
      kind: 'file',
      files: [file],
      skipped: 0,
      truncated: false,
      warnings: [],
      symlinks: [],
      cleanup: () => {},
    };
  }
  return { ok: false, code: 'unsupported_target', message: 'Unsupported target type.' };
}

function looksLikeGitHost(url: string): boolean {
  return /(github\.com|gitlab\.com|bitbucket\.org)\/[^/]+\/[^/]+\/?$/.test(url);
}

async function ingestGit(url: string): Promise<IngestResult> {
  const dir = mkdtempSync(join(tmpdir(), 'guardian-scanskill-git-'));
  // `--`: a target that merely ends in `.git` may start with `-`
  // (`--upload-pack=<command>;.git`), and git would run it as an option.
  // Run from the (empty) temp directory, hardened (`platform/gitSafety.ts`):
  // no hook runs on the checkout, and the `ext::` transport is refused.
  const r = await execGit(dir, ['clone', '--depth', '1', '--quiet', '--', url, dir], { timeoutMs: 120000 });
  if (r.failure !== null || r.status !== 0) {
    safeRm(dir);
    const msg = r.failure?.message ?? (r.stderr.split(/\r?\n/).find((l) => l.trim() !== '')?.trim() || `git exited ${r.status}`);
    return {
      ok: false,
      code: 'unsupported_target',
      message: `git clone failed (is git installed and the URL reachable?): ${msg}`,
    };
  }
  const collected = collectDir(dir);
  return {
    ok: true,
    root: dir,
    kind: 'git',
    ...collected,
    cleanup: () => safeRm(dir),
  };
}

async function ingestUrl(url: string): Promise<IngestResult> {
  if (typeof fetch !== 'function') {
    return { ok: false, code: 'unsupported_target', message: 'No fetch available to download URL.' };
  }
  const dir = mkdtempSync(join(tmpdir(), 'guardian-scanskill-url-'));
  const isZip = /\.zip($|\?)/i.test(url);
  const fileName = isZip ? 'download.zip' : basename(url.split('?')[0] ?? 'download') || 'download';
  const dest = join(dir, fileName);
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 60000);
    try {
      const res = await fetch(url, { signal: controller.signal });
      if (!res.ok) throw new Error(`http ${res.status}`);
      const buf = Buffer.from(await res.arrayBuffer());
      writeFileSync(dest, buf);
    } finally {
      clearTimeout(timeout);
    }
  } catch (e) {
    safeRm(dir);
    return {
      ok: false,
      code: 'unsupported_target',
      message: `download failed: ${e instanceof Error ? e.message : 'unknown'}`,
    };
  }
  if (isZip) {
    const res = await ingestZip(dest, true, dir);
    return res;
  }
  const read = readOne(dir, dest, fileName);
  if (read.kind !== 'ok') {
    safeRm(dir);
    return { ok: false, code: 'unsupported_target', message: 'Downloaded file is binary or too large.' };
  }
  return {
    ok: true,
    root: dir,
    kind: 'url',
    files: [read.file],
    skipped: 0,
    truncated: false,
    warnings: [],
    symlinks: [],
    cleanup: () => safeRm(dir),
  };
}

async function ingestZip(
  zipPath: string,
  ownsParent: boolean,
  parentDir?: string,
): Promise<IngestResult> {
  const extractDir = mkdtempSync(join(tmpdir(), 'guardian-scanskill-zip-'));
  const extracted = await tryExtract(zipPath, extractDir);
  if (!extracted) {
    safeRm(extractDir);
    if (ownsParent && parentDir) safeRm(parentDir);
    return {
      ok: false,
      code: 'unsupported_target',
      message: 'Could not extract zip (need `tar` or `unzip` on PATH).',
    };
  }
  const collected = collectDir(extractDir);
  return {
    ok: true,
    root: extractDir,
    kind: 'zip',
    ...collected,
    cleanup: () => {
      safeRm(extractDir);
      if (ownsParent && parentDir) safeRm(parentDir);
    },
  };
}

/** How long one extraction may take before its whole process tree is killed. */
const EXTRACT_TIMEOUT_MS = 120_000;

/**
 * Extracts `zipPath` into `destDir` with the system's `tar` (bsdtar — Windows
 * 10+, macOS, most Linux — reads zip with `tar -xf`), else `unzip`. Through
 * the runner (review 8, finding 4): its timeout kills the whole tree and
 * returns at the deadline — execa's own `timeout`, used here before, signalled
 * only the direct child and then waited on any process still holding its pipes.
 */
async function tryExtract(zipPath: string, destDir: string): Promise<boolean> {
  for (const [command, args] of [
    ['tar', ['-xf', zipPath, '-C', destDir]],
    ['unzip', ['-o', '-q', zipPath, '-d', destDir]],
  ] as const) {
    const r = await runProcess({ command, args: [...args], cwd: destDir, timeoutMs: EXTRACT_TIMEOUT_MS });
    if (r.outcome === 'completed') return true;
  }
  return false;
}

/**
 * Is `candidate` (an absolute path) `root` itself or something inside it?
 * Pure and platform-agnostic — `path.relative` already returns an absolute
 * path (never a `..`-prefixed one) for a candidate on a different Windows
 * drive, which `isAbsolute` catches the same way `startsWith('..')` catches
 * a POSIX escape. A sibling directory that merely shares `root`'s name as a
 * PREFIX (`/pkg-evil` next to `/pkg`) is correctly rejected too:
 * `path.relative` resolves it through the parent (`../pkg-evil`), never as a
 * bare string match.
 */
export function isPathWithinRoot(candidate: string, root: string): boolean {
  const rel = relative(root, candidate);
  return rel === '' || (!rel.startsWith('..') && !isAbsolute(rel));
}

function collectDir(root: string): {
  files: IngestedFile[];
  skipped: number;
  truncated: boolean;
  warnings: string[];
  symlinks: SymlinkEntry[];
} {
  const files: IngestedFile[] = [];
  const warnings: string[] = [];
  const symlinks: SymlinkEntry[] = [];
  let totalBytes = 0;
  let skipped = 0;
  let truncated = false;

  // Resolved once, outside the walk: every directory the walk descends into
  // is checked against THIS, never against `root` the raw string, so a
  // symlinked `root` itself (the caller passed a link as the top-level
  // target) still anchors the boundary at root's real, physical location —
  // see `ingestTarget`'s `directory` branch, which never lstat-guards its
  // own top-level `target` the way this function guards everything below it.
  let rootReal: string;
  try {
    rootReal = realpathSync(root);
  } catch {
    rootReal = root;
  }

  const stack: string[] = [root];
  while (stack.length > 0) {
    const dir = stack.pop();
    // `stack.length > 0` already guarantees this, but the compiler cannot see
    // it and an assertion would hide a real change to the loop condition.
    if (dir === undefined) break;
    let entries: string[];
    try {
      entries = readdirSync(dir);
    } catch {
      continue;
    }
    for (const entry of entries) {
      if (files.length >= MAX_FILES || totalBytes >= MAX_TOTAL_BYTES) {
        truncated = true;
        break;
      }
      const abs = join(dir, entry);
      // `lstat`, never `stat`: a symlink (or, where `lstat` reports it this
      // way, a Windows junction) must be IDENTIFIED without ever being
      // followed. This is the fix for the reproduced defect — see the
      // module header and this function's own doc comment above.
      let s;
      try {
        s = lstatSync(abs);
      } catch {
        continue;
      }
      if (s.isSymbolicLink()) {
        symlinks.push({ relPath: rel(root, abs), target: readLinkTargetSafely(abs), kind: 'symlink' });
        skipped += 1;
        continue;
      }
      if (s.isDirectory()) {
        if (SKIP_DIRS.has(entry)) continue;
        // Second, independent guard: an ordinary directory (lstat says so,
        // not a link) whose REALPATH still resolves outside the root —
        // the shape a junction or bind mount takes on a platform/Node
        // version where `lstat` does not flag it as a link at all. Never
        // descended into; reported the same way a link is, target string
        // (the realpath) only.
        // A network path on the way is never resolved (Windows would authenticate to its host): it escapes.
        const real = entryKindAnywhere(abs) === 'remote' ? null : safeRealpath(abs);
        if (real === null || !isPathWithinRoot(real, rootReal)) {
          symlinks.push({
            relPath: rel(root, abs),
            target: real ?? '(unresolvable)',
            kind: 'escaped_directory',
          });
          skipped += 1;
          continue;
        }
        stack.push(abs);
        continue;
      }
      if (!s.isFile()) {
        // A FIFO, a device or a socket in the skill: never opened, never silent
        // (review of 3.0, W2E — it used to vanish from the audit uncounted).
        skipped += 1;
        warnings.push(`not read: ${rel(root, abs)} (not a regular file: a FIFO, a device or a socket)`);
        continue;
      }
      const ext = extOf(entry);
      if (BINARY_EXT.has(ext)) {
        skipped += 1;
        continue;
      }
      if (s.size > MAX_FILE_BYTES) {
        skipped += 1;
        warnings.push(`skipped large file: ${rel(root, abs)} (${Math.round(s.size / 1024)} KB)`);
        continue;
      }
      // Read through `platform/projectFs.ts` against the ingestion root: a
      // file swapped for a FIFO, a device or a link since the lstat above is
      // refused on its descriptor, never waited on or read without end, and
      // named (review of 3.0, W2E).
      const read = readOne(root, abs, rel(root, abs));
      if (read.kind !== 'ok') {
        skipped += 1;
        if (read.kind === 'refused') warnings.push(`not read: ${rel(root, abs)} (${describeReadRefusal(read.reason)})`);
        continue;
      }
      files.push(read.file);
      totalBytes += read.file.bytes;
    }
    if (truncated) break;
  }
  if (truncated) {
    warnings.push(`scan truncated at ${files.length} files / ${Math.round(totalBytes / 1024)} KB`);
  }
  return { files, skipped, truncated, warnings, symlinks };
}

/** `readlinkSync`, best-effort: a link can vanish or become unreadable
 *  between the `lstat` above and this call (TOCTOU is inherent to any
 *  filesystem walk); reporting `'(unreadable)'` beats throwing out of the
 *  whole scan over one link. */
function readLinkTargetSafely(abs: string): string {
  try {
    return readlinkSync(abs);
  } catch {
    return '(unreadable)';
  }
}

function safeRealpath(abs: string): string | null {
  try {
    return realpathSync(abs);
  } catch {
    return null;
  }
}

function rel(root: string, abs: string): string {
  let r = abs.slice(root.length).replace(/\\/g, '/');
  if (r.startsWith('/')) r = r.slice(1);
  return r || basename(abs);
}

type ReadOne =
  | { kind: 'ok'; file: IngestedFile }
  | { kind: 'binary' }
  | { kind: 'refused'; reason: Parameters<typeof describeReadRefusal>[0] };

/** `abs` (inside `root`), as an ingested text file — or why not. */
function readOne(root: string, abs: string, relPath: string): ReadOne {
  // Resolved first: a relative `abs` (a relative target) is already joined
  // onto `root`, and must not be resolved against it a second time.
  const read = readProjectBytes(root, resolve(abs), MAX_FILE_BYTES);
  if (read.status === 'absent') return { kind: 'refused', reason: 'unreadable' };
  if (read.status === 'refused') return { kind: 'refused', reason: read.reason };
  const raw = read.bytes;
  if (looksBinary(raw)) return { kind: 'binary' };
  const content = raw.toString('utf8');
  const name = basename(abs);
  const ext = extOf(name);
  const shebang = content.startsWith('#!');
  const isCode = CODE_EXT.has(ext) || (DOC_EXT.has(ext) ? false : shebang);
  const isExecutable = EXECUTABLE_EXT.has(ext) || shebang;
  // config files: not "code" (run text/any rules), not executable.
  const finalIsCode = CONFIG_EXT.has(ext) ? false : isCode;
  return {
    kind: 'ok',
    file: {
      relPath,
      absPath: abs,
      content,
      isCode: finalIsCode,
      isExecutable,
      bytes: raw.length,
    },
  };
}

/** Heuristic: a NUL byte in the first 8 KB means binary. */
function looksBinary(buf: Buffer): boolean {
  const n = Math.min(buf.length, 8192);
  for (let i = 0; i < n; i += 1) {
    if (buf[i] === 0) return true;
  }
  return false;
}

function safeRm(dir: string): void {
  try {
    rmSync(dir, { recursive: true, force: true });
  } catch {
    /* best effort */
  }
}
