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
 * throwing. A download and an extraction are bounded in size, not only in
 * time: a 60 s download of an endless body, or a zip bomb extracted for two
 * minutes, filled the disk before either deadline.
 *
 * The analyzer only ever sees reviewable text — and what it does not see is
 * said (`unread`): code that may run and was not read (native code, an
 * archive, an oversized or undecodable file, installed dependencies, the
 * part of a package past the walk's caps) is a named gap `scan_skill`
 * reports as partial coverage, never as part of a clean verdict. Only
 * content the host never runs — images, fonts, media, version-control
 * metadata — is left out silently. Build output (`dist/`, `build/`, …) is
 * read, after the package's own files: it is what a manifest's `node
 * dist/index.js` runs.
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
import { mebibytes, readBodyCapped } from '../platform/httpBody.js';
import { networkPathOf, networkPathProblem } from '../platform/projectPath.js';
import { readBoundedBytes, readSmallText, textOf } from '../hooks/configFile.js';
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

/**
 * Something in the package that may run and was not read: a file (native
 * code, an archive, an oversized or undecodable file, one that could not be
 * opened) or a directory (installed dependencies, one that could not be
 * listed). `relPath` ends in `/` for a directory.
 */
export interface UnreadEntry {
  relPath: string;
  why: string;
}

interface IngestSuccess {
  ok: true;
  root: string;
  kind: TargetKind;
  files: IngestedFile[];
  /** Every entry not read, the {@link unread} gaps and the content left out silently (images, links) alike. */
  skipped: number;
  /** The walk stopped at its caps: the rest of the package was not read. */
  truncated: boolean;
  /** What may run and was not read — each a gap of the audit (see the module doc). */
  unread: UnreadEntry[];
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

/** The walk's caps — past either, the rest of the package is not read, and that is a gap. */
interface WalkLimits {
  maxFiles: number;
  maxTotalBytes: number;
}

const DEFAULT_WALK_LIMITS: WalkLimits = { maxFiles: 4000, maxTotalBytes: 25 * 1024 * 1024 };
const MAX_FILE_BYTES = 2 * 1024 * 1024;

const CODE_EXT = new Set([
  '.sh', '.bash', '.zsh', '.ps1', '.psm1', '.bat', '.cmd', '.vbs', '.vbe', '.wsf',
  '.py', '.rb', '.pl', '.lua', '.php',
  '.js', '.mjs', '.cjs', '.jsx', '.ts', '.mts', '.cts', '.tsx',
  '.go', '.rs', '.java', '.kt', '.c', '.cc', '.cpp', '.h',
]);
const EXECUTABLE_EXT = new Set([
  '.sh', '.bash', '.zsh', '.ps1', '.psm1', '.bat', '.cmd', '.vbs', '.vbe', '.wsf',
  '.py', '.rb', '.pl', '.php', '.js', '.mjs', '.cjs',
]);
const DOC_EXT = new Set(['.md', '.markdown', '.txt', '.rst', '.adoc']);
const CONFIG_EXT = new Set(['.json', '.yaml', '.yml', '.toml', '.ini', '.cfg']);

/** Version-control and archiver metadata: not part of what installs (a clone's own `.git` among them). Left out silently. */
const METADATA_DIRS = new Set(['.git', '.svn', '.hg', '__MACOSX']);
/**
 * Installed dependencies and caches: they run with the package, but read
 * here they would bury its own files under their code (and the walk's caps)
 * — not read, and each one named as a gap. A `__pycache__` `.pyc` is loaded
 * instead of a source that does not check it, so it is not inert either.
 */
const DEPENDENCY_DIRS = new Set(['node_modules', 'vendor', '.venv', 'venv', '__pycache__', '.cache', 'coverage']);
/**
 * Build output: often the very code a manifest runs — a plugin's `.mcp.json`
 * starts `node dist/index.js`, and a payload there was never read. Read, after
 * the package's own files, so a large bundle meets the walk's caps last.
 */
const BUILD_DIRS = new Set(['dist', 'build', 'out', 'target', '.next']);

/** What the host never runs: images, fonts, media, documents, data. Counted in `skipped`, never a gap. */
const INERT_EXT = new Set([
  '.png', '.jpg', '.jpeg', '.gif', '.webp', '.ico', '.bmp', '.pdf',
  '.woff', '.woff2', '.ttf', '.eot', '.mp3', '.mp4', '.mov', '.wav', '.db', '.sqlite',
]);
/** Files the Finder and Explorer leave behind, binary and never run. */
const INERT_NAMES = new Set(['.ds_store', 'thumbs.db', 'desktop.ini']);
/** Code no reader of text can review, and archives nothing here opens: not read, and named as a gap. */
const OPAQUE_EXT: ReadonlyMap<string, string> = new Map([
  ...['.exe', '.dll', '.so', '.dylib', '.node', '.wasm', '.bin', '.o', '.a'].map((e) => [e, 'native code, not reviewed'] as const),
  ...['.class', '.jar', '.pyc'].map((e) => [e, 'compiled bytecode, not reviewed'] as const),
  ...['.zip', '.gz', '.tar', '.tgz', '.bz2', '.7z', '.rar'].map((e) => [e, 'an archive inside the package, not opened'] as const),
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

/**
 * How much a zip may hold. Its central directory is judged before anything
 * is extracted, and the extraction directory is watched while `tar` /
 * `unzip` run: both are bounded only by their own deadline otherwise, and a
 * zip bomb fills a disk long before two minutes are up.
 */
interface ZipLimits {
  /** The archive itself (a local `.zip`, or a download). */
  maxArchiveBytes: number;
  /** Entries declared, and entries on disk while it is extracted. */
  maxEntries: number;
  /** Bytes declared once extracted, and bytes on disk while it is extracted. */
  maxExtractedBytes: number;
}

const DEFAULT_ZIP_LIMITS: ZipLimits = {
  maxArchiveBytes: 64 * 1024 * 1024,
  maxEntries: 20_000,
  maxExtractedBytes: 256 * 1024 * 1024,
};

/** A download larger than this is refused, never written: the walk reads 25 MB of it at most anyway. */
const MAX_DOWNLOAD_BYTES = 64 * 1024 * 1024;

/** The caps a test lowers to reach them; production always uses the defaults. */
interface IngestOptions {
  walk?: Partial<WalkLimits>;
  zip?: Partial<ZipLimits>;
  maxDownloadBytes?: number;
}

interface IngestLimits {
  walk: WalkLimits;
  zip: ZipLimits;
  maxDownloadBytes: number;
}

export async function ingestTarget(targetRaw: string, options: IngestOptions = {}): Promise<IngestResult> {
  const target = targetRaw.trim();
  if (!target) return { ok: false, code: 'target_not_found', message: 'Empty target.' };
  const limits: IngestLimits = {
    walk: { ...DEFAULT_WALK_LIMITS, ...options.walk },
    zip: { ...DEFAULT_ZIP_LIMITS, ...options.zip },
    maxDownloadBytes: options.maxDownloadBytes ?? MAX_DOWNLOAD_BYTES,
  };

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
    return ingestGit(target, limits);
  }
  if (/^https?:\/\//i.test(target)) {
    if (looksLikeGitHost(target)) return ingestGit(target, limits);
    return ingestUrl(target, limits);
  }

  // Local path.
  if (!existsSync(target)) {
    return { ok: false, code: 'target_not_found', message: `Path does not exist: ${target}` };
  }
  const st = statSync(target);
  if (st.isDirectory()) {
    const collected = collectDir(target, limits.walk);
    return {
      ok: true,
      root: target,
      kind: 'directory',
      ...collected,
      cleanup: () => {},
    };
  }
  if (st.isFile()) {
    if (extOf(target) === '.zip') return ingestZip(target, limits);
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
      unread: [],
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

async function ingestGit(url: string, limits: IngestLimits): Promise<IngestResult> {
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
  const collected = collectDir(dir, limits.walk);
  return {
    ok: true,
    root: dir,
    kind: 'git',
    ...collected,
    cleanup: () => safeRm(dir),
  };
}

async function ingestUrl(url: string, limits: IngestLimits): Promise<IngestResult> {
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
      // Read to the cap, never past it: the 60 s above bounded only the time.
      const body = await readBodyCapped(res, limits.maxDownloadBytes);
      if (body === null) throw new Error(`the file is over ${mebibytes(limits.maxDownloadBytes)}; vet a local copy`);
      writeFileSync(dest, body);
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
    const res = await ingestZip(dest, limits, dir);
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
    unread: [],
    warnings: [],
    symlinks: [],
    cleanup: () => safeRm(dir),
  };
}

/** `ownedDir`: the download's own temp directory, removed with the extraction. */
async function ingestZip(zipPath: string, limits: IngestLimits, ownedDir?: string): Promise<IngestResult> {
  const refuse = (message: string): IngestFailure => {
    if (ownedDir !== undefined) safeRm(ownedDir);
    return { ok: false, code: 'unsupported_target', message };
  };
  const declared = zipOverLimits(zipPath, limits.zip);
  if (declared !== null) return refuse(`Zip not extracted: ${declared}.`);
  const extractDir = mkdtempSync(join(tmpdir(), 'guardian-scanskill-zip-'));
  const failure = await tryExtract(zipPath, extractDir, limits.zip);
  if (failure !== null) {
    safeRm(extractDir);
    return refuse(failure);
  }
  const collected = collectDir(extractDir, limits.walk);
  return {
    ok: true,
    root: extractDir,
    kind: 'zip',
    ...collected,
    cleanup: () => {
      safeRm(extractDir);
      if (ownedDir !== undefined) safeRm(ownedDir);
    },
  };
}

const EOCD_SIGNATURE = 0x06054b50;
const ZIP64_LOCATOR_SIGNATURE = 0x07064b50;
const ZIP64_EOCD_SIGNATURE = 0x06064b50;
const CENTRAL_ENTRY_SIGNATURE = 0x02014b50;

/**
 * Why a zip is over `limits` by what its central directory DECLARES — its
 * size, its entry count, its total once extracted — or null. A zip bomb
 * declares what it inflates to (42.zip; the overlapping-entry bombs declare
 * terabytes), so it is refused here, unopened; one whose declarations lie
 * meets the watch in {@link tryExtract}. ZIP64 records are read too: they
 * are where a large declaration lives.
 */
function zipOverLimits(path: string, limits: ZipLimits): string | null {
  const read = readBoundedBytes(path, limits.maxArchiveBytes);
  if (read.status === 'absent') return 'the archive is gone';
  if (read.status === 'refused') {
    return read.reason === 'too-large'
      ? `the archive is over ${mebibytes(limits.maxArchiveBytes)}`
      : `the archive could not be read (${read.reason})`;
  }
  const buf = read.bytes;
  let eocd = -1;
  for (let i = buf.length - 22; i >= Math.max(0, buf.length - 22 - 0xffff); i -= 1) {
    if (buf.readUInt32LE(i) === EOCD_SIGNATURE) {
      eocd = i;
      break;
    }
  }
  if (eocd === -1) return 'it is not a zip archive (no end-of-central-directory record)';
  let entries = buf.readUInt16LE(eocd + 10);
  let cdSize = buf.readUInt32LE(eocd + 12);
  let cdOffset = buf.readUInt32LE(eocd + 16);
  if (entries === 0xffff || cdSize === 0xffffffff || cdOffset === 0xffffffff) {
    const locator = eocd - 20;
    if (locator < 0 || buf.readUInt32LE(locator) !== ZIP64_LOCATOR_SIGNATURE) return 'a ZIP64 archive without its locator';
    const record = Number(buf.readBigUInt64LE(locator + 8));
    if (record + 56 > buf.length || buf.readUInt32LE(record) !== ZIP64_EOCD_SIGNATURE) {
      return 'a ZIP64 archive without its directory record';
    }
    entries = Number(buf.readBigUInt64LE(record + 32));
    cdSize = Number(buf.readBigUInt64LE(record + 40));
    cdOffset = Number(buf.readBigUInt64LE(record + 48));
  }
  if (entries > limits.maxEntries) return `it declares ${entries} entries, over the ${limits.maxEntries} vetted`;
  const tooBig = `it declares over ${mebibytes(limits.maxExtractedBytes)} once extracted (a zip bomb, or a package too large to vet)`;
  let total = 0;
  let seen = 0;
  const end = Math.min(buf.length, cdOffset + cdSize);
  for (let at = cdOffset; at + 46 <= end && buf.readUInt32LE(at) === CENTRAL_ENTRY_SIGNATURE; ) {
    seen += 1;
    if (seen > limits.maxEntries) return `it holds over ${limits.maxEntries} entries`;
    const nameLength = buf.readUInt16LE(at + 28);
    const extraLength = buf.readUInt16LE(at + 30);
    const commentLength = buf.readUInt16LE(at + 32);
    const size = buf.readUInt32LE(at + 24);
    total += size === 0xffffffff ? (zip64Uncompressed(buf, at + 46 + nameLength, extraLength) ?? Number.POSITIVE_INFINITY) : size;
    if (total > limits.maxExtractedBytes) return tooBig;
    at += 46 + nameLength + extraLength + commentLength;
  }
  return null;
}

/** The uncompressed size in an entry's ZIP64 extra field (id 1, its first 8 bytes), or null. */
function zip64Uncompressed(buf: Buffer, from: number, length: number): number | null {
  const end = Math.min(buf.length, from + length);
  for (let p = from; p + 4 <= end; ) {
    const id = buf.readUInt16LE(p);
    const size = buf.readUInt16LE(p + 2);
    if (id === 0x0001 && size >= 8 && p + 12 <= end) return Number(buf.readBigUInt64LE(p + 4));
    p += 4 + size;
  }
  return null;
}

/** How long one extraction may take before its whole process tree is killed. */
const EXTRACT_TIMEOUT_MS = 120_000;
/** How often the extraction directory is measured while it fills. */
const EXTRACT_WATCH_MS = 200;

/**
 * Why the tree at `dir` is over `limits`, or null: its entries and bytes,
 * walked with `lstat` only (a link is counted, never followed) and stopped
 * at the first cap passed.
 */
function treeOverLimits(dir: string, limits: ZipLimits): string | null {
  let entries = 0;
  let bytes = 0;
  const stack = [dir];
  for (let d = stack.pop(); d !== undefined; d = stack.pop()) {
    let names: string[];
    try {
      names = readdirSync(d);
    } catch {
      continue;
    }
    for (const name of names) {
      entries += 1;
      if (entries > limits.maxEntries) return `over ${limits.maxEntries} entries on disk`;
      const abs = join(d, name);
      let s;
      try {
        s = lstatSync(abs);
      } catch {
        continue;
      }
      if (s.isDirectory()) stack.push(abs);
      else bytes += s.size;
      if (bytes > limits.maxExtractedBytes) return `over ${mebibytes(limits.maxExtractedBytes)} on disk (a zip bomb, or a package too large to vet)`;
    }
  }
  return null;
}

/**
 * Extracts `zipPath` into `destDir` with the system's `tar` (bsdtar — Windows
 * 10+, macOS, most Linux — reads zip with `tar -xf`), else `unzip`. Through
 * the runner (review 8, finding 4): its timeout kills the whole tree and
 * returns at the deadline — execa's own `timeout`, used here before, signalled
 * only the direct child and then waited on any process still holding its pipes.
 * The directory is measured while it fills, and the extraction killed past
 * `limits`: a zip whose central directory lies about its sizes still inflates
 * only this far. Null on success, else why it failed.
 */
async function tryExtract(zipPath: string, destDir: string, limits: ZipLimits): Promise<string | null> {
  for (const [command, args] of [
    ['tar', ['-xf', zipPath, '-C', destDir]],
    ['unzip', ['-o', '-q', zipPath, '-d', destDir]],
  ] as const) {
    const controller = new AbortController();
    let over: string | null = null;
    const watch = setInterval(() => {
      over ??= treeOverLimits(destDir, limits);
      if (over !== null) controller.abort();
    }, EXTRACT_WATCH_MS);
    let outcome: string;
    try {
      const r = await runProcess({ command, args: [...args], cwd: destDir, timeoutMs: EXTRACT_TIMEOUT_MS, signal: controller.signal });
      outcome = r.outcome;
    } finally {
      clearInterval(watch);
    }
    over ??= treeOverLimits(destDir, limits);
    if (over !== null) return `Zip extraction stopped: ${over}.`;
    if (outcome === 'completed') return null;
  }
  return 'Could not extract zip (need `tar` or `unzip` on PATH).';
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

function collectDir(root: string, limits: WalkLimits = DEFAULT_WALK_LIMITS): {
  files: IngestedFile[];
  skipped: number;
  truncated: boolean;
  unread: UnreadEntry[];
  warnings: string[];
  symlinks: SymlinkEntry[];
} {
  const files: IngestedFile[] = [];
  const warnings: string[] = [];
  const symlinks: SymlinkEntry[] = [];
  const unread: UnreadEntry[] = [];
  let totalBytes = 0;
  let skipped = 0;
  let truncated = false;
  const notRead = (abs: string, why: string, dir = false): void => {
    skipped += 1;
    unread.push({ relPath: `${rel(root, abs)}${dir ? '/' : ''}`, why });
  };

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

  // Build output is walked after everything else (see BUILD_DIRS): a bundle
  // is large, and the package's own files must not be what the caps cut.
  const stack: string[] = [root];
  const later: string[] = [];
  for (let dir = stack.pop() ?? later.pop(); dir !== undefined; dir = stack.pop() ?? later.pop()) {
    let entries: string[];
    try {
      entries = readdirSync(dir);
    } catch {
      notRead(dir, 'a directory that could not be listed', true);
      continue;
    }
    for (const entry of entries) {
      if (files.length >= limits.maxFiles || totalBytes >= limits.maxTotalBytes) {
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
        if (METADATA_DIRS.has(entry)) continue;
        if (DEPENDENCY_DIRS.has(entry)) {
          notRead(abs, 'installed dependencies or a cache, not read', true);
          continue;
        }
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
        (BUILD_DIRS.has(entry) ? later : stack).push(abs);
        continue;
      }
      if (!s.isFile()) {
        // A FIFO, a device or a socket in the skill: never opened, never silent
        // (review of 3.0, W2E — it used to vanish from the audit uncounted).
        notRead(abs, 'not a regular file: a FIFO, a device or a socket');
        warnings.push(`not read: ${rel(root, abs)} (not a regular file: a FIFO, a device or a socket)`);
        continue;
      }
      const ext = extOf(entry);
      if (INERT_EXT.has(ext) || INERT_NAMES.has(entry.toLowerCase())) {
        skipped += 1;
        continue;
      }
      const opaque = OPAQUE_EXT.get(ext);
      if (opaque !== undefined) {
        notRead(abs, opaque);
        continue;
      }
      if (s.size > MAX_FILE_BYTES) {
        notRead(abs, `over ${mebibytes(MAX_FILE_BYTES)}, not read`);
        warnings.push(`skipped large file: ${rel(root, abs)} (${Math.round(s.size / 1024)} KB)`);
        continue;
      }
      // Read through `platform/projectFs.ts` against the ingestion root: a
      // file swapped for a FIFO, a device or a link since the lstat above is
      // refused on its descriptor, never waited on or read without end, and
      // named (review of 3.0, W2E).
      const read = readOne(root, abs, rel(root, abs));
      if (read.kind !== 'ok') {
        if (read.kind === 'refused') {
          notRead(abs, describeReadRefusal(read.reason));
          warnings.push(`not read: ${rel(root, abs)} (${describeReadRefusal(read.reason)})`);
        } else {
          notRead(abs, 'binary content (NUL bytes) under a name that is not a binary type');
        }
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
  return { files, skipped, truncated, unread, warnings, symlinks };
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

/**
 * `abs` relative to `root`, with forward slashes. `path.relative`, not a
 * slice of `root.length`: `join` normalises what it builds, so under a target
 * spelled `./skill` every path lost its first character (`SKILL.md` read as
 * `KILL.md`, `.claude/settings.json` as `claude/settings.json` — whose hooks
 * then went unread by the command checks).
 */
function rel(root: string, abs: string): string {
  const r = relative(resolve(root), resolve(abs)).split('\\').join('/');
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
  const content = decodeText(raw);
  if (content === null) return { kind: 'binary' };
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

/**
 * The text of a file, by its byte-order mark — UTF-16 LE or BE, or UTF-8
 * with the mark dropped — and UTF-8 without one; null when it is binary (a
 * NUL byte in the first 8 KB of a file with no UTF-16 mark). Windows
 * PowerShell 5 saves a script as UTF-16 LE: every ASCII character is
 * followed by a NUL, and such a `.ps1` read as binary and was never
 * reviewed. A UTF-8 mark is not text: left in, it read as hidden Unicode.
 */
function decodeText(raw: Buffer): string | null {
  if (raw.length >= 2 && raw[0] === 0xff && raw[1] === 0xfe) return raw.subarray(2).toString('utf16le');
  if (raw.length >= 2 && raw[0] === 0xfe && raw[1] === 0xff) {
    const body = Buffer.from(raw.subarray(2, 2 + ((raw.length - 2) & ~1)));
    return body.swap16().toString('utf16le');
  }
  if (looksBinary(raw)) return null;
  return textOf(raw);
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
