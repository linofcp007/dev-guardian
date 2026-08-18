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

import { execa } from 'execa';
import {
  existsSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, join } from 'node:path';

export interface IngestedFile {
  relPath: string;
  absPath: string;
  content: string;
  /** Source/executable → run code rules and apply the executable multiplier. */
  isCode: boolean;
  isExecutable: boolean;
  bytes: number;
}

export type TargetKind = 'directory' | 'file' | 'zip' | 'git' | 'url';

export interface IngestSuccess {
  ok: true;
  root: string;
  kind: TargetKind;
  files: IngestedFile[];
  skipped: number;
  truncated: boolean;
  warnings: string[];
  cleanup(): void;
}

export interface IngestFailure {
  ok: false;
  code: 'target_not_found' | 'unsupported_target';
  message: string;
}

export type IngestResult = IngestSuccess | IngestFailure;

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

export async function ingestTarget(targetRaw: string): Promise<IngestResult> {
  const target = targetRaw.trim();
  if (!target) return { ok: false, code: 'target_not_found', message: 'Empty target.' };

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
    const file = readOne(target, basename(target));
    if (!file) {
      return { ok: false, code: 'unsupported_target', message: 'File is binary or too large to review.' };
    }
    return {
      ok: true,
      root: target,
      kind: 'file',
      files: [file],
      skipped: 0,
      truncated: false,
      warnings: [],
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
  try {
    await execa('git', ['clone', '--depth', '1', '--quiet', url, dir], { timeout: 120000 });
  } catch (e) {
    safeRm(dir);
    const msg = e instanceof Error ? e.message : 'git clone failed';
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
  const file = readOne(dest, fileName);
  if (!file) {
    safeRm(dir);
    return { ok: false, code: 'unsupported_target', message: 'Downloaded file is binary or too large.' };
  }
  return {
    ok: true,
    root: dir,
    kind: 'url',
    files: [file],
    skipped: 0,
    truncated: false,
    warnings: [],
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

async function tryExtract(zipPath: string, destDir: string): Promise<boolean> {
  // bsdtar (Windows 10+, macOS, most Linux) understands zip via `tar -xf`.
  try {
    await execa('tar', ['-xf', zipPath, '-C', destDir], { timeout: 120000 });
    return true;
  } catch {
    /* fall through */
  }
  try {
    await execa('unzip', ['-o', '-q', zipPath, '-d', destDir], { timeout: 120000 });
    return true;
  } catch {
    return false;
  }
}

function collectDir(root: string): {
  files: IngestedFile[];
  skipped: number;
  truncated: boolean;
  warnings: string[];
} {
  const files: IngestedFile[] = [];
  const warnings: string[] = [];
  let totalBytes = 0;
  let skipped = 0;
  let truncated = false;

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
      let s;
      try {
        s = statSync(abs);
      } catch {
        continue;
      }
      if (s.isDirectory()) {
        if (SKIP_DIRS.has(entry)) continue;
        stack.push(abs);
        continue;
      }
      if (!s.isFile()) continue;
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
      const file = readOne(abs, rel(root, abs));
      if (!file) {
        skipped += 1;
        continue;
      }
      files.push(file);
      totalBytes += file.bytes;
    }
    if (truncated) break;
  }
  if (truncated) {
    warnings.push(`scan truncated at ${files.length} files / ${Math.round(totalBytes / 1024)} KB`);
  }
  return { files, skipped, truncated, warnings };
}

function rel(root: string, abs: string): string {
  let r = abs.slice(root.length).replace(/\\/g, '/');
  if (r.startsWith('/')) r = r.slice(1);
  return r || basename(abs);
}

function readOne(abs: string, relPath: string): IngestedFile | null {
  let raw: Buffer;
  try {
    raw = readFileSync(abs);
  } catch {
    return null;
  }
  if (looksBinary(raw)) return null;
  const content = raw.toString('utf8');
  const name = basename(abs);
  const ext = extOf(name);
  const shebang = content.startsWith('#!');
  const isCode = CODE_EXT.has(ext) || (DOC_EXT.has(ext) ? false : shebang);
  const isExecutable = EXECUTABLE_EXT.has(ext) || shebang;
  // config files: not "code" (run text/any rules), not executable.
  const finalIsCode = CONFIG_EXT.has(ext) ? false : isCode;
  return {
    relPath,
    absPath: abs,
    content,
    isCode: finalIsCode,
    isExecutable,
    bytes: raw.length,
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
