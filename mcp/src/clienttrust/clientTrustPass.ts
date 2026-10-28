/**
 * The client-trust checks as one pass of a scan — `scan_sast` runs it beside
 * Semgrep (whose `client-trust.yml` pack reads the code), and `review_pr`
 * over the files its diff changed:
 *
 *   - every `.env*` file of the project (`publicEnv.ts`): a secret behind a
 *     browser-exposed prefix. The files git IGNORES are read too —
 *     `.env.local` is where such a secret usually lives, and no other scan
 *     of dev-guardian reads it (gitleaks' files pass reads what git does not
 *     ignore). In a git work tree they are found with git's own listing (the
 *     ignored ones with `--directory`, so an ignored `node_modules/` is one
 *     entry, never a walk); outside one, by a walk bounded in depth and
 *     entries. A value is judged in memory and never reported;
 *   - every Supabase project's migrations (`supabaseRls.ts`): each
 *     `supabase/migrations/` directory with its `../config.toml`.
 *
 * With `files` (a scope, a diff) only those env files are read, and the
 * migrations of each Supabase directory one of them is in — all of that
 * directory's migrations, since a table's RLS can be enabled in any of them —
 * and only findings in `files` are kept.
 *
 * Nothing to check (no env file, no migration) is no entry at all, as Bandit
 * is none without Python: the pass did not apply. An env file that is no
 * regular file of the project (a link out of it, a FIFO, one over its cap) is
 * skipped with a note — never read, never a gap: it is the developer's
 * machine. A MIGRATION that cannot be read is a named gap (`ok` with the
 * pass's name in `missing`): its directory is not judged without it.
 */

import { createHash } from 'node:crypto';
import { listScannedFiles } from '../platform/guardianIgnore.js';
import { isGuardianOutput } from '../platform/guardianOutput.js';
import { describeReadRefusal, hashProjectFile, listProjectDir, readProjectText } from '../platform/projectFs.js';
import { git, splitNul } from '../runners/git.js';
import { SCANNED_WALK_EXCLUDE } from '../runners/projectFiles.js';
import type { ScannerParser } from '../runners/scannerParsers/index.js';
import type { Finding, ToolRun } from '../types.js';
import { CLIENT_TRUST_TOOL, checkEnvFile, isEnvFileName } from './publicEnv.js';
import { checkSupabaseMigrations, exposedSchemasFrom, type MigrationFile } from './supabaseRls.js';

export { CLIENT_TRUST_TOOL };

/** An env file over this is not read (a real one is a few KB). */
const ENV_FILE_MAX_BYTES = 256 * 1024;
/** One migration over this is not read; a seed dump belongs in `seed.sql`. */
const MIGRATION_MAX_BYTES = 4 * 1024 * 1024;
/** The most env files read in one pass. */
const MAX_ENV_FILES = 200;
/** The most migrations read for one Supabase directory. */
const MAX_MIGRATIONS = 5000;
/** The walk outside git: how deep, and how many directory entries in all. */
const WALK_MAX_DEPTH = 6;
const WALK_MAX_ENTRIES = 200_000;

const MIGRATION_RE = /(?:^|\/)supabase\/migrations\/[^/]+\.sql$/i;
const SUPABASE_CONFIG_RE = /(?:^|\/)supabase\/config\.toml$/i;

const basenameOf = (rel: string): string => rel.slice(rel.lastIndexOf('/') + 1);
const dirOf = (rel: string): string => (rel.includes('/') ? rel.slice(0, rel.lastIndexOf('/')) : '');
const excludedDir = (rel: string): boolean => rel.split('/').slice(0, -1).some((s) => SCANNED_WALK_EXCLUDE.has(s));

interface EnvFileListing {
  /** Project-relative, `/`-separated, sorted. */
  files: string[];
  /** Of `files`, those git ignores. */
  ignored: Set<string>;
  /** The walk outside git stopped at its bound: a deeper env file may be unread. */
  cut: boolean;
}

/** The project's env files — tracked, untracked and git-ignored — or a bounded walk's outside git. */
export async function listEnvFiles(root: string): Promise<EnvFileListing> {
  const keep = (rel: string): boolean => isEnvFileName(basenameOf(rel)) && !excludedDir(rel) && !isGuardianOutput(rel);
  const visible = await git(root, ['ls-files', '-z', '--cached', '--others', '--exclude-standard']);
  if (visible.exitCode === 0) {
    const files = new Set(splitNul(visible.stdout).filter(keep));
    const ignored = new Set<string>();
    const hidden = await git(root, ['ls-files', '-z', '--others', '--ignored', '--exclude-standard', '--directory']);
    if (hidden.exitCode === 0) {
      for (const rel of splitNul(hidden.stdout)) {
        if (rel.endsWith('/') || !keep(rel)) continue;
        files.add(rel);
        ignored.add(rel);
      }
    }
    return { files: [...files].sort(), ignored, cut: false };
  }
  return walkEnvFiles(root);
}

function walkEnvFiles(root: string): EnvFileListing {
  const files: string[] = [];
  let entries = 0;
  let cut = false;
  const queue: Array<{ rel: string; depth: number }> = [{ rel: '', depth: 0 }];
  while (queue.length > 0) {
    const next = queue.shift();
    if (next === undefined) break;
    const listed = listProjectDir(root, next.rel === '' ? '.' : next.rel);
    entries += listed.length;
    if (entries > WALK_MAX_ENTRIES) {
      cut = true;
      break;
    }
    for (const e of listed) {
      const rel = next.rel === '' ? e.name : `${next.rel}/${e.name}`;
      if (e.kind === 'directory') {
        if (SCANNED_WALK_EXCLUDE.has(e.name) || isGuardianOutput(rel)) continue;
        if (next.depth + 1 > WALK_MAX_DEPTH) cut = true;
        else queue.push({ rel, depth: next.depth + 1 });
      } else if (e.kind === 'file' && isEnvFileName(e.name) && !isGuardianOutput(rel)) {
        files.push(rel);
      }
    }
  }
  return { files: files.sort(), ignored: new Set(), cut };
}

/** The `supabase/migrations` directories among `files`, and those whose `supabase/config.toml` is among them. */
function migrationDirsOf(files: readonly string[]): string[] {
  const dirs = new Set<string>();
  for (const rel of files) {
    if (MIGRATION_RE.test(rel)) dirs.add(dirOf(rel));
    else if (SUPABASE_CONFIG_RE.test(rel)) dirs.add(`${dirOf(rel)}/migrations`.replace(/^\//, ''));
  }
  return [...dirs].sort();
}

interface ClientTrustResult {
  toolRun: ToolRun;
  /** The pass's gap — a file it found and could not read — as its `missing_tools` name; empty without one. */
  missing: string[];
  findings: Finding[];
}

/** The findings as a parser input, for a pass that pushes onto `parser_inputs`. */
export function clientTrustParser(findings: readonly Finding[]): ScannerParser {
  return { name: CLIENT_TRUST_TOOL, parse: () => ({ findings: [...findings], cves: [] }) };
}

/**
 * Run the checks over `root` (see the module comment); null when there was
 * nothing to check. `ignores` is the project's `.guardianignore`: what it
 * excludes is not read.
 */
export async function runClientTrustChecks(
  root: string,
  opts: { files?: readonly string[]; ignores?: (rel: string) => boolean } = {},
): Promise<ClientTrustResult | null> {
  const ignored = (rel: string): boolean => opts.ignores?.(rel) === true;
  let envFiles: string[];
  let gitIgnored = new Set<string>();
  let cut = false;
  let migrationDirs: string[];
  if (opts.files !== undefined) {
    envFiles = opts.files.filter((rel) => isEnvFileName(basenameOf(rel)) && !excludedDir(rel));
    migrationDirs = migrationDirsOf(opts.files);
  } else {
    const listing = await listEnvFiles(root);
    envFiles = listing.files;
    gitIgnored = listing.ignored;
    cut = listing.cut;
    migrationDirs = migrationDirsOf(await listScannedFiles(root));
  }
  envFiles = envFiles.filter((rel) => !ignored(rel));
  const notes: string[] = [];
  // Migrations that could not be read: their directory is not judged, a gap.
  const unread: string[] = [];
  if (envFiles.length > MAX_ENV_FILES) {
    notes.push(`${envFiles.length - MAX_ENV_FILES} env file(s) past the first ${MAX_ENV_FILES} were not read`);
    envFiles = envFiles.slice(0, MAX_ENV_FILES);
  }

  // An env file that is not a regular file of the project — a link out of it
  // (a worktree's `.env.local` linked to the main checkout's), a FIFO (a
  // secrets manager's mount), one over the cap — is skipped with a note,
  // never read (a FIFO would block) and never a gap: it is the developer's
  // machine, not the project, and a gap there would hold every scan at exit 2.
  const findings: Finding[] = [];
  let envRead = 0;
  let hiddenRead = 0;
  for (const rel of envFiles) {
    const r = readProjectText(root, rel, ENV_FILE_MAX_BYTES);
    if (r.status === 'absent') continue;
    if (r.status === 'refused') {
      notes.push(`${rel} skipped: ${describeReadRefusal(r.reason)}`);
      continue;
    }
    envRead += 1;
    if (gitIgnored.has(rel)) hiddenRead += 1;
    findings.push(...checkEnvFile(rel, r.text));
  }

  let migrationsRead = 0;
  for (const dir of migrationDirs) {
    const sql = listProjectDir(root, dir)
      .filter((e) => (e.kind === 'file' || e.kind === 'link') && /\.sql$/i.test(e.name))
      .map((e) => (dir === '' ? e.name : `${dir}/${e.name}`))
      .filter((rel) => !ignored(rel))
      .sort()
      .slice(0, MAX_MIGRATIONS);
    if (sql.length === 0) continue;
    const files: MigrationFile[] = [];
    const before = unread.length;
    for (const rel of sql) {
      const r = readProjectText(root, rel, MIGRATION_MAX_BYTES);
      if (r.status === 'ok') files.push({ path: rel, text: r.text });
      else if (r.status === 'refused') {
        unread.push(rel);
        notes.push(`${rel}: ${describeReadRefusal(r.reason)}`);
      }
    }
    if (unread.length > before) {
      // A table's RLS may be enabled in the migration that was not read:
      // judged without it, the directory would report what it cannot know.
      notes.push(`the migrations of ${dir} were not checked: one of them could not be read`);
      continue;
    }
    const supabaseDir = dirOf(dir);
    const config = readProjectText(root, supabaseDir === '' ? 'config.toml' : `${supabaseDir}/config.toml`, 256 * 1024);
    migrationsRead += files.length;
    findings.push(...checkSupabaseMigrations(files, exposedSchemasFrom(config.status === 'ok' ? config.text : undefined)));
  }

  if (envRead === 0 && migrationsRead === 0 && unread.length === 0 && notes.length === 0) return null;
  const parts = [
    `${envRead} env file(s)${hiddenRead > 0 ? ` (${hiddenRead} ignored by git, read all the same)` : ''}`,
    `${migrationsRead} Supabase migration(s)`,
  ];
  if (cut) notes.push(`the walk for env files stopped at its bound (depth ${WALK_MAX_DEPTH}, ${WALK_MAX_ENTRIES} entries)`);
  const reason = [`read ${parts.join(' and ')}`, ...notes.slice(0, 6)].join('; ');
  const kept = opts.files === undefined ? findings : findings.filter((f) => f.file_path !== undefined && opts.files?.includes(f.file_path));
  return {
    toolRun: { name: CLIENT_TRUST_TOOL, status: 'ok', reason },
    missing: unread.length > 0 ? [CLIENT_TRUST_TOOL] : [],
    findings: kept,
  };
}

/**
 * The content of the project's env files, for a scan's cache key: the tree
 * hash leaves a git-ignored `.env.local` out, and a cached scan must not
 * answer for a value pasted into it since.
 */
export async function envFilesState(root: string): Promise<string> {
  const listing = await listEnvFiles(root);
  const h = createHash('sha256');
  for (const rel of listing.files.slice(0, MAX_ENV_FILES)) h.update(`${rel}:${await hashProjectFile(root, rel)}\n`);
  return h.digest('hex');
}
