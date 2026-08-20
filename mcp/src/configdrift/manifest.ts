/**
 * `.dev-guardian/configs.json` — what `init_project` copied, from where, at
 * which plugin version, and what the bytes were at the time.
 *
 * ---- Why this file exists at all --------------------------------------
 *
 * `init_project` copies four baseline configs into a project and then never
 * looks at them again: an existing target is skipped as `already_exists`,
 * which is the correct call — the user owns and edits those files — but it
 * means a fix to a shipped config never reaches anyone who already ran init.
 * `configs/semgrep/base.yml`'s `wp-unescaped-output` rule could not match
 * anything at all (`pattern: echo $_GET[$X]` is not valid PHP); it was fixed
 * in b51a2dc, and every project initialised before that is still running the
 * dead rule with no way to find out. Without a record of what was copied,
 * there is nothing to compare against, so there is no way to tell.
 *
 * ---- Why not `.guardian/`, which already exists -----------------------
 *
 * Because `gitignoreGuard.ts` adds `.guardian/` to the project's `.gitignore`
 * at every server start. That is right for what lives there — a SQLite
 * database and scanner report dumps, per-machine and disposable — and exactly
 * wrong for this. A provenance record has to be committed alongside the
 * configs it describes: the teammate who clones the repo runs the same
 * `.semgrep.yml` and deserves the same drift notice, and CI has no other way
 * to learn which baseline the checkout carries. So it is a separate,
 * deliberately un-ignored directory.
 *
 * ---- Why the file is never trusted ------------------------------------
 *
 * It is a plain JSON file in the user's repository: hand-editable, subject to
 * merge conflicts, and resolvable by someone who does not know what it is.
 * Every read here is defensive and degrades to `null` ("no manifest"), never
 * to an exception. A drift advisory is a courtesy; it must not be able to
 * take a scan down with it.
 */

import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';

/** Path of the manifest relative to the project root. POSIX-shaped by design
 *  — it is also the string shown to users and written into headers. */
export const MANIFEST_RELATIVE_PATH = '.dev-guardian/configs.json';

/** Bumped only for a shape change that older readers cannot interpret. */
export const MANIFEST_SCHEMA_VERSION = 1;

export interface ConfigManifestEntry {
  /** Path relative to the project root, POSIX separators. */
  target: string;
  /** Path relative to the plugin's `configs/`, POSIX separators. */
  source: string;
  /** Plugin version that produced this record. */
  plugin_version: string;
  /** Canonical hash of the shipped file at record time. */
  source_sha256: string;
  /** Canonical hash of the project's file at record time. */
  target_sha256: string;
  recorded_at: string;
  /**
   * `copied` — dev-guardian wrote the file itself, so provenance is certain.
   * `adopted` — the file was already there and was taken under management
   * later. Kept distinct because an adopted entry's history before adoption
   * is unknown, and pretending otherwise is how a "we shipped newer" claim
   * gets made about a file the user hand-wrote.
   */
  provenance: 'copied' | 'adopted';
  /** Relative path of a `.new` file a refresh left alongside, if any. */
  delivered_as?: string;
  delivered_at?: string;
}

export interface ConfigManifest {
  schema_version: number;
  entries: ConfigManifestEntry[];
}

export function manifestPath(projectPath: string): string {
  return join(projectPath, MANIFEST_RELATIVE_PATH);
}

export function emptyManifest(): ConfigManifest {
  return { schema_version: MANIFEST_SCHEMA_VERSION, entries: [] };
}

/**
 * The manifest, or `null` when there is none, it is unreadable, or it is not
 * shaped like a manifest. Individual malformed entries are dropped rather
 * than poisoning the whole file — one bad merge-conflict resolution should
 * cost the entry it damaged, not drift tracking for the other three configs.
 */
export function readManifest(projectPath: string): ConfigManifest | null {
  let raw: unknown;
  try {
    raw = JSON.parse(readFileSync(manifestPath(projectPath), 'utf8'));
  } catch {
    return null;
  }
  if (typeof raw !== 'object' || raw === null) return null;
  const obj = raw as { schema_version?: unknown; entries?: unknown };
  if (!Array.isArray(obj.entries)) return null;
  const entries = obj.entries.filter(isEntry);
  const schema_version =
    typeof obj.schema_version === 'number' ? obj.schema_version : MANIFEST_SCHEMA_VERSION;
  return { schema_version, entries };
}

function isEntry(value: unknown): value is ConfigManifestEntry {
  if (typeof value !== 'object' || value === null) return false;
  const e = value as Record<string, unknown>;
  return (
    typeof e['target'] === 'string' &&
    typeof e['source'] === 'string' &&
    typeof e['plugin_version'] === 'string' &&
    typeof e['source_sha256'] === 'string' &&
    typeof e['target_sha256'] === 'string' &&
    (e['provenance'] === 'copied' || e['provenance'] === 'adopted')
  );
}

/**
 * Writes the manifest, sorted by target so the file has a stable diff, and
 * reports whether it landed. Returns `false` rather than throwing on an
 * unwritable project (read-only checkout, permissions) — losing provenance is
 * a degraded experience, not a failure of the operation that triggered it.
 */
export function writeManifest(projectPath: string, manifest: ConfigManifest): boolean {
  const sorted: ConfigManifest = {
    schema_version: manifest.schema_version,
    entries: [...manifest.entries].sort((a, b) => a.target.localeCompare(b.target)),
  };
  try {
    const path = manifestPath(projectPath);
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, `${JSON.stringify(sorted, null, 2)}\n`, 'utf8');
    return true;
  } catch {
    return false;
  }
}

/** Replaces any entry with the same target, preserving the rest. */
export function upsertManifestEntry(
  manifest: ConfigManifest | null,
  entry: ConfigManifestEntry,
): ConfigManifest {
  const base = manifest ?? emptyManifest();
  return {
    schema_version: MANIFEST_SCHEMA_VERSION,
    entries: [...base.entries.filter((e) => e.target !== entry.target), entry],
  };
}

export function findManifestEntry(
  manifest: ConfigManifest | null,
  target: string,
): ConfigManifestEntry | null {
  return manifest?.entries.find((e) => e.target === target) ?? null;
}
