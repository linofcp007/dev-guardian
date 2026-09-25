/**
 * Seeding helpers for the history-scoping tests: several projects, several
 * scan types, deterministic order.
 *
 * Every seeded scan gets an explicit `started_at` one second after the
 * previous one, so "newest" never depends on two inserts landing in
 * different milliseconds. Project paths are real temp directories in the
 * canonical spelling `resolveProjectPath` produces, because that is the
 * string every real scan persists and every tool resolves its
 * `project_path` argument to.
 */

import type { PluginContext } from '../../src/context.js';
import { resolveProjectPath } from '../../src/platform/projectPath.js';
import { makeFinding } from '../../src/runners/scannerParsers/index.js';
import { GuardianDatabase as Database } from '../../src/storage/db.js';
import { Storage } from '../../src/storage/index.js';
import { runMigrations } from '../../src/storage/migrations/runner.js';
import type { Category, ScanStatus, ScanType, Severity, ToolRun } from '../../src/types.js';
import { makeTempDir } from './tempDir.js';

export interface Seeded {
  db: Database;
  storage: Storage;
  plugin: PluginContext;
}

export function freshPlugin(): Seeded {
  const db = new Database(':memory:');
  runMigrations(db);
  const storage = new Storage(db);
  const plugin: PluginContext = {
    storage,
    shell: null,
    scriptsDir: '',
    progressNotifier: { send: () => {} },
  };
  return { db, storage, plugin };
}

/** A real, empty project directory, in canonical form. */
export function projectDir(prefix = 'hist-'): string {
  return resolveProjectPath(makeTempDir(prefix)).path;
}

export interface SeedFinding {
  /** Explicit fingerprint; computed from the other fields when omitted. */
  fp?: string;
  tool?: string;
  rule_id?: string;
  severity?: Severity;
  file?: string;
  line?: number;
  identity?: string;
  message?: string;
  subcategory?: string;
  category?: Category;
}

export interface SeedScan {
  id: string;
  type: ScanType;
  project: string;
  findings?: SeedFinding[];
  tools_run?: ToolRun[];
  missing_tools?: string[];
  meta?: Record<string, unknown>;
  status?: Extract<ScanStatus, 'completed' | 'failed' | 'cancelled'>;
}

let clock = Date.parse('2026-01-01T00:00:00.000Z');

/** Inserts, fills and finalizes one scan, stamped one second after the last. */
export function seedScan(s: Seeded, scan: SeedScan): string {
  s.storage.scans.insert({
    scan_id: scan.id,
    scan_type: scan.type,
    project_path: scan.project,
    tree_hash: `h-${scan.id}`,
  });
  if (scan.findings !== undefined && scan.findings.length > 0) {
    s.storage.findings.bulkInsert(
      scan.findings.map((f, i) => {
        const base = makeFinding({
          tool: f.tool ?? 'semgrep',
          rule_id: f.rule_id ?? 'rule',
          severity: f.severity ?? 'high',
          category: f.category ?? 'security',
          title: `finding ${f.fp ?? i}`,
          file_path: f.file ?? `src/${scan.id}-${i}.ts`,
          line_start: f.line ?? i + 1,
          ...(f.message !== undefined ? { message: f.message } : {}),
          ...(f.subcategory !== undefined ? { subcategory: f.subcategory } : {}),
        });
        return {
          ...base,
          ...(f.fp !== undefined ? { fingerprint: f.fp } : {}),
          ...(f.identity !== undefined ? { identity: f.identity, content_key: `ck-${f.identity}` } : {}),
          scan_id: scan.id,
        };
      }),
    );
  }
  s.storage.scans.finalize({
    scan_id: scan.id,
    status: scan.status ?? 'completed',
    tools_run: scan.tools_run ?? [{ name: 'semgrep', status: 'ok' }],
    missing_tools: scan.missing_tools ?? [],
    ...(scan.meta !== undefined ? { meta: scan.meta } : {}),
  });
  clock += 1000;
  s.db.prepare('UPDATE scans SET started_at = ?, finished_at = ? WHERE id = ?').run(
    new Date(clock).toISOString(),
    new Date(clock + 500).toISOString(),
    scan.id,
  );
  return scan.id;
}
