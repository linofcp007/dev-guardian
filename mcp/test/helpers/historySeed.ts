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

export interface ChildSpec {
  findings?: SeedFinding[];
  /** The child's scanner was not installed: skipped, coverage none. */
  blind?: boolean;
  /** The child's scanner ran and failed (Semgrep exit 7): coverage none. */
  failed?: boolean;
  /** Explicit bookkeeping (a partial child: [semgrep failed, bandit ok]). Wins over blind/failed. */
  runs?: ToolRun[];
  missing?: string[];
}

/**
 * Task 9's `security_scan_full` shape: the parent row first (it starts
 * first) holding every child's findings merged and `meta.child_scans`, then
 * one real scan per child type with `meta.parent_scan_id`.
 */
export function seedOrchestratedRun(
  s: Seeded,
  id: string,
  project: string,
  children: { sast?: ChildSpec; secrets?: ChildSpec; deps?: ChildSpec; iac?: ChildSpec },
): void {
  const run = (name: string, c: ChildSpec | undefined): ToolRun =>
    c?.blind === true
      ? { name, status: 'skipped', reason: 'not_installed' }
      : c?.failed === true
        ? { name, status: 'failed', reason: 'exit 7' }
        : { name, status: 'ok' };
  const gap = (c: ChildSpec | undefined): boolean => c?.blind === true || c?.failed === true;
  const kids = [
    { type: 'sast' as const, tool: 'semgrep', c: children.sast },
    { type: 'secrets' as const, tool: 'gitleaks', c: children.secrets },
    { type: 'deps' as const, tool: 'trivy', c: children.deps },
    { type: 'iac' as const, tool: 'trivy-config', c: children.iac },
  ];
  const runsOf = (k: (typeof kids)[number]): ToolRun[] => k.c?.runs ?? [run(k.tool, k.c)];
  const missingOf = (k: (typeof kids)[number]): string[] => k.c?.missing ?? (gap(k.c) ? [k.tool] : []);
  seedScan(s, {
    id,
    type: 'security_full',
    project,
    tools_run: kids.flatMap(runsOf),
    missing_tools: kids.flatMap(missingOf),
    findings: kids.flatMap((k) => k.c?.findings ?? []),
    meta: {
      child_scans: kids.map((k) => ({ tool: `scan_${k.type}`, scan_id: `${id}-${k.type}`, status: 'completed' })),
    },
  });
  for (const k of kids) {
    seedScan(s, {
      id: `${id}-${k.type}`,
      type: k.type,
      project,
      tools_run: runsOf(k),
      missing_tools: missingOf(k),
      findings: k.c?.findings ?? [],
      meta: { parent_scan_id: id },
    });
  }
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
