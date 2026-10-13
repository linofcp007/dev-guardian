/**
 * map_attack_surface over a TypeScript project whose imports are `import type`
 * and multi-line re-exports — against the REAL Semgrep (review 8, finding 1).
 *
 * Measured on 3.2.1: a two-file repository whose only import was
 * `import type { Thing } from './types.js'` made the metavariable recovery
 * count every match unrecoverable and mark its step `failed`; with nothing
 * readable at all no surface was saved, `validate_finding` refused with
 * `no_surface_snapshot`, and both `baseline update` and `scan` exited 2 — on
 * any TypeScript project. Now those shapes are read, and an import or env
 * edge that still cannot be is a note: only a lost route fails the run.
 *
 * Gated on Semgrep being on PATH.
 */
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, describe, expect, it, vi } from 'vitest';
import type { PluginContext } from '../../src/context.js';
import { resolveProjectPath } from '../../src/platform/projectPath.js';
import { resolveScriptsDir } from '../../src/platform/scriptsDir.js';
import { GuardianDatabase as Database } from '../../src/storage/db.js';
import { Storage } from '../../src/storage/index.js';
import { runMigrations } from '../../src/storage/migrations/runner.js';
import { TOOLS } from '../../src/tools/index.js';
import '../../src/tools/mapAttackSurface.js';
import type { ToolRun } from '../../src/types.js';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';
import { isInstalled } from '../helpers/toolchain.js';

vi.setConfig({ testTimeout: 300_000 });
afterAll(cleanupTempDirs);

const SEMGREP = await isInstalled('semgrep');

const FILES: Record<string, string> = {
  'src/types.ts': 'export interface Thing { id: string }\nexport type Other = number;\n',
  'src/index.ts':
    "import type { Thing } from './types.js';\n" +
    "import type * as T from './types.js';\n" +
    "export {\n  first,\n  second,\n} from './helpers.js';\n" +
    'export function show(t: Thing, o: T.Other): string { return t.id + String(o); }\n',
  'src/helpers.ts': 'export const first = 1;\nexport const second = 2;\n',
};

describe('map_attack_surface: TypeScript type imports and multi-line re-exports', () => {
  it.skipIf(!SEMGREP)('the recovery step is not failed, and the surface is saved', async () => {
    const dir = resolveProjectPath(makeTempDir('surface-type-imports-')).path;
    for (const [rel, body] of Object.entries(FILES)) {
      mkdirSync(join(dir, rel, '..'), { recursive: true });
      writeFileSync(join(dir, rel), body);
    }
    const tool = TOOLS.find((t) => t.name === 'map_attack_surface');
    if (!tool) throw new Error('map_attack_surface not registered');
    const db = new Database(':memory:');
    runMigrations(db);
    const storage = new Storage(db);
    const ctx: PluginContext = { storage, shell: null, scriptsDir: resolveScriptsDir(), progressNotifier: { send: () => {} } };
    const r = await tool.handler({ project_path: dir, force: true }, ctx);
    if (!r.ok) throw new Error(JSON.stringify(r.error));
    const out = r as unknown as { tools_run: ToolRun[]; missing_tools: string[] };
    const recovery = out.tools_run.find((t) => t.name === 'semgrep-metavar-recovery');
    expect(recovery?.status, JSON.stringify(out.tools_run)).not.toBe('failed');
    expect(recovery?.reason ?? '').not.toMatch(/could not be read/);
    expect(out.missing_tools).not.toContain('semgrep-metavar-recovery');
    expect(storage.surface.getLatestForProject(dir)).not.toBeNull();
  });
});
