/**
 * `src/cli.ts` — the entry `scripts/bundle.mjs` bundles into `dist/cli.js`,
 * the one module `cli/dev-guardian.mjs` imports. The CLI is plain JavaScript:
 * a member a loader forgot to return is `undefined` there, and fails only when
 * the subcommand that reads it runs. Each loader here returns every member,
 * defined; the e2e files run the bundle itself (`cliLazyStorage.test.ts` for
 * the Node-without-sqlite path, `pluginInstall.test.ts` from an install).
 */

import { describe, expect, it } from 'vitest';
import * as entry from '../../../src/cli.js';

/** The members of `value` that are `undefined`. */
const undefinedMembers = (value: object): string[] =>
  Object.entries(value)
    .filter(([, v]) => v === undefined)
    .map(([k]) => k);

describe('src/cli.ts', () => {
  it('re-exports what every subcommand uses, defined', () => {
    expect(undefinedMembers(entry)).toEqual([]);
    expect(entry.ALL_HOSTS.length).toBeGreaterThan(0);
  });

  it('loadCiModules: the scan pipeline, the gate and its reports', async () => {
    const ci = await entry.loadCiModules();
    expect(undefinedMembers(ci)).toEqual([]);
    expect(ci.SEVERITIES).toContain('high');
    expect(ci.BASELINE_RELATIVE_PATH).toBe('.guardian/baseline.json');
  });

  it('loadDashboardModules: storage, the snapshot and its renderers', async () => {
    const mods = await entry.loadDashboardModules();
    expect(undefinedMembers(mods)).toEqual([]);
    expect(Object.keys(mods).sort()).toEqual(['Storage', 'buildSnapshot', 'openDatabase', 'renderDashboard', 'renderStatus', 'runMigrations']);
  });

  it('loadImportSarifModules: the registry holds import_sarif once it is loaded', async () => {
    const mods = await entry.loadImportSarifModules();
    expect(undefinedMembers(mods)).toEqual([]);
    expect(mods.TOOLS.some((t) => t.name === 'import_sarif')).toBe(true);
  });

  it('loadDbModules: inspecting and registering a project database', async () => {
    const mods = await entry.loadDbModules();
    expect(undefinedMembers(mods)).toEqual([]);
    expect(Object.keys(mods).sort()).toEqual(['inspectProjectDatabase', 'registerProjectDatabase']);
  });
});
