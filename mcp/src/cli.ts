/**
 * Everything `cli/dev-guardian.mjs` uses from the server's code, in one
 * module — the entry `scripts/bundle.mjs` bundles into the self-contained
 * `dist/cli.js`, as it bundles `server.ts` into `dist/server.js`.
 *
 * Why a bundle: a plugin install is a git checkout with no `node_modules`
 * (the repository is the distribution — CLAUDE.md). The CLI used to import
 * the per-file `tsc` output, `dist/<area>/*.js`, one module at a time; those
 * import the npm dependencies by name, so the day `scan`'s import graph first
 * reached one (`yaml`, through `platform/boundedParse.js`), `scan` and
 * `status` failed in every install with `Cannot find package 'yaml'` — while
 * every test passed, because the tests run in a checkout that has
 * `node_modules`. esbuild inlines every package here; only Node's builtins
 * stay external. `test/e2e/pluginInstall.test.ts` runs the CLI from a copy of
 * the tracked files with no `node_modules` in reach.
 *
 * The CLI imports this module and Node's builtins, and nothing else.
 *
 * What is re-exported directly is loaded with the CLI: `--help`, `check`,
 * `mcp-config` and `ci-init` need nothing more. The `load*` functions reach
 * the scan pipeline and the storage layer through dynamic `import()`, which
 * the bundle keeps lazy — esbuild wraps each module reached only that way in
 * an initializer that runs on the first call — so a command that never asks
 * for them never evaluates them. Each one that opens a database checks
 * `node:sqlite` first, and rejects with Node's own error shape for a missing
 * builtin (`ERR_UNKNOWN_BUILTIN_MODULE`) when it cannot load, which the CLI
 * turns into one line instead of an unexpected error.
 */

import type * as DbModule from './storage/db.js';

export { ALL_HOSTS } from './hostsetup/hostSpecs.js';
export { previewMcpConfig, setupHost } from './hostsetup/setup.js';
export { execGitSync } from './platform/gitSafety.js';
export { detectOs } from './platform/osDetect.js';
export { hardenCommandSearch } from './platform/binaryPath.js';
export { canonicalPath } from './platform/projectPath.js';
export { scanForSecrets } from './hooks/secretScan.js';
export { assessBashCommand } from './hooks/bashGuard.js';
export { decodeText } from './hooks/textEncoding.js';
export { untrustedText } from './platform/untrustedText.js';
export {
  describeReadRefusal,
  describeWriteRefusal,
  isWithinDir,
  PROJECT_LOCKFILE_MAX_BYTES,
  readProjectText,
  writeProjectFile,
} from './platform/projectFs.js';

/** Rejects, as Node does for a builtin it lacks, when this Node cannot load `node:sqlite`. */
function requireNodeSqlite(db: typeof DbModule): void {
  if (db.nodeSqliteAvailable()) return;
  throw Object.assign(new Error(db.NODE_SQLITE_REQUIRED), { code: 'ERR_UNKNOWN_BUILTIN_MODULE' });
}

/** `scan` and `baseline update`: the scan pipeline, the gate and its reports. */
export async function loadCiModules() {
  const [db, ciTypes, baseline, gate, report, runScansMod, appRunner, types, refConfig] = await Promise.all([
    import('./storage/db.js'),
    import('./ci/types.js'),
    import('./ci/baseline.js'),
    import('./ci/gate.js'),
    import('./ci/report.js'),
    import('./ci/runScans.js'),
    import('./ci/appRunner.js'),
    import('./types.js'),
    import('./ci/refConfig.js'),
  ]);
  requireNodeSqlite(db);
  return {
    CI_EXIT: ciTypes.CI_EXIT,
    BASELINE_RELATIVE_PATH: baseline.BASELINE_RELATIVE_PATH,
    parseBaseline: baseline.parseBaseline,
    buildBaseline: baseline.buildBaseline,
    serialiseBaseline: baseline.serialiseBaseline,
    evaluateGate: gate.evaluateGate,
    exitCodeForCoverage: gate.exitCodeForCoverage,
    renderHuman: report.renderHuman,
    renderJson: report.renderJson,
    renderSarif: report.renderSarif,
    runScans: runScansMod.runScans,
    startApp: appRunner.startApp,
    SEVERITIES: types.SEVERITIES,
    resolveCiRef: refConfig.resolveCiRef,
    readBaselineAtRef: refConfig.readBaselineAtRef,
    resetExclusionsFromRef: refConfig.resetExclusionsFromRef,
  };
}

/** `status` and `dashboard`: the storage layer, the snapshot and its two renderers. */
export async function loadDashboardModules() {
  const [db, storage, migrations, snapshot, statusRenderer, dashboardRenderer] = await Promise.all([
    import('./storage/db.js'),
    import('./storage/index.js'),
    import('./storage/migrations/runner.js'),
    import('./dashboard/snapshot.js'),
    import('./dashboard/renderStatus.js'),
    import('./dashboard/renderHtml.js'),
  ]);
  requireNodeSqlite(db);
  return {
    openDatabase: storage.openDatabase,
    Storage: storage.Storage,
    runMigrations: migrations.runMigrations,
    buildSnapshot: snapshot.buildSnapshot,
    renderStatus: statusRenderer.renderStatus,
    renderDashboard: dashboardRenderer.renderDashboard,
  };
}

/** `import-sarif`: the storage layer and the tool registry, with `import_sarif` registered (loading it does). */
export async function loadImportSarifModules() {
  const [db, storage, tools] = await Promise.all([
    import('./storage/db.js'),
    import('./storage/index.js'),
    import('./tools/index.js'),
    import('./tools/importSarif.js'),
  ]);
  requireNodeSqlite(db);
  return { openDatabase: storage.openDatabase, Storage: storage.Storage, TOOLS: tools.TOOLS };
}

/** `db adopt`: inspecting and registering a project's database. */
export async function loadDbModules() {
  const db = await import('./storage/db.js');
  requireNodeSqlite(db);
  return { inspectProjectDatabase: db.inspectProjectDatabase, registerProjectDatabase: db.registerProjectDatabase };
}
