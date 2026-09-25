/**
 * `deps_update_plan` — proposes an ordered dependency-upgrade plan.
 *
 * Unlike scan tools, this does NOT produce Findings — its output is an
 * ordered list of `UpgradeStep` entries. Wiring it through the
 * scan-tool factory would force-fit it into a ScanResult shape; we use
 * `registerToolModule` directly instead.
 *
 * Strategy:
 *   1. Detect the stack via `latest stack_snapshots` (or `package.json` /
 *      `pyproject.toml` / etc. as a fallback).
 *   2. Per ecosystem:
 *        npm      → `npm outdated --json` for direct-dependency current/
 *                    latest, PLUS a sweep of the whole CVE map for anything
 *                    that listing never surfaces — `npm outdated --json`
 *                    has listed only DIRECT dependencies since npm 7, so a
 *                    transitive package never appears in it at all. Every
 *                    CVE-driven target is the smallest version STRICTLY
 *                    ABOVE what is currently installed
 *                    (`../deps/versionCompare.js#minCleanVersionAbove`, or
 *                    its `...Loose` counterpart for a PRE-RELEASE install —
 *                    fix round 3, item N2: `2.0.0-beta.1` is genuinely
 *                    below a clean `2.0.1` fix, which the strict clean-
 *                    version check alone cannot see) — never a scanner's
 *                    raw "fixed_version" taken on faith, which can be an
 *                    older release branch's own backport, simply stale
 *                    (`already_fixed` — never relabels a resolved CVE
 *                    `security` on the strength of an ordinary npm-latest
 *                    bump; only ever claimed for a CLEAN installed version,
 *                    never a pre-release), or belonging to some OTHER
 *                    ecosystem the CVE table's own lack of an ecosystem
 *                    column cannot rule out (the CVE-map sweep only claims
 *                    a package `package-lock.json` / `node_modules` —
 *                    including pnpm's own flat `.pnpm` store, fix round 3 —
 *                    actually resolves, case-insensitively, keyed by the
 *                    LOCKFILE's own spelling of the name). Every
 *                    `npm install` carries `--ignore-scripts`; a transitive
 *                    CVE'd package gets an `npm pkg set
 *                    overrides[<pkg>]=<version>` step (bracket notation — a
 *                    dotted package name would otherwise become a nested
 *                    key; deliberately UNQUOTED — `create_fix_pr` runs this
 *                    without a shell, and fix round 2's own quoting
 *                    corrupted `package.json` there; a shell-quoted,
 *                    paste-safe copy is in `shell_command` instead) with a
 *                    `follow_up_command` of `npm install --ignore-scripts`
 *                    to re-resolve the lockfile. A direct dependency `npm
 *                    outdated` itself never lists at all is reported
 *                    `unplanned`, not silently skipped;
 *        pip      → NEVER runs pip/pip-audit against the host interpreter.
 *                    Reads this project's own `requirements*.txt` pins
 *                    (including pip-compile hash-continuation lines,
 *                    extras and environment markers) and PEP 621
 *                    `[project] dependencies` — scoped to that ONE TOML
 *                    table (fix round 3: a `[tool.uv] dev-dependencies`
 *                    array earlier in the same file used to win an
 *                    unscoped substring search outright), extras and range
 *                    specs included (a depth-counting array parser, not a
 *                    `[^\]]*` regex that stopped at an extras marker's own
 *                    `]`), environment markers stripped before matching on
 *                    either path — and proposes a step only for an exact
 *                    pin with an active CVE and a fix version above the pin
 *                    — see `runPipPlan`'s own doc comment for why
 *                    `upgrade_command` is not a real, executable command
 *                    here, and why the target file is also exposed as a
 *                    structured `file` field. Pip has NO CVE-map sweep of
 *                    its own (fix round 3: the earlier one mislabelled
 *                    non-pip packages, e.g. a composer or Go one, `'pip'`
 *                    purely because npm did not resolve them) — a
 *                    genuinely transitive pip dependency with no manifest
 *                    mention now surfaces through the catch-all below;
 *        composer / cargo / go / rubygems / dotnet → each stack's own
 *                    "outdated" command. dotnet ALWAYS restores explicitly
 *                    FIRST now (fix round 3 — never "try list first,
 *                    restore only on failure": a STALE but PRESENT `obj/`
 *                    makes `dotnet list --no-restore` exit 0 with valid-
 *                    looking JSON built from the OLD resolution, which
 *                    that shape could never catch), `--locked-mode` when
 *                    ANY `packages.lock.json` exists anywhere under the
 *                    project, a plain restore otherwise — a scan must
 *                    never modify the working tree, and a
 *                    `requestedVersion` != `resolvedVersion` mismatch in
 *                    the list JSON is treated as stale even after a
 *                    restore that reported success.
 *      (Other stacks return an empty plan with `unsupported_ecosystems_present`.)
 *      **Every package with an active CVE that did NOT become a step is
 *      reported in `unplanned`** (package, ecosystem, cve_ids, reason) —
 *      never silently dropped: a non-exact pip specifier, a CVE whose only
 *      reported fix is a downgrade or already resolved, a transitive
 *      package with no recorded installed version to compare against, or
 *      one no ecosystem's own manifest evidence could confirm at all. As a
 *      final catch-all (fix round 3, `appendCatchAllUnplanned`), ANY CVE
 *      key that still has neither a step nor an ecosystem-specific
 *      `unplanned` entry after every runner has had a turn — a composer/
 *      cargo/go/rubygems package (none of those have a CVE-map sweep of
 *      their own), a `.NET` target whose restore failed — is reported
 *      `unplanned` with ecosystem `'unknown'` rather than vanishing from
 *      both `plan` and `unplanned` together.
 *   3. Classify each entry as patch / minor / major (by semver diff).
 *   4. Mark entries as `security` when an active CVE exists for the package —
 *      sourced from the latest `deps` / `deps_audit` / `security_full` scan
 *      of THIS SAME PROJECT (`CVE_SOURCE_SCAN_TYPES`, `../types.js`), never
 *      an unscoped "whatever scan is latest in the whole database" lookup.
 *   5. Order the result by `prefer` (default: security, then patch, then
 *      minor, then major).
 */

import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { execa } from 'execa';
import { z } from 'zod';
import type { PluginContext } from '../context.js';
import {
  compareVersions,
  isCleanVersion,
  minCleanVersionAbove,
  minCleanVersionAboveLoose,
} from '../deps/versionCompare.js';
import { ProjectPath } from '../schemas.js';
import { CVE_SOURCE_SCAN_TYPES, type DomainError, type ToolResult } from '../types.js';
import { resolveProjectPath } from '../platform/projectPath.js';
import { registerToolModule, type ToolModule } from './index.js';

type Classification = 'security' | 'patch' | 'minor' | 'major';

interface UpgradeStep {
  /** Also the field Task 11's structured matching calls `package`. */
  package_name: string;
  /** Also `from`. */
  installed_version: string;
  /** Also `to`. */
  latest_version: string;
  classification: Classification;
  ecosystem: 'npm' | 'pip' | 'composer' | 'cargo' | 'go' | 'rubygems' | 'dotnet' | 'unknown';
  reason?: string;
  /** Active CVE ids on `installed_version`, when `classification === 'security'`. */
  cve_ids?: string[];
  /**
   * The manifest/lock file this step's edit applies to — structured, not
   * parsed out of `upgrade_command` (fix round 1, item 9): a path can
   * contain spaces, which a whitespace-tokenised command string cannot
   * represent unambiguously. Set on `pip` steps; other ecosystems' targets
   * are named by `package_name` and `upgrade_command` alone.
   */
  file?: string;
  /**
   * MUST stay argv-safe — no quoting of any kind. `create_fix_pr`'s own
   * `fixpr/apply.ts` splits this on whitespace and runs it WITHOUT a shell
   * (`toArgv`, its own module comment), so a quoted token is not unwrapped:
   * a fix round 2 attempt to single-quote `overrides[...]=...` (to make it
   * paste-safe in a shell that globs by default) made `npm pkg set` receive
   * the literal quote characters as part of the key/value, writing
   * `"'overrides":{"minimist":"1.2.6'"}` to `package.json` while `apply.ts`
   * still reported `applied: true` (fix round 3, item N1 — the coordinator's
   * own probe against `applyGroup`). A human-facing, shell-quoted copy of
   * the SAME command belongs in `shell_command` instead.
   */
  upgrade_command: string;
  /** The SAME command as `upgrade_command`, shell-quoted for a human to
   *  paste into a terminal (a shell that globs by default, e.g. zsh, reads
   *  an unquoted `overrides[...]` as a filename pattern) — never used by
   *  `create_fix_pr`'s own unquoted, non-shell `execa` invocation. Set only
   *  where quoting would otherwise matter (an npm `overrides` step); absent
   *  when `upgrade_command` is already shell-safe as written. */
  shell_command?: string;
  /**
   * A second command that MUST run after `upgrade_command` for the fix to
   * actually take effect — set on an npm `overrides` step
   * (`npm pkg set overrides[...]=...` only rewrites `package.json`; the
   * lockfile/`node_modules` do not reflect it until a plain
   * `npm install --ignore-scripts` re-resolves). `undefined` when
   * `upgrade_command` alone is the whole fix.
   */
  follow_up_command?: string;
}

/** A package with an active CVE that could NOT be turned into an
 *  `UpgradeStep` — reported instead of silently dropped (fix round 1, item
 *  7): a range specifier with no determinable installed version, a CVE
 *  whose only reported fix is a downgrade, a transitive dependency with no
 *  recorded installed version to compare against, and so on. */
interface UnplannedEntry {
  package_name: string;
  ecosystem: UpgradeStep['ecosystem'];
  cve_ids: string[];
  reason: string;
}

/** What one ecosystem runner returns: the steps it could plan, plus every
 *  CVE'd package it looked at but could not turn into a step. */
interface EcosystemPlan {
  steps: UpgradeStep[];
  unplanned: UnplannedEntry[];
}

function noUnplanned(steps: UpgradeStep[]): EcosystemPlan {
  return { steps, unplanned: [] };
}

/** What `listActiveCves` resolves per package: enough to compute the
 *  MINIMUM fixed version (never "latest") and to populate `cve_ids`. */
interface CveInfo {
  cveIds: string[];
  /** `cves.fixed_version`, when every active CVE on the package reported
   *  one AND it is a clean version genuinely above `installedVersion`.
   *  `undefined` when none did, or the only candidates were stale/messy
   *  (see `listActiveCves`'s own comment). */
  fixedVersion?: string;
  /**
   * The `installed_version` this CVE was recorded against, from whichever
   * scan produced it. Used as the "current version" for a package no
   * ecosystem-native tool reports at all — a transitive npm dependency,
   * which `npm outdated --json` never lists (fix round 1, item 2).
   */
  installedVersion?: string;
  /** The package name as the CVE scan recorded it (real case) — `cves` is
   *  keyed by LOWERCASED name, so this is needed wherever the original
   *  casing matters (reporting an unplanned transitive package by name). */
  displayName: string;
}

interface Summary {
  total: number;
  by_classification: Record<Classification, number>;
  has_security_updates: boolean;
}

const inputSchema = {
  project_path: ProjectPath,
  prefer: z
    .enum(['security', 'patch', 'minor', 'major'])
    .optional()
    .describe('Sort entries so this classification appears first. Default: security.'),
};

const tool: ToolModule = {
  name: 'deps_update_plan',
  title: 'Dependency upgrade plan',
  description:
    'Produce an ordered upgrade plan from the project. npm/composer/cargo/go/rubygems/dotnet use ' +
    'each stack\'s own "outdated" command; pip reads this project\'s own requirements*.txt / ' +
    'pyproject.toml pins and never touches the host Python. Classifies each entry as security ' +
    '(minimum CVE-fixed version, from the same project\'s latest deps scan) / patch / minor / ' +
    'major, and returns a sortable, structured plan (package_name, ecosystem, installed_version, ' +
    'latest_version, cve_ids, upgrade_command).',
  inputSchema,
  handler: async (input, ctx) => handler(input, ctx),
};

registerToolModule(tool);

async function handler(
  input: Record<string, unknown>,
  ctx: PluginContext,
): Promise<ToolResult<Record<string, unknown>>> {
  const inp = input as { project_path?: string; prefer?: Classification };
  let projectPath: string;
  try {
    projectPath = resolveProjectPath(inp.project_path).path;
  } catch (e) {
    return failDomain('not_a_git_repo', (e as Error).message);
  }

  const cves = listActiveCves(ctx, projectPath);
  const ecosystems = detectEcosystems(projectPath);
  const plansByEcosystem = await Promise.all(
    ecosystems.map(async (eco): Promise<EcosystemPlan> => {
      switch (eco) {
        case 'npm':
          return runNpmOutdated(projectPath, cves);
        case 'pip':
          return runPipPlan(projectPath, cves);
        case 'composer':
          return noUnplanned(await runComposerOutdated(projectPath, cves));
        case 'cargo':
          return noUnplanned(await runCargoOutdated(projectPath, cves));
        case 'go':
          return noUnplanned(await runGoOutdated(projectPath, cves));
        case 'rubygems':
          return noUnplanned(await runBundlerOutdated(projectPath, cves));
        case 'dotnet':
          return noUnplanned(await runDotnetOutdated(projectPath, cves));
        default:
          return noUnplanned([]);
      }
    }),
  );

  const flat: UpgradeStep[] = plansByEcosystem.flatMap((p) => p.steps);
  const unplanned: UnplannedEntry[] = plansByEcosystem.flatMap((p) => p.unplanned);
  appendCatchAllUnplanned(cves, flat, unplanned);
  const ordered = orderPlan(flat, inp.prefer ?? 'security');
  const summary = summarize(ordered);

  return {
    ok: true,
    plan: ordered,
    summary,
    unplanned,
    stack_detected: ecosystems,
    unsupported_ecosystems_present: detectUnsupportedEcosystems(projectPath),
  };
}

// ---------------------------------------------------------------------- detection

function detectEcosystems(projectPath: string): Array<UpgradeStep['ecosystem']> {
  const out: Array<UpgradeStep['ecosystem']> = [];
  if (existsSync(join(projectPath, 'package.json'))) out.push('npm');
  if (
    existsSync(join(projectPath, 'pyproject.toml')) ||
    existsSync(join(projectPath, 'requirements.txt')) ||
    existsSync(join(projectPath, 'setup.py'))
  )
    out.push('pip');
  if (existsSync(join(projectPath, 'composer.json'))) out.push('composer');
  if (existsSync(join(projectPath, 'Cargo.toml'))) out.push('cargo');
  if (existsSync(join(projectPath, 'go.mod'))) out.push('go');
  if (existsSync(join(projectPath, 'Gemfile'))) out.push('rubygems');
  if (anyCsproj(projectPath)) out.push('dotnet');
  return out;
}

function anyCsproj(projectPath: string): boolean {
  try {
    return readdirSync(projectPath).some((n) => n.endsWith('.csproj') || n.endsWith('.sln'));
  } catch {
    return false;
  }
}

function detectUnsupportedEcosystems(projectPath: string): string[] {
  // Maven / Gradle: parsing `mvn versions:display-dependency-updates` or
  // `gradle dependencyUpdates` output is non-trivial — listed as unsupported
  // pending demand.
  const out: string[] = [];
  if (existsSync(join(projectPath, 'pom.xml'))) out.push('maven');
  if (
    existsSync(join(projectPath, 'build.gradle')) ||
    existsSync(join(projectPath, 'build.gradle.kts'))
  )
    out.push('gradle');
  return out;
}

/**
 * The final safety net (fix round 3, item #7 — "catch-all"): every CVE key
 * that, after every ecosystem runner has had a turn, produced NEITHER a
 * step NOR an `unplanned` entry is pushed to `unplanned` here, tagged
 * ecosystem `'unknown'`. The `cves` table has no ecosystem column, and
 * every per-ecosystem runner only claims a package it has SOME real
 * evidence for (a manifest mention, an "outdated" listing, a resolved
 * lockfile entry) — which means a package genuinely outside every runner's
 * evidence (composer/cargo/go/rubygems have no CVE-map sweep of their own
 * at all; a pnpm project's `node_modules` symlinks are invisible to the
 * npm-lockfile reader; a `.NET` target whose locked restore failed) used to
 * vanish from BOTH `plan` and `unplanned` with nothing to show for it.
 * Reproduced by the coordinator on three different shapes — npm+composer
 * with no pip (`laravel/framework`), a pnpm project (`minimist`), and a
 * `.NET` project with a failed locked restore — all silently dropped.
 * `undetermined`/`unknown` is the same honest fallback `license_compatibility`
 * already uses for "this tool cannot decide" rather than silence.
 */
function appendCatchAllUnplanned(
  cves: Map<string, CveInfo>,
  steps: UpgradeStep[],
  unplanned: UnplannedEntry[],
): void {
  const named = new Set<string>([
    ...steps.map((s) => s.package_name.toLowerCase()),
    ...unplanned.map((u) => u.package_name.toLowerCase()),
  ]);
  for (const [pkgLower, cve] of cves) {
    if (named.has(pkgLower)) continue;
    unplanned.push({
      package_name: cve.displayName,
      ecosystem: 'unknown',
      cve_ids: cve.cveIds,
      reason:
        'active CVE, but no ecosystem runner in this project found manifest/lockfile/outdated-' +
        'listing evidence for it — could not be attributed to a supported stack or turned into a step',
    });
  }
}

/**
 * Active CVEs, keyed by lowercased package name, sourced from the latest
 * `deps` / `deps_audit` / `security_full` scan of THIS project —
 * `CVE_SOURCE_SCAN_TYPES` (`../types.js`), the same set Task 6 established
 * as "the same project's deps history". Previously this read
 * `ctx.storage.scans.getLatest()`, the UNSCOPED "any project, any scan
 * type" row — a `sast`-only scan of a different project could win here and
 * silently zero out every CVE, the same class of bug documented in
 * `scansRepo.ts`'s own module comment for `getLatest`/`listHistory`.
 */
function listActiveCves(ctx: PluginContext, projectPath: string): Map<string, CveInfo> {
  const history = ctx.storage.scans.listHistoryForProject(projectPath, 50);
  const latest = history.find(
    (s) => CVE_SOURCE_SCAN_TYPES.includes(s.scan_type) && s.status === 'completed',
  );
  const out = new Map<string, CveInfo>();
  if (!latest) return out;
  for (const cve of ctx.storage.cves.listActive(latest.scan_id)) {
    const key = cve.package_name.toLowerCase();
    // Trivy's own `FixedVersion` is free text and routinely NOT a single
    // installable version: multi-branch lists ("4.17.12, 5.0.0") and open
    // ranges (">=4.17.11") both appear on real scans (lodash's own CVE
    // history has both), and a CVE row can simply be STALE (recorded
    // against an older installed version than what a fresh ecosystem query
    // reports now). `minCleanVersionAbove` — never a raw `fixed_version`
    // read verbatim — is what keeps a package with several active CVEs,
    // some clean and one messy or stale, from silently ending up with a
    // downgrade as its computed minimum (fix round 1, CRITICAL item 1).
    const existing = out.get(key);
    const installedForThisCve = cve.installed_version;
    const candidate = minCleanVersionAbove(installedForThisCve, [cve.fixed_version]);
    if (existing) {
      existing.cveIds.push(cve.cve_id);
      if (existing.installedVersion === undefined) existing.installedVersion = installedForThisCve;
      // The MINIMUM version that clears every active CVE is the MAXIMUM of
      // each individual CVE's own minimum fix — installing anything less
      // than the highest one leaves that CVE's own fix unmet.
      if (
        candidate !== undefined &&
        (existing.fixedVersion === undefined || compareVersions(candidate, existing.fixedVersion) > 0)
      ) {
        existing.fixedVersion = candidate;
      }
    } else {
      out.set(key, {
        cveIds: [cve.cve_id],
        fixedVersion: candidate,
        installedVersion: installedForThisCve,
        displayName: cve.package_name,
      });
    }
  }
  return out;
}

// ---------------------------------------------------------------------- runners

/**
 * npm branch (item 4, fix round 1 items 1 and 2):
 *   - a package with an active CVE upgrades to the MINIMUM fixed version
 *     (`cves.fixed_version`) rather than `npm outdated`'s own `latest` —
 *     the smallest change that actually resolves the CVE, not whatever is
 *     newest today — and NEVER a downgrade: `minCleanVersionAbove` compares
 *     against THIS run's own `npm outdated` "current" value, the freshest
 *     installed-version signal available, not just the (possibly stale)
 *     value the CVE row was recorded against;
 *   - every `npm install` this plan emits carries `--ignore-scripts` — a
 *     dependency's install/postinstall script must never run just because
 *     this tool proposed a version bump;
 *   - a TRANSITIVE package (not named in this project's own `package.json`
 *     `dependencies`/`devDependencies`/`optionalDependencies`/
 *     `peerDependencies` — see `readNpmDirectDependencies`'s own comment for
 *     why NOT `npm outdated --json`'s `dependent` field) with an active CVE
 *     gets an `overrides` step instead of an `npm install` —
 *     `npm install <transitive>@<version>` does not reliably pin a nested
 *     dependency's resolved version the way `package.json`'s own
 *     `overrides` field does. `npm pkg set` edits the manifest only, so
 *     every override step also carries a `follow_up_command`
 *     (`npm install --ignore-scripts`, no explicit package) to re-resolve
 *     the lockfile.
 *
 * **Driven from the CVE map, not from `npm outdated`'s own listing, for the
 * transitive case.** `npm outdated --json` has listed ONLY direct
 * dependencies since npm 7 — a transitive package never appears in it at
 * all, so a check that only classifies entries FROM that listing (`pkg in
 * parsed`) can never actually reach the transitive branch against a real
 * npm install; it only fired in a hand-built mock. Pass 1 below still reads
 * `npm outdated` for direct-dependency current/latest info; pass 2 sweeps
 * the WHOLE `cves` map for anything pass 1 did not already handle and that
 * is not a declared direct dependency, using the CVE row's own recorded
 * `installed_version` (the only "current version" signal available for a
 * package no ecosystem-native tool reports at all).
 */
async function runNpmOutdated(
  projectPath: string,
  cves: Map<string, CveInfo>,
): Promise<EcosystemPlan> {
  const result = await execa('npm', ['outdated', '--json'], {
    cwd: projectPath,
    reject: false,
    timeout: 60_000,
  });
  const steps: UpgradeStep[] = [];
  const unplanned: UnplannedEntry[] = [];
  let outdatedObj: Record<string, unknown> = {};
  if (result.stdout.trim().length > 0) {
    try {
      const parsed: unknown = JSON.parse(result.stdout);
      if (parsed && typeof parsed === 'object') outdatedObj = parsed as Record<string, unknown>;
    } catch {
      /* leave outdatedObj empty — pass 2 (CVE-map sweep) still runs */
    }
  }

  const directDeps = readNpmDirectDependencies(projectPath);
  const handled = new Set<string>(); // lowercased names pass 1 already decided

  // Pass 1: npm outdated's own entries — direct dependencies only, on a
  // real npm 7+ install (see this function's own doc comment).
  for (const [pkg, raw] of Object.entries(outdatedObj)) {
    if (!raw || typeof raw !== 'object') continue;
    const row = raw as Record<string, unknown>;
    const installed = typeof row['current'] === 'string' ? (row['current'] as string) : '';
    const npmLatest = typeof row['latest'] === 'string' ? (row['latest'] as string) : '';
    if (!installed) continue;
    const pkgLower = pkg.toLowerCase();
    handled.add(pkgLower);

    const cve = cves.get(pkgLower);
    // The CVE's own minimum fix, checked against THIS run's actual current
    // version — never the (possibly stale) version the CVE row itself was
    // recorded against. `minCleanVersionAboveLoose`, not the strict
    // `minCleanVersionAbove` (fix round 3, item N2): `installed` can be a
    // PRE-RELEASE (`2.0.0-beta.1`), which the strict clean-version regex
    // rejects outright — that rejection alone used to read as "no safe
    // version above installed", indistinguishable from the package already
    // being past the fix. The loose comparator uses real pre-release
    // precedence instead, so a genuinely later fix (`2.0.1`) is still
    // recognised as above a pre-release install of the SAME or an earlier
    // core version. The candidate fix itself is still required to be a
    // clean, installable version either way.
    const safeCveVersion = cve ? minCleanVersionAboveLoose(installed, [cve.fixedVersion]) : undefined;
    // A CVE row whose OWN recorded fix target IS defined but no longer
    // above the FRESH installed version npm just reported: the package was
    // already upgraded past the fix by the time this ran, and the CVE
    // record is simply stale (fix round 2, "cheap" item — the coordinator's
    // own probe: installed already at/above the fix). This must NEVER fall
    // through to npm's ordinary "latest" labelled `security` with those
    // (already-resolved) CVE ids still attached — it is reported as
    // resolved/stale here instead, tagged `already_fixed` so a caller can
    // pattern-match on it.
    //
    // Only ever claimed when `installed` is a plain, unambiguous CLEAN
    // version (fix round 3, item N2): a pre-release install failing
    // `minCleanVersionAboveLoose` above for a DIFFERENT reason (no clean
    // candidate exists at all, or the whole string is not even loosely a
    // version) must not be misread as "already fixed" just because
    // `safeCveVersion` came back empty — `isCleanVersion(installed)` and a
    // DIRECT `compareVersions` against the CVE's own recorded fix is the
    // only basis for "the install is already at or above the fix",
    // independent of whatever `safeCveVersion` computed.
    const staleCve =
      cve !== undefined &&
      cve.fixedVersion !== undefined &&
      isCleanVersion(installed) &&
      compareVersions(cve.fixedVersion, installed) <= 0;
    if (staleCve && cve) {
      unplanned.push({
        package_name: pkg,
        ecosystem: 'npm',
        cve_ids: cve.cveIds,
        reason:
          `already_fixed: installed version ${installed} is already at or above the recorded fix ` +
          `${cve.fixedVersion} — the CVE record is stale.`,
      });
    }
    const safeNpmLatest =
      isCleanVersion(npmLatest) && compareVersions(npmLatest, installed) > 0 ? npmLatest : undefined;
    const latest = staleCve ? safeNpmLatest : (safeCveVersion ?? safeNpmLatest);

    if (cve && !staleCve && !latest) {
      unplanned.push({
        package_name: pkg,
        ecosystem: 'npm',
        cve_ids: cve.cveIds,
        reason:
          'active CVE, but no safe upgrade target: the reported fix version is not above the ' +
          'installed version, and npm reports no newer release either',
      });
      continue;
    }
    if (!latest || installed === latest) continue;

    // `!staleCve && cve !== undefined` narrows `cve` directly in this `if`
    // (fix round 2, item 11 — no `!` non-null assertion; the previous shape
    // computed a separately-named `isTransitive` boolean first, which TS
    // cannot use to narrow `cve` inside a ternary's true branch).
    if (!staleCve && cve !== undefined && directDeps.size > 0 && !directDeps.has(pkgLower)) {
      steps.push(buildOverrideStep({ package_name: pkg, installed_version: installed, latest_version: latest, cve }));
    } else {
      steps.push(
        buildStep({
          package_name: pkg,
          installed_version: installed,
          latest_version: latest,
          ecosystem: 'npm',
          // A stale CVE must not re-attach its (already resolved) ids via
          // buildStep's own lookup — an empty map forces the ordinary
          // semver classification instead of `security`.
          cves: staleCve ? new Map() : cves,
          upgrade_command: `npm install ${pkg}@${latest} --ignore-scripts`,
        }),
      );
    }
  }

  // Pass 2: CVE'd packages `npm outdated` never lists at all — either a
  // TRANSITIVE dependency (npm 7+ never lists one), or a DIRECT dependency
  // npm's own "outdated" check simply did not flag (fix round 2, item 7's
  // npm half: this used to `continue` silently for a direct dependency,
  // dropping an active CVE with no upgrade target AND no unplanned entry).
  // Driven entirely from the CVE map — see the module comment above — but,
  // for the transitive branch, ONLY for a package this npm install's own
  // resolved graph actually contains (fix round 2, item 10: the `cves`
  // table has no ecosystem column, so without this check every non-npm
  // CVE'd package in a polyglot repo — a pip `django`, a composer
  // `laravel/framework` — was wrongly turned into an npm override step).
  const npmResolvedNames = readNpmResolvedPackageNames(projectPath);
  for (const [pkgLower, cve] of cves) {
    if (handled.has(pkgLower)) continue;
    if (directDeps.has(pkgLower)) {
      unplanned.push({
        package_name: cve.displayName,
        ecosystem: 'npm',
        cve_ids: cve.cveIds,
        reason:
          'active CVE on a direct dependency that `npm outdated` did not report — no upgrade ' +
          'target determined automatically',
      });
      continue;
    }
    const lockfileName = npmResolvedNames.get(pkgLower);
    if (lockfileName === undefined) continue; // not a package this npm install resolves at all — leave it to its own ecosystem
    const installed = cve.installedVersion;
    const target = minCleanVersionAbove(installed, [cve.fixedVersion]);
    if (!installed || !target) {
      // A package this npm graph DOES resolve, but with no recorded
      // installed_version on the CVE row at all — cannot even compute a
      // target, only report the gap when there IS an installed_version.
      if (installed) {
        unplanned.push({
          package_name: lockfileName,
          ecosystem: 'npm',
          cve_ids: cve.cveIds,
          reason: `active CVE on a transitive dependency, but no fix version above the recorded installed version ${installed}`,
        });
      }
      continue;
    }
    steps.push(
      // `lockfileName`, NOT `cve.displayName` (fix round 3, "cheap" item):
      // `overrides[<name>]` must be keyed by the LOCKFILE's own spelling —
      // a scanner's own recorded casing (`MiniMist`) creates an override
      // for a name that does not exist in the tree at all, silently doing
      // nothing.
      buildOverrideStep({ package_name: lockfileName, installed_version: installed, latest_version: target, cve }),
    );
  }

  return { steps, unplanned };
}

/**
 * The package NAMES this project's own `package.json` declares directly
 * (`dependencies` + `devDependencies` + `optionalDependencies` +
 * `peerDependencies`) — used to tell a direct dependency apart from a
 * transitive one.
 *
 * **Not** `npm outdated --json`'s own `dependent` field: measured directly
 * against a real npm install, `dependent` for a TOP-LEVEL package is not
 * this project's `package.json` `name` at all — it read the enclosing
 * DIRECTORY's basename instead (`"npmoutdated"` for a project whose
 * `package.json` declared `"name": "x"`). Comparing that against
 * `package.json`'s own `name` field made every direct dependency look
 * transitive: the vulnerable package then got an `overrides` step
 * (`npm pkg set`, which only edits `package.json`) instead of a real
 * `npm install`, so `node_modules`/`package-lock.json` never actually
 * changed and the re-scan still found the same CVE — reproduced against a
 * genuine Trivy scan of a genuine `npm install`, not simulated.
 */
function readNpmDirectDependencies(projectPath: string): Set<string> {
  // Lowercased (fix round 2, item 10): a legacy package can have declared an
  // uppercase name in `package.json` before npm enforced lowercase package
  // names, and every comparison against this set (`runNpmOutdated`'s own
  // pass 1 and pass 2) must agree on case or a direct dependency can be
  // misread as transitive purely from a casing mismatch.
  const out = new Set<string>();
  try {
    const raw = readFileSync(join(projectPath, 'package.json'), 'utf8');
    const pkg = JSON.parse(raw) as Record<string, unknown>;
    for (const field of ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies']) {
      const deps = pkg[field];
      if (deps && typeof deps === 'object') {
        for (const name of Object.keys(deps as Record<string, unknown>)) out.add(name.toLowerCase());
      }
    }
  } catch {
    /* unreadable/unparseable — returns empty, and the call site treats an
     * empty set as "cannot tell", defaulting to a real npm install rather
     * than guessing transitive (see runNpmOutdated's own comment on why). */
  }
  return out;
}

/**
 * Every package name this npm install's own graph ACTUALLY resolves —
 * direct or transitive — read from `package-lock.json` (lockfile v2/v3's
 * `packages` map, keyed `node_modules/<name>` — possibly nested,
 * `node_modules/a/node_modules/b`; v1's recursive `dependencies` map), or
 * `node_modules/` itself when no lockfile is present. Returns a
 * `Map<lowercased, real-cased>` rather than a plain `Set` (fix round 3,
 * "cheap" item): `overrides[<name>]` must use the LOCKFILE's own spelling,
 * never a CVE scanner's own recorded casing — `npm pkg set
 * overrides[MiniMist]=...` for a package the lockfile spells `minimist`
 * creates an override for a name that does not exist, doing nothing.
 *
 * **Why this exists**: `cves` (`Map<string, CveInfo>`) has NO ecosystem
 * column — a `django` (pip) or `laravel/framework` (composer) CVE sits in
 * the exact same table as an npm one. Fix round 1's pass 2 swept that WHOLE
 * table unconditionally, so on a polyglot repo it minted `npm pkg set
 * overrides[django]=...` for a package npm has never heard of (fix round 2,
 * item 10 — NEW BREAKAGE the coordinator's own probe reproduced). Pass 2
 * only creates an npm step for a package this function actually resolves.
 */
function readNpmResolvedPackageNames(projectPath: string): Map<string, string> {
  const out = new Map<string, string>();
  const add = (name: string): void => {
    if (!out.has(name.toLowerCase())) out.set(name.toLowerCase(), name);
  };
  try {
    const raw = readFileSync(join(projectPath, 'package-lock.json'), 'utf8');
    const lock = JSON.parse(raw) as Record<string, unknown>;
    const packages = lock['packages'];
    if (packages && typeof packages === 'object') {
      for (const key of Object.keys(packages as Record<string, unknown>)) {
        const m = /node_modules\/(@[^/]+\/[^/]+|[^/]+)$/.exec(key);
        if (m?.[1]) add(m[1]);
      }
    }
    const deps = lock['dependencies'];
    if (deps && typeof deps === 'object') collectLockV1Deps(deps as Record<string, unknown>, add);
  } catch {
    /* no/unreadable package-lock.json — fall through to node_modules below */
  }
  if (out.size === 0) {
    try {
      for (const name of listNodeModulesPackages(join(projectPath, 'node_modules'))) add(name);
    } catch {
      /* no node_modules either — returns whatever the lockfile branch found
       * (possibly empty), which the caller treats as "resolves nothing". */
    }
  }
  return out;
}

function collectLockV1Deps(deps: Record<string, unknown>, add: (name: string) => void): void {
  for (const [name, val] of Object.entries(deps)) {
    add(name);
    if (val && typeof val === 'object') {
      const nested = (val as Record<string, unknown>)['dependencies'];
      if (nested && typeof nested === 'object') collectLockV1Deps(nested as Record<string, unknown>, add);
    }
  }
}

/**
 * Every package name `node_modules/` itself resolves — the fallback when no
 * `package-lock.json` exists. Walks pnpm's own flat `.pnpm/<encoded>/
 * node_modules/<realName>` store in addition to the ordinary top-level
 * entries (fix round 3, item #7's pnpm case): pnpm's TOP-LEVEL
 * `node_modules/<name>` entries are SYMLINKS into `.pnpm/`, and
 * `Dirent.isDirectory()` reflects the symlink itself (always `false`), not
 * its target — a plain `entry.isDirectory()` check silently skips every
 * pnpm dependency, direct or transitive, which is how the coordinator's own
 * probe found a pnpm-resolved transitive `minimist` reported nowhere at
 * all. The `.pnpm` store lists every installed package — direct AND
 * transitive — as its own real (non-symlink) directory one level down, so
 * reading it directly sidesteps the symlink issue entirely rather than
 * trying to resolve each link.
 */
function listNodeModulesPackages(nodeModulesDir: string): string[] {
  const out: string[] = [];
  const addScoped = (dir: string, scopeName: string): void => {
    try {
      for (const scoped of readdirSync(join(dir, scopeName))) {
        if (safeIsDirectory(join(dir, scopeName, scoped))) out.push(`${scopeName}/${scoped}`);
      }
    } catch {
      /* unreadable scope dir — skip it */
    }
  };
  let entries: string[] = [];
  try {
    entries = readdirSync(nodeModulesDir);
  } catch {
    return out;
  }
  for (const name of entries) {
    if (name === '.pnpm') {
      try {
        for (const storeEntry of readdirSync(join(nodeModulesDir, '.pnpm'))) {
          const innerNm = join(nodeModulesDir, '.pnpm', storeEntry, 'node_modules');
          try {
            for (const pkgName of readdirSync(innerNm)) {
              if (!safeIsDirectory(join(innerNm, pkgName))) continue;
              if (pkgName.startsWith('@')) addScoped(innerNm, pkgName);
              else out.push(pkgName);
            }
          } catch {
            /* unreadable inner node_modules — skip this store entry */
          }
        }
      } catch {
        /* .pnpm listed but unreadable — skip it */
      }
      continue;
    }
    if (!safeIsDirectory(join(nodeModulesDir, name))) continue; // follows a pnpm top-level symlink too — see module comment
    if (name.startsWith('@')) {
      addScoped(nodeModulesDir, name);
      continue;
    }
    if (name.startsWith('.')) continue;
    out.push(name);
  }
  return out;
}

/** `statSync`-based directory check that FOLLOWS symlinks (unlike
 *  `Dirent.isDirectory()`, which reflects the dirent itself) — needed for
 *  pnpm's own top-level `node_modules/<name>` entries, each a symlink into
 *  `.pnpm/`. */
function safeIsDirectory(p: string): boolean {
  try {
    return statSync(p).isDirectory();
  } catch {
    return false;
  }
}

function buildOverrideStep(input: {
  package_name: string;
  installed_version: string;
  latest_version: string;
  cve: CveInfo;
}): UpgradeStep {
  return {
    package_name: input.package_name,
    installed_version: input.installed_version,
    latest_version: input.latest_version,
    ecosystem: 'npm',
    classification: 'security',
    reason: `Active CVE (${input.cve.cveIds.join(', ')}) on a transitive dependency — pinned via npm overrides`,
    cve_ids: input.cve.cveIds,
    // Bracket notation (`overrides[name]`), never `overrides.name`: `npm pkg
    // set` interprets a DOT in a dotted key path as a nested-object
    // separator, so a package name that itself contains a dot (a real one:
    // `socket.io-parser`) would silently become `{overrides: {socket:
    // {"io-parser": ...}}}` instead of the flat key the real package name
    // is. Bracket notation is npm's own documented way to set a literal key
    // regardless of what characters it contains, and works identically for
    // names without a dot too — so it is used unconditionally, not only
    // when a dot is detected.
    //
    // UNQUOTED (fix round 3, item N1 — reverting fix round 2's own single
    // quotes): `create_fix_pr`'s `fixpr/apply.ts` splits `upgrade_command`
    // on whitespace and runs it WITHOUT a shell, so a quoted token is not a
    // shell-quoting hint to it — it is literal characters `npm pkg set`
    // receives as part of the argument. Quoting it broke `create_fix_pr`
    // silently: `applied: true` was still reported, but `package.json` grew
    // `"'overrides": {"minimist": "1.2.6'"}` — the literal quote marks
    // baked into the key and value. `shell_command` carries the
    // shell-quoted form instead, for a human pasting this into a terminal.
    upgrade_command: `npm pkg set overrides[${input.package_name}]=${input.latest_version}`,
    shell_command: `npm pkg set 'overrides[${input.package_name}]=${input.latest_version}'`,
    // `npm pkg set` only rewrites package.json — the lockfile/node_modules
    // do not reflect the override until a plain reinstall re-resolves them.
    follow_up_command: 'npm install --ignore-scripts',
  };
}

/**
 * pip branch (item 4). Previously this ran `pip list --outdated` /
 * (nominally) `pip install -U` — both against whatever Python interpreter
 * happens to be on the MCP host's own PATH, which is never this project's
 * environment and, for `pip install -U`, would upgrade the HOST's global
 * site-packages. Neither the host's installed-package list nor a live
 * registry query is used any more: this reads the project's OWN
 * `requirements*.txt` pins (`pkg==version`, the only specifier exact enough
 * to know an "installed" version without inspecting an environment) and
 * proposes a step only for a pin with an active CVE and a known SAFE fixed
 * version (never a downgrade — `minCleanVersionAbove`, same guard as the
 * npm branch, fix round 1 item 1).
 *
 * `upgrade_command` is deliberately NOT a real `pip`/`sed` invocation: there
 * is no cross-platform, shell-free, whitespace-only-tokenised command that
 * edits one line of a text file (`fixpr/apply.ts`'s own `toArgv` requires
 * exactly that — see its module comment). It names the file and the pin
 * change in a fixed, human-readable shape instead; a literal attempt to
 * execute it fails closed (unknown binary) rather than touching anything.
 * The AUTHORITATIVE target file is the structured `file` field on the step
 * (fix round 1, item 9) — a path can contain spaces, which the
 * whitespace-tokenised `upgrade_command` string cannot represent. Task 11
 * matches on the structured fields (`package_name`, `ecosystem`, `file`,
 * `installed_version`, `latest_version`, `cve_ids`) to perform the actual
 * edit, not on this string.
 *
 * **Every requirement mention with an active CVE that could not become a
 * step is reported in `unplanned`** (fix round 1, item 7) — a non-exact
 * specifier (`>=`, `~=`, …: no single installed version to compare
 * against), an unpinned bare name, or an exact pin whose CVE has no safe
 * fix version above it — never silently dropped.
 */
async function runPipPlan(
  projectPath: string,
  cves: Map<string, CveInfo>,
): Promise<EcosystemPlan> {
  const steps: UpgradeStep[] = [];
  const unplanned: UnplannedEntry[] = [];
  const handled = new Set<string>(); // lowercased names an actual manifest mentioned

  const considerMention = (file: string, mention: RequirementMention): void => {
    handled.add(mention.name.toLowerCase());
    const cve = cves.get(mention.name.toLowerCase());
    if (!cve) return; // no active CVE — nothing to plan or report
    if (mention.version === undefined) {
      unplanned.push({
        package_name: mention.name,
        ecosystem: 'pip',
        cve_ids: cve.cveIds,
        reason: mention.unplannableReason ?? 'could not determine a pinned version',
      });
      return;
    }
    const step = buildPipSecurityStep({ file, pin: { name: mention.name, version: mention.version }, cves });
    if (step) {
      steps.push(step);
    } else {
      unplanned.push({
        package_name: mention.name,
        ecosystem: 'pip',
        cve_ids: cve.cveIds,
        reason: `active CVE (${cve.cveIds.join(', ')}), but no fix version above the pinned ${mention.version} is known`,
      });
    }
  };

  for (const file of findPipRequirementsFiles(projectPath)) {
    for (const mention of parsePinnedRequirements(file.content)) considerMention(file.relPath, mention);
  }
  for (const mention of parsePyprojectPins(projectPath)) considerMention('pyproject.toml', mention);

  // Fix round 3, item #7: there is deliberately NO pass 2 here any more. The
  // fix round 2 shape swept the WHOLE `cves` map for anything npm's own
  // lockfile did not resolve and labelled every one of them `pip` ("likely
  // transitive") — but "not npm" does not mean "pip": the coordinator's own
  // probe showed a composer `laravel/framework` and a Go
  // `golang.org/x/net` both mislabelled `pip` by this exact sweep in a repo
  // that has pip present alongside them. `ecosystem: 'pip'` is now used ONLY
  // for a package this function's own parsing actually found a manifest
  // line for (`handled`, above) — every other CVE'd package, including a
  // genuinely transitive pip dependency this file never mentions by name,
  // falls through to `appendCatchAllUnplanned`'s generic `'unknown'` entry
  // in the top-level handler, which is the honest attribution: this
  // function has no evidence it is pip at all, only that it is not
  // something ELSE this project's runners could place either.
  return { steps, unplanned };
}

interface PinnedRequirement {
  name: string;
  version: string;
}

/** One package name found in a requirements file or pyproject.toml, whether
 *  or not it was an exact pin. `version` is set only for an exact `==` pin;
 *  otherwise `unplannableReason` says why no version could be determined —
 *  see `parsePinnedRequirements`'s own comment. */
interface RequirementMention {
  name: string;
  version?: string;
  unplannableReason?: string;
}

function buildPipSecurityStep(opts: {
  file: string;
  pin: PinnedRequirement;
  cves: Map<string, CveInfo>;
}): UpgradeStep | null {
  const cve = opts.cves.get(opts.pin.name.toLowerCase());
  if (!cve) return null;
  const target = minCleanVersionAbove(opts.pin.version, [cve.fixedVersion]);
  if (!target) return null;
  return {
    package_name: opts.pin.name,
    installed_version: opts.pin.version,
    latest_version: target,
    ecosystem: 'pip',
    classification: 'security',
    reason: `Active CVE (${cve.cveIds.join(', ')}) on the pinned version`,
    cve_ids: cve.cveIds,
    file: opts.file,
    upgrade_command: `pip-pin ${opts.file} ${opts.pin.name}==${target}`,
  };
}

/** `requirements*.txt` at the project root, plus one level into a
 *  `requirements/` directory — same shallow scope `deps_audit.ts`'s own
 *  pip-audit wiring uses (not shared code: that module belongs to a
 *  different tool). */
function findPipRequirementsFiles(projectPath: string): Array<{ relPath: string; content: string }> {
  const out: Array<{ relPath: string; content: string }> = [];
  const tryRead = (relPath: string): void => {
    try {
      out.push({ relPath, content: readFileSync(join(projectPath, relPath), 'utf8') });
    } catch {
      /* unreadable — skip */
    }
  };
  let rootEntries: string[] = [];
  try {
    rootEntries = readdirSync(projectPath);
  } catch {
    return out;
  }
  for (const name of rootEntries) {
    if (/^requirements.*\.txt$/i.test(name)) tryRead(name);
  }
  const reqDir = join(projectPath, 'requirements');
  if (existsSync(reqDir)) {
    try {
      for (const name of readdirSync(reqDir)) {
        if (name.toLowerCase().endsWith('.txt')) tryRead(join('requirements', name));
      }
    } catch {
      /* best-effort */
    }
  }
  return out;
}

/**
 * Every package MENTION in a requirements file — exact `==` pins (returned
 * with `version` set, the only specifier precise enough to name a single
 * "installed" version without inspecting an environment) AND range/unpinned
 * mentions (returned with `unplannableReason` set instead, so an active CVE
 * on one is reported in `unplanned` rather than silently dropped — fix
 * round 1, item 7).
 *
 * Handles the shapes a real `requirements.txt` uses beyond a bare
 * `pkg==1.2.3`:
 *   - pip-compile's hash-pinned, line-continued form
 *     (`django==4.2.0 \` followed by `    --hash=sha256:...` lines) — a
 *     trailing backslash joins the logical line, and `--hash=...` tokens
 *     are stripped before parsing;
 *   - extras (`celery[redis]==5.3.0`) — the `[redis]` marker is stripped;
 *     the package identity for CVE matching is `celery`, not the bracketed
 *     form;
 *   - environment markers (`pkg==1.0.0; python_version >= "3.8"`) — the
 *     marker (after `;`) is dropped, the pin itself is still read.
 */
function parsePinnedRequirements(content: string): RequirementMention[] {
  const out: RequirementMention[] = [];
  for (const rawLine of joinContinuedLines(content)) {
    let line = rawLine.split('#')[0]?.trim() ?? '';
    if (!line || line.startsWith('-')) continue; // -r other.txt, --index-url, etc.
    line = line.replace(/\s+--hash=\S+/g, '').trim(); // pip-compile hash annotations
    const semi = line.indexOf(';');
    if (semi >= 0) line = line.slice(0, semi).trim(); // environment marker
    if (!line) continue;
    const mention = parseOneRequirementSpec(line);
    if (mention) out.push(mention);
  }
  return out;
}

/**
 * Parses ONE already-isolated requirement specifier — no comments, no
 * `--hash=...` annotations, no line continuation: the caller (a
 * requirements-file line, or one element of a pyproject
 * `dependencies = [...]` array) already stripped those. Shared so both
 * shapes get the SAME extras/exact/range/bare handling rather than two
 * copies that can drift (fix round 2, item 7).
 *
 * The environment marker (everything from a top-level `;` onward,
 * `pkg==1.0.0; python_version >= "3.8"`) IS stripped here, internally (fix
 * round 3, "cheap" item) — `parsePinnedRequirements` already stripped it
 * before this function existed as a shared helper, but a pyproject array
 * element (`"urllib3==1.26.0; python_version >= '3.8'"`) went straight from
 * `parsePyprojectPins` to this function with no such preprocessing, so the
 * marker's trailing text made every one of the regexes below fail to match
 * at all — the whole mention silently vanished, not even reported
 * `unplanned`. Doing it here, once, means BOTH callers get it whether or
 * not they remembered to strip it themselves.
 *
 * Returns an exact `==` pin with `version` set, a non-exact specifier or
 * bare name with `unplannableReason` set (fix round 1, item 7 — never
 * silently dropped), or `null` when the text is not a package mention at
 * all (a VCS URL, a local path, `-e .`, …).
 */
function parseOneRequirementSpec(specRaw: string): RequirementMention | null {
  const semi = specRaw.indexOf(';');
  const spec = (semi >= 0 ? specRaw.slice(0, semi) : specRaw).trim();
  if (!spec) return null;

  // Extras: `celery[redis]==5.3.0` -> name `celery`, rest `==5.3.0`.
  const extras = /^([A-Za-z0-9._-]+)\[[^\]]*\](.*)$/.exec(spec);
  const target = extras ? `${extras[1]}${extras[2]}` : spec;

  const exact = /^([A-Za-z0-9._-]+)\s*==\s*([A-Za-z0-9._-]+)$/.exec(target);
  if (exact) {
    const [, name, version] = exact;
    if (name && version) return { name, version };
    return null;
  }
  const range = /^([A-Za-z0-9._-]+)\s*(>=|<=|~=|!=|===|<|>)/.exec(target);
  if (range?.[1] && range[2]) {
    return {
      name: range[1],
      unplannableReason: `non-exact specifier (${range[2]}) — cannot determine a safe target without inspecting the installed environment`,
    };
  }
  const bare = /^[A-Za-z0-9._-]+$/.exec(target);
  if (bare) {
    return { name: target, unplannableReason: 'no version specifier — cannot determine an installed version' };
  }
  // Anything else (a VCS URL, a local path, `-e .`, …) is not a package
  // mention this module can reason about at all — silently skipped, same
  // as before.
  return null;
}

/** Joins a pip-compile-style backslash line continuation
 *  (`django==4.2.0 \` followed by `    --hash=sha256:...`) into one logical
 *  line, so `parsePinnedRequirements` sees the whole pin on one line. */
function joinContinuedLines(content: string): string[] {
  const out: string[] = [];
  let buffer = '';
  for (const line of content.split(/\r?\n/)) {
    const continued = /\\\s*$/.test(line);
    buffer += continued ? line.replace(/\\\s*$/, ' ') : line;
    if (continued) continue;
    out.push(buffer);
    buffer = '';
  }
  if (buffer) out.push(buffer);
  return out;
}

/**
 * PEP 621 `[project] dependencies = ["pkg==1.2.3", "pkg[extra]>=1.0", …]` —
 * a regex scan, the same simplicity `licenseCompatibility.ts#detectProjectLicense`
 * already uses for this same file rather than adding a TOML parser
 * dependency for one array. Poetry's own `[tool.poetry.dependencies]` table
 * (`pkg = "1.2.3"`) is a different, non-PEP-621 shape and is out of scope
 * here.
 *
 * Scoped to the `[project]` TABLE specifically, not the whole file (fix
 * round 3, "cheap" item): `dependencies\s*=\s*\[` as a bare substring search
 * also matches INSIDE `dev-dependencies = [...]` — "dev-dependencies" ends
 * in "dependencies" — so a `[tool.uv] dev-dependencies = [...]` array
 * placed earlier in the file than `[project] dependencies = [...]` won the
 * old unscoped search outright, and the REAL PEP 621 dependency list was
 * never read at all. `extractProjectTableText` isolates the `[project]`
 * table's own text (from its header to the next `[section]` header or EOF)
 * first; `extractDependenciesArray` then searches only within that slice.
 *
 * Every element goes through `parseOneRequirementSpec` (fix round 2, item
 * 7): a range specifier (`django>=4.2`) and an extras pin
 * (`celery[redis]==5.3.0`) are now returned as proper `RequirementMention`s
 * — an exact pin with `version` set, or an unplannable one with a reason —
 * instead of the old exact-`==`-only regex silently dropping everything
 * else.
 */
function parsePyprojectPins(projectPath: string): RequirementMention[] {
  const out: RequirementMention[] = [];
  let raw: string;
  try {
    raw = readFileSync(join(projectPath, 'pyproject.toml'), 'utf8');
  } catch {
    return out;
  }
  const projectTable = extractProjectTableText(raw);
  if (projectTable === null) return out; // no [project] table at all — nothing PEP 621 defines to read
  const block = extractDependenciesArray(projectTable);
  if (block === null) return out;
  const entryPattern = /["']([^"']*)["']/g;
  let m: RegExpExecArray | null;
  while ((m = entryPattern.exec(block)) !== null) {
    const mention = parseOneRequirementSpec(m[1] ?? '');
    if (mention) out.push(mention);
  }
  return out;
}

/** The raw text of the `[project]` TOML table only — from its own header
 *  line to the next top-level `[...]` header (any table, including
 *  `[project.urls]` — TOML does not nest a table's OWN content under a
 *  dotted child header) or EOF. `null` when no bare `[project]` header
 *  exists at all. Matches only a header that is EXACTLY `[project]` on its
 *  own line — `[tool.project]` or `[project.optional-dependencies]` do not
 *  count as the table itself. */
function extractProjectTableText(raw: string): string | null {
  const header = /^[ \t]*\[project\][ \t]*$/m.exec(raw);
  if (!header) return null;
  const start = header.index + header[0].length;
  const rest = raw.slice(start);
  const nextHeader = /^[ \t]*\[/m.exec(rest);
  return nextHeader ? rest.slice(0, nextHeader.index) : rest;
}

/**
 * The raw text INSIDE `dependencies = [ ... ]`, depth-counting brackets
 * rather than matching up to the first `]` (fix round 2, item 7): the fix
 * round 1 regex `dependencies\s*=\s*\[([^\]]*)\]` stopped at the FIRST `]`
 * it saw, which an extras marker introduces well before the array's own
 * closing bracket — `["django>=4.2", "celery[redis]==5.3.0", "urllib3"]`
 * was truncated to `"django>=4.2", "celery[redis` (matching the
 * coordinator's own probe: `celery[redis]==5.3.0` and anything after it
 * silently vanished). Returns `null` when no `dependencies = [` is found,
 * or the array never closes (malformed TOML — nothing to parse either way).
 */
function extractDependenciesArray(raw: string): string | null {
  const startMatch = /dependencies\s*=\s*\[/i.exec(raw);
  if (!startMatch) return null;
  const start = startMatch.index + startMatch[0].length;
  let depth = 1;
  let i = start;
  for (; i < raw.length && depth > 0; i += 1) {
    const ch = raw[i];
    if (ch === '[') depth += 1;
    else if (ch === ']') depth -= 1;
  }
  if (depth !== 0) return null; // never closed — malformed, bail out rather than guess
  return raw.slice(start, i - 1);
}

async function runComposerOutdated(
  projectPath: string,
  cves: Map<string, CveInfo>,
): Promise<UpgradeStep[]> {
  const result = await execa('composer', ['outdated', '--format=json'], {
    cwd: projectPath,
    reject: false,
    timeout: 90_000,
  });
  if (result.exitCode !== 0 || result.stdout.trim().length === 0) return [];
  let parsed: unknown;
  try {
    parsed = JSON.parse(result.stdout);
  } catch {
    return [];
  }
  const installed = (parsed as { installed?: unknown[] })?.installed;
  if (!Array.isArray(installed)) return [];
  const out: UpgradeStep[] = [];
  for (const row of installed) {
    const name =
      row && typeof row === 'object' && 'name' in row && typeof row['name'] === 'string'
        ? (row['name'] as string)
        : '';
    const version =
      row && typeof row === 'object' && 'version' in row && typeof row['version'] === 'string'
        ? (row['version'] as string)
        : '';
    const latest =
      row && typeof row === 'object' && 'latest' in row && typeof row['latest'] === 'string'
        ? (row['latest'] as string)
        : '';
    if (!name || !version || !latest || version === latest) continue;
    out.push(
      buildStep({
        package_name: name,
        installed_version: version,
        latest_version: latest,
        ecosystem: 'composer',
        cves,
        upgrade_command: `composer require ${name}:^${latest}`,
      }),
    );
  }
  return out;
}

async function runCargoOutdated(
  projectPath: string,
  cves: Map<string, CveInfo>,
): Promise<UpgradeStep[]> {
  // Requires `cargo install cargo-outdated`.
  const result = await execa('cargo', ['outdated', '--format', 'json'], {
    cwd: projectPath,
    reject: false,
    timeout: 90_000,
  });
  if (result.exitCode !== 0 || result.stdout.trim().length === 0) return [];
  let parsed: unknown;
  try {
    parsed = JSON.parse(result.stdout);
  } catch {
    return [];
  }
  const dependencies = (parsed as { dependencies?: unknown[] })?.dependencies;
  if (!Array.isArray(dependencies)) return [];
  const out: UpgradeStep[] = [];
  for (const row of dependencies) {
    if (!row || typeof row !== 'object') continue;
    const r = row as Record<string, unknown>;
    const name = typeof r['name'] === 'string' ? (r['name'] as string) : '';
    const project = typeof r['project'] === 'string' ? (r['project'] as string) : '';
    const latest = typeof r['latest'] === 'string' ? (r['latest'] as string) : '';
    if (!name || !project || !latest || project === latest) continue;
    out.push(
      buildStep({
        package_name: name,
        installed_version: project,
        latest_version: latest,
        ecosystem: 'cargo',
        cves,
        upgrade_command: `cargo update -p ${name} --precise ${latest}`,
      }),
    );
  }
  return out;
}

async function runGoOutdated(
  projectPath: string,
  cves: Map<string, CveInfo>,
): Promise<UpgradeStep[]> {
  // `go list -m -u -json all` emits one JSON object per line.
  const result = await execa('go', ['list', '-m', '-u', '-json', 'all'], {
    cwd: projectPath,
    reject: false,
    timeout: 90_000,
  });
  if (result.exitCode !== 0) return [];
  const out: UpgradeStep[] = [];
  // Go emits a stream of JSON objects, not a JSON array. Concatenate and
  // split by `}\n{` boundaries.
  const lines = result.stdout.split(/(?<=\})\s*(?=\{)/);
  for (const chunk of lines) {
    let mod: { Path?: string; Version?: string; Update?: { Version?: string } } | null;
    try {
      mod = JSON.parse(chunk) as typeof mod;
    } catch {
      continue;
    }
    if (!mod) continue;
    if (!mod.Update || !mod.Path || !mod.Version) continue;
    const name = mod.Path;
    const installed = mod.Version;
    const latest = mod.Update.Version ?? '';
    if (!latest || installed === latest) continue;
    out.push(
      buildStep({
        package_name: name,
        installed_version: installed,
        latest_version: latest,
        ecosystem: 'go',
        cves,
        upgrade_command: `go get ${name}@${latest}`,
      }),
    );
  }
  return out;
}

async function runBundlerOutdated(
  projectPath: string,
  cves: Map<string, CveInfo>,
): Promise<UpgradeStep[]> {
  // `bundle outdated --parseable` emits machine-friendly lines:
  // gem-name (newest 1.2.3, installed 1.2.0)
  const result = await execa('bundle', ['outdated', '--parseable'], {
    cwd: projectPath,
    reject: false,
    timeout: 90_000,
  });
  // `bundle outdated` exits non-zero when anything is outdated.
  const text = result.stdout || '';
  if (text.trim().length === 0) return [];
  const out: UpgradeStep[] = [];
  for (const line of text.split(/\r?\n/)) {
    const m = /^(\S+) \(newest ([^,]+), installed ([^,)]+)/.exec(line);
    if (!m) continue;
    const name = m[1] ?? '';
    const latest = m[2] ?? '';
    const installed = m[3] ?? '';
    if (!name || !installed || !latest || installed === latest) continue;
    out.push(
      buildStep({
        package_name: name,
        installed_version: installed,
        latest_version: latest,
        ecosystem: 'rubygems',
        cves,
        upgrade_command: `bundle update ${name}`,
      }),
    );
  }
  return out;
}

const DOTNET_SKIP_DIRS = new Set(['bin', 'obj', 'node_modules', '.git', '.guardian', 'packages', '.vs']);

/** True when ANY `packages.lock.json` exists anywhere under `projectPath`
 *  (bounded recursive walk, same skip-dirs shape `depsAudit.ts`'s own
 *  dotnet SCA uses — not shared code, that module belongs to a different
 *  tool). Checking only `projectPath` itself (the fix round 1 shape) missed
 *  every lock file that sits next to an individual `.csproj` in a
 *  subdirectory — the common case for anything beyond a single-project repo
 *  (fix round 2, item 8, the `depsUpdatePlan.ts` half). */
function anyPackagesLockJsonExists(projectPath: string): boolean {
  const maxDepth = 4;
  function walk(dir: string, depth: number): boolean {
    if (depth > maxDepth) return false;
    let entries: string[];
    try {
      entries = readdirSync(dir);
    } catch {
      return false;
    }
    if (entries.includes('packages.lock.json')) return true;
    for (const name of entries) {
      if (DOTNET_SKIP_DIRS.has(name)) continue;
      const abs = join(dir, name);
      let isDir: boolean;
      try {
        isDir = statSync(abs).isDirectory();
      } catch {
        continue;
      }
      if (isDir && walk(abs, depth + 1)) return true;
    }
    return false;
  }
  return walk(projectPath, 0);
}

/** Same field-level check as `depsAudit.ts`'s `hasStaleTopLevelMismatch`
 *  (not shared code — see this file's own convention, e.g.
 *  `findPipRequirementsFiles`'s comment): a top-level package whose
 *  `requestedVersion` does not match its own `resolvedVersion` means the
 *  listing was built from a STALE `obj/`, even though the command exited 0
 *  with valid-looking JSON (fix round 3, item #8). */
function hasStaleTopLevelMismatch(raw: string): boolean {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return false;
  }
  const projects = (parsed as { projects?: unknown })?.projects;
  if (!Array.isArray(projects)) return false;
  for (const proj of projects) {
    const frameworks = (proj as { frameworks?: unknown })?.frameworks;
    if (!Array.isArray(frameworks)) continue;
    for (const fw of frameworks) {
      const topLevel = (fw as { topLevelPackages?: unknown })?.topLevelPackages;
      if (!Array.isArray(topLevel)) continue;
      for (const pkg of topLevel) {
        if (!pkg || typeof pkg !== 'object') continue;
        const p = pkg as Record<string, unknown>;
        const requested = typeof p['requestedVersion'] === 'string' ? p['requestedVersion'] : undefined;
        const resolved = typeof p['resolvedVersion'] === 'string' ? p['resolvedVersion'] : undefined;
        if (requested !== undefined && resolved !== undefined && requested !== resolved) return true;
      }
    }
  }
  return false;
}

/**
 * **ALWAYS restores explicitly first** (fix round 3, item #8 — the fix
 * round 1/2 "try `dotnet list` directly, restore only on failure" shape is
 * gone). Measured directly: `dotnet list --no-restore` on a STALE `obj/`
 * (restored once, the `.csproj` edited since — a routine, not an edge,
 * case) exits 0 with valid-looking JSON built from the OLD, pre-drift
 * resolution — no failure for "restore only on failure" to ever catch.
 * `dotnet restore --locked-mode` runs first whenever ANY
 * `packages.lock.json` exists under the project (fix round 2, item 8's own
 * `anyPackagesLockJsonExists`), a plain `dotnet restore` otherwise (writes
 * `obj/` only); a failed restore returns an empty plan (this ecosystem has
 * no dedicated `unplanned` channel of its own — the top-level
 * `appendCatchAllUnplanned` sweep is what keeps a CVE'd package from
 * vanishing silently when this returns nothing). Only once restore has
 * genuinely succeeded does `dotnet list --outdated --no-restore` run at
 * all. `hasStaleTopLevelMismatch` is a second check even after a
 * successful restore — a `requestedVersion` != `resolvedVersion` mismatch
 * means something still drifted, and is treated the same as a failure
 * rather than trusted.
 */
async function runDotnetOutdated(
  projectPath: string,
  cves: Map<string, CveInfo>,
): Promise<UpgradeStep[]> {
  const restoreArgs = ['restore', '--nologo', '--verbosity', 'quiet'];
  if (anyPackagesLockJsonExists(projectPath)) restoreArgs.push('--locked-mode');
  const restore = await execa('dotnet', restoreArgs, { cwd: projectPath, reject: false, timeout: 5 * 60_000 });
  if (restore.exitCode !== 0) return []; // private feed not configured, lock out of sync (never rewritten), etc. — skip the branch

  const listArgs = ['list', 'package', '--outdated', '--format', 'json', '--no-restore'];
  const r = await execa('dotnet', listArgs, {
    cwd: projectPath,
    reject: false,
    timeout: 90_000,
  });

  // `--format json` is available on .NET 8+; on older SDKs we fall back to
  // parsing the human-readable text output (less precise but functional).
  if (r.exitCode === 0 && r.stdout.trim().startsWith('{')) {
    if (hasStaleTopLevelMismatch(r.stdout)) return []; // requested != resolved despite a fresh restore — do not trust it
    return parseDotnetJson(r.stdout, cves);
  }

  const fallback = await execa(
    'dotnet',
    ['list', 'package', '--outdated', '--no-restore'],
    { cwd: projectPath, reject: false, timeout: 90_000 },
  );
  if (fallback.exitCode !== 0 || fallback.stdout.trim().length === 0) return [];
  return parseDotnetText(fallback.stdout, cves);
}

function parseDotnetJson(raw: string, cves: Map<string, CveInfo>): UpgradeStep[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return [];
  }
  const projects =
    (parsed as { projects?: Array<{ frameworks?: Array<{ topLevelPackages?: unknown[] }> }> })
      ?.projects;
  if (!Array.isArray(projects)) return [];
  const out: UpgradeStep[] = [];
  for (const proj of projects) {
    for (const fw of proj.frameworks ?? []) {
      for (const pkg of fw.topLevelPackages ?? []) {
        if (!pkg || typeof pkg !== 'object') continue;
        const p = pkg as Record<string, unknown>;
        const name = typeof p['id'] === 'string' ? (p['id'] as string) : '';
        const installed =
          typeof p['resolvedVersion'] === 'string' ? (p['resolvedVersion'] as string) : '';
        const latest =
          typeof p['latestVersion'] === 'string' ? (p['latestVersion'] as string) : '';
        if (!name || !installed || !latest || installed === latest) continue;
        out.push(
          buildStep({
            package_name: name,
            installed_version: installed,
            latest_version: latest,
            ecosystem: 'dotnet',
            cves,
            upgrade_command: `dotnet add package ${name} --version ${latest}`,
          }),
        );
      }
    }
  }
  return out;
}

function parseDotnetText(text: string, cves: Map<string, CveInfo>): UpgradeStep[] {
  // Lines look like:
  //   > Microsoft.AspNetCore.App   2.1.0    2.1.0    3.1.0
  // (package, requested, resolved, latest). We skip header lines.
  const out: UpgradeStep[] = [];
  for (const lineRaw of text.split(/\r?\n/)) {
    const line = lineRaw.trim();
    if (!line.startsWith('>')) continue;
    const parts = line.replace(/^>\s*/, '').split(/\s+/);
    if (parts.length < 4) continue;
    const [name, _requested, resolved, latest] = parts;
    if (!name || !resolved || !latest || resolved === latest) continue;
    out.push(
      buildStep({
        package_name: name,
        installed_version: resolved,
        latest_version: latest,
        ecosystem: 'dotnet',
        cves,
        upgrade_command: `dotnet add package ${name} --version ${latest}`,
      }),
    );
  }
  return out;
}

// ---------------------------------------------------------------------- classification

interface BuildStepInput {
  package_name: string;
  installed_version: string;
  latest_version: string;
  ecosystem: UpgradeStep['ecosystem'];
  cves: Map<string, CveInfo>;
  upgrade_command: string;
}

function buildStep(input: BuildStepInput): UpgradeStep {
  const semverKind = semverDiffKind(input.installed_version, input.latest_version);
  const cve = input.cves.get(input.package_name.toLowerCase());
  const classification: Classification = cve ? 'security' : (semverKind ?? 'major');
  const step: UpgradeStep = {
    package_name: input.package_name,
    installed_version: input.installed_version,
    latest_version: input.latest_version,
    ecosystem: input.ecosystem,
    classification,
    upgrade_command: input.upgrade_command,
  };
  if (cve) {
    step.reason = `Active CVE (${cve.cveIds.join(', ')}) on installed version`;
    step.cve_ids = cve.cveIds;
  }
  return step;
}

function semverDiffKind(installed: string, latest: string): 'patch' | 'minor' | 'major' | null {
  const a = /^v?(\d+)\.(\d+)\.(\d+)/.exec(installed);
  const b = /^v?(\d+)\.(\d+)\.(\d+)/.exec(latest);
  if (!a || !b) return null;
  if (a[1] !== b[1]) return 'major';
  if (a[2] !== b[2]) return 'minor';
  if (a[3] !== b[3]) return 'patch';
  return null;
}

// ---------------------------------------------------------------------- ordering

function orderPlan(plan: UpgradeStep[], prefer: Classification): UpgradeStep[] {
  const order: Record<Classification, number> = {
    security: 0,
    patch: 1,
    minor: 2,
    major: 3,
  };
  // Move `prefer` to rank 0 if it isn't security already.
  if (prefer !== 'security') order[prefer] = -1;
  return [...plan].sort(
    (a, b) =>
      order[a.classification] - order[b.classification] ||
      a.package_name.localeCompare(b.package_name),
  );
}

function summarize(plan: UpgradeStep[]): Summary {
  const by_classification: Record<Classification, number> = {
    security: 0,
    patch: 0,
    minor: 0,
    major: 0,
  };
  for (const s of plan) by_classification[s.classification] += 1;
  return {
    total: plan.length,
    by_classification,
    has_security_updates: by_classification.security > 0,
  };
}

// ---------------------------------------------------------------------- domain error

function failDomain(
  code: DomainError['code'],
  message: string,
): ToolResult<Record<string, unknown>> {
  return { ok: false, error: { code, message } };
}
