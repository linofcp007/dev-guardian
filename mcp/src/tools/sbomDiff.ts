/**
 * `sbom_diff` — compare two SBOM scan rows, full component list, keyed by
 * (ecosystem, name), one VERSION SET per key.
 *
 * `generate_sbom` always writes the complete SBOM document to
 * `.guardian/reports/sbom-<scan>/` (`meta.file_path`) and additionally
 * persists a capped `top_packages` summary (25 entries, document order) for
 * cheap inline display. This tool ALWAYS reads the full file when it is
 * still on disk — never the capped summary — because comparing only the
 * first 25 components in document order silently missed every change
 * outside that slice; `top_packages` is a last-resort fallback for a scan
 * row whose file has since been deleted, not the normal path. `use_full_file`
 * is still accepted for backward compatibility but is now a no-op: the
 * behaviour it used to opt into is the only behaviour there is.
 *
 * Keyed by (ecosystem, name), not name alone: two different ecosystems can
 * legitimately share a package name (an npm `lodash` and an unrelated
 * `lodash` elsewhere), and collapsing them under one name silently merged
 * two different packages' version histories into one diff entry. Ecosystem
 * is read from each component's purl (`pkg:TYPE/...`) — CycloneDX's own
 * `purl` field, SPDX's `externalRefs[].referenceType === 'purl'` — and
 * falls back to `'unknown'` when no purl is present (the `top_packages`
 * fallback path never carries one).
 *
 * **Each key holds a SET of versions, not one** (fix round 1, item 6): a
 * real SBOM can list `lodash@3` AND `lodash@4` at once (nested duplicate
 * installs are routine in `node_modules`) — the brief's own worked example.
 * Keying by (ecosystem, name) alone still collapsed that set down to
 * whichever single `Component` won the `Map` insertion, silently hiding
 * every other version at that key. `added`/`removed` are now computed PER
 * VERSION: a version present on one side and not the other is reported
 * individually. The single common case — exactly one version on each side,
 * and they differ — is still reported as one `changed` entry (the familiar
 * "3.0.0 → 4.0.0" shape) rather than decomposed into a same-key
 * add-plus-remove pair, which would read as two unrelated events for what
 * is obviously one version bump.
 *
 * Output buckets:
 *   - added:     (ecosystem, name, version) present in `to`, not in `from`
 *   - removed:   (ecosystem, name, version) present in `from`, not in `to`
 *   - changed:   a key with EXACTLY one version on each side, and they differ
 *   - unchanged: (ecosystem, name, version) present on both sides (count only)
 *
 * The default pair is the two latest completed SBOM scans OF THIS PROJECT
 * (`project_path`, resolved the same way every other tool resolves it) —
 * previously unscoped across the whole database, so two unrelated projects'
 * SBOMs could be compared by accident whenever neither `from_scan_id` nor
 * `to_scan_id` was given. Explicit ids bypass the project scope entirely (a
 * caller who names both scans exactly is trusted to mean it).
 *
 * **A mixed full-file/capped-summary comparison is refused, not silently
 * run** (fix round 1, item 6): if one scan's SBOM file is still on disk and
 * the other's is not, the fallback side reads EVERY component as ecosystem
 * `'unknown'` (the capped summary never carries a purl) while the full side
 * has real ecosystems — every single component would then key-mismatch and
 * report as a spurious removed+added pair, which is strictly worse than no
 * diff. When BOTH sides fall back (both files gone), the comparison still
 * runs — both are `'unknown'` uniformly, so no artificial mismatch — but
 * `component_source` reports `'capped_summary_fallback'` and
 * `summary_caveat` says the totals are NOT the true, uncapped ones. The
 * response arrays are additionally capped (`RESPONSE_CAP`) on a `full_file`
 * comparison; `summary` there carries the true, uncapped totals, the same
 * "cap the response, never the count" shape `scanToolFactory.ts`'s own
 * `top_findings` uses.
 */

import { existsSync, readFileSync } from 'node:fs';
import { z } from 'zod';
import type { PluginContext } from '../context.js';
import { resolveProjectPath } from '../platform/projectPath.js';
import { ProjectPath } from '../schemas.js';
import type { DomainError, ToolResult } from '../types.js';
import { registerToolModule, type ToolModule } from './index.js';

/** Response arrays are capped here; `summary` counts are never capped on a
 *  `full_file` comparison (see the module comment for the fallback case). */
const RESPONSE_CAP = 50;

const inputSchema = {
  project_path: ProjectPath,
  from_scan_id: z
    .string()
    .uuid()
    .optional()
    .describe("The older generate_sbom scan. Default: this project's second-newest completed SBOM scan."),
  to_scan_id: z
    .string()
    .uuid()
    .optional()
    .describe("The newer generate_sbom scan. Default: this project's newest completed SBOM scan."),
  /** No longer changes behaviour — full-file comparison always happens now
   *  when the SBOM file is still on disk. Kept so an existing caller that
   *  passes it does not break. */
  use_full_file: z
    .boolean()
    .optional()
    .describe(
      'Ignored; kept so existing callers do not break. The full SBOM file is always compared when it is ' +
        'still on disk, and the capped summary stored with the scan only when it is not (component_source says which).',
    ),
};

const tool: ToolModule = {
  name: 'sbom_diff',
  title: 'SBOM diff (added / removed / changed components)',
  description:
    'Compare two generate_sbom scans, full component list, keyed by (ecosystem, name) with a ' +
    'version SET per key so multiple versions of the same package in the same ecosystem are ' +
    'reported per-version, never collapsed. Default to/from: the two latest completed SBOM scans ' +
    'of project_path. Refuses a comparison that would mix a full component list against a capped ' +
    '25-item summary (spurious results); response arrays are capped but summary carries the true, ' +
    'uncapped totals except on the (flagged) both-capped fallback path.',
  inputSchema,
  handler: async (input, ctx) => handler(input, ctx),
};

registerToolModule(tool);

interface Component {
  name: string;
  version?: string;
  ecosystem: string;
}

type ComponentSource = 'full_file' | 'capped_summary_fallback';

interface LoadResult {
  components: Component[];
  source: ComponentSource;
}

async function handler(
  input: Record<string, unknown>,
  ctx: PluginContext,
): Promise<ToolResult<Record<string, unknown>>> {
  const inp = input as {
    project_path?: string;
    from_scan_id?: string;
    to_scan_id?: string;
    use_full_file?: boolean;
  };

  let projectPath: string;
  try {
    projectPath = resolveProjectPath(inp.project_path).path;
  } catch (e) {
    return failDomain('not_a_git_repo', (e as Error).message);
  }

  const needsDefaultPair = !inp.from_scan_id || !inp.to_scan_id;
  const sboms = needsDefaultPair
    ? ctx.storage.scans
        .listHistoryForProject(projectPath, 50)
        .filter((s) => s.scan_type === 'sbom' && s.status === 'completed')
    : [];
  if (needsDefaultPair && sboms.length < 2) {
    return failDomain(
      'unknown_scan_id',
      `Need at least two completed SBOM scans of '${projectPath}' (found ${sboms.length}). ` +
        `Call generate_sbom twice or pass explicit ids.`,
    );
  }

  const toId = inp.to_scan_id ?? sboms[0]?.scan_id;
  const fromId = inp.from_scan_id ?? sboms[1]?.scan_id;
  if (!toId || !fromId) {
    return failDomain('unknown_scan_id', 'Could not resolve both ends of the SBOM diff.');
  }
  if (toId === fromId) {
    return failDomain('unknown_scan_id', `Cannot diff a scan against itself (${toId}).`);
  }

  const fromLoaded = loadComponents(ctx, fromId);
  const toLoaded = loadComponents(ctx, toId);
  if (!fromLoaded || !toLoaded) {
    return failDomain('unknown_scan_id', 'One or both SBOM scans have no components recorded.');
  }
  if (fromLoaded.source !== toLoaded.source) {
    const describe = (s: ComponentSource): string =>
      s === 'full_file' ? 'its full SBOM file' : 'a capped summary (its SBOM file no longer exists on disk)';
    return failDomain(
      'unknown_scan_id',
      `Refusing to compare: '${fromId}' was read from ${describe(fromLoaded.source)}, while '${toId}' ` +
        `was read from ${describe(toLoaded.source)}. Comparing a full component list against a capped, ` +
        `ecosystem-untagged summary would report every component as spuriously removed and re-added. ` +
        `Re-run generate_sbom for whichever scan lost its file, or pass two scan ids whose files are ` +
        `both still on disk.`,
    );
  }
  const source = fromLoaded.source; // same on both sides, per the check above

  const fromGrouped = groupByKey(fromLoaded.components);
  const toGrouped = groupByKey(toLoaded.components);
  const allKeys = new Set([...fromGrouped.keys(), ...toGrouped.keys()]);

  const added: Component[] = [];
  const removed: Component[] = [];
  const changed: Array<{ name: string; ecosystem: string; from_version: string; to_version: string }> = [];
  let unchangedCount = 0;

  for (const key of allKeys) {
    const fromEntry = fromGrouped.get(key);
    const toEntry = toGrouped.get(key);
    const fromVersions = fromEntry?.versions ?? new Set<string>();
    const toVersions = toEntry?.versions ?? new Set<string>();
    const meta = toEntry ?? fromEntry;
    if (!meta) continue; // unreachable — a key only exists because one side has it

    const addedVersions = [...toVersions].filter((v) => !fromVersions.has(v));
    const removedVersions = [...fromVersions].filter((v) => !toVersions.has(v));
    unchangedCount += [...toVersions].filter((v) => fromVersions.has(v)).length;

    if (fromVersions.size === 1 && toVersions.size === 1 && addedVersions.length === 1 && removedVersions.length === 1) {
      changed.push({
        name: meta.name,
        ecosystem: meta.ecosystem,
        from_version: removedVersions[0] ?? '',
        to_version: addedVersions[0] ?? '',
      });
      continue;
    }
    for (const v of addedVersions) added.push({ name: meta.name, ecosystem: meta.ecosystem, ...(v ? { version: v } : {}) });
    for (const v of removedVersions) removed.push({ name: meta.name, ecosystem: meta.ecosystem, ...(v ? { version: v } : {}) });
  }

  const truncated =
    source === 'full_file' &&
    (added.length > RESPONSE_CAP || removed.length > RESPONSE_CAP || changed.length > RESPONSE_CAP);

  return {
    ok: true,
    project_path: projectPath,
    from_scan_id: fromId,
    to_scan_id: toId,
    component_source: source,
    summary_caveat:
      source === 'capped_summary_fallback'
        ? 'Both SBOM files are gone from disk — this diff compares only the capped 25-item ' +
          'top_packages summaries, not the full component lists. Totals below are NOT the true, ' +
          'uncapped component counts, and ecosystem is unknown for every entry.'
        : null,
    summary: {
      added: added.length,
      removed: removed.length,
      changed: changed.length,
      unchanged: unchangedCount,
    },
    added: added.slice(0, RESPONSE_CAP),
    removed: removed.slice(0, RESPONSE_CAP),
    changed: changed.slice(0, RESPONSE_CAP),
    truncated,
  };
}

interface GroupedEntry {
  name: string;
  ecosystem: string;
  versions: Set<string>;
}

/** Groups a flat component list by (ecosystem, name) into a version SET per
 *  key — see the module comment for why a single `Component` per key
 *  silently hid coexisting versions of the same package. A component with
 *  no version at all is recorded as the empty string, its own "version". */
function groupByKey(components: Component[]): Map<string, GroupedEntry> {
  const out = new Map<string, GroupedEntry>();
  for (const c of components) {
    const key = `${c.ecosystem}:${c.name}`;
    let entry = out.get(key);
    if (!entry) {
      entry = { name: c.name, ecosystem: c.ecosystem, versions: new Set() };
      out.set(key, entry);
    }
    entry.versions.add(c.version ?? '');
  }
  return out;
}

/**
 * The full component list for a scan, always from the SBOM file still on
 * disk when it exists (`meta.file_path`) — the capped `top_packages`
 * summary is only a fallback for a scan row whose file has since been
 * removed. The `source` this returns is what `handler` uses to refuse a
 * mixed full-file/fallback comparison (see the module comment).
 */
function loadComponents(ctx: PluginContext, scanId: string): LoadResult | null {
  const rec = ctx.storage.scans.getById(scanId);
  if (!rec) return null;
  const filePath = (rec.meta as { file_path?: string } | undefined)?.file_path;
  if (filePath && existsSync(filePath)) {
    try {
      const raw = readFileSync(filePath, 'utf8');
      return { components: extractFromSbomJson(raw), source: 'full_file' };
    } catch {
      /* fall through to the capped summary */
    }
  }
  const top = (rec.meta as { top_packages?: Array<{ name: string; version?: string }> } | undefined)
    ?.top_packages;
  if (!top || top.length === 0) return null;
  return {
    components: top.map((c) => ({
      name: c.name,
      ...(c.version !== undefined ? { version: c.version } : {}),
      ecosystem: 'unknown',
    })),
    source: 'capped_summary_fallback',
  };
}

/** The ecosystem segment of a purl (`pkg:npm/lodash@4` → `npm`), or
 *  `'unknown'` when no purl is present. */
function ecosystemFromPurl(purl: string | undefined): string {
  if (!purl) return 'unknown';
  const m = /^pkg:([^/]+)\//.exec(purl);
  return m?.[1] ?? 'unknown';
}

function extractFromSbomJson(raw: string): Component[] {
  let root: unknown;
  try {
    root = JSON.parse(raw);
  } catch {
    return [];
  }
  const cdx = (root as { components?: Array<{ name?: string; version?: string; purl?: string }> })
    ?.components;
  if (Array.isArray(cdx)) {
    // flatMap rather than filter+map: the filter narrowed nothing for the
    // compiler, so the map needed an assertion to re-state what the filter
    // had already checked.
    return cdx.flatMap((c) => {
      if (typeof c?.name !== 'string') return [];
      const out: Component = { name: c.name, ecosystem: ecosystemFromPurl(c.purl) };
      if (typeof c.version === 'string') out.version = c.version;
      return [out];
    });
  }
  const spdx = (
    root as {
      packages?: Array<{
        name?: string;
        versionInfo?: string;
        externalRefs?: Array<{ referenceType?: string; referenceLocator?: string }>;
      }>;
    }
  )?.packages;
  if (Array.isArray(spdx)) {
    return spdx.flatMap((p) => {
      if (typeof p?.name !== 'string') return [];
      const purlRef = (p.externalRefs ?? []).find((r) => r.referenceType === 'purl');
      const out: Component = { name: p.name, ecosystem: ecosystemFromPurl(purlRef?.referenceLocator) };
      if (typeof p.versionInfo === 'string') out.version = p.versionInfo;
      return [out];
    });
  }
  return [];
}

function failDomain(
  code: DomainError['code'],
  message: string,
): ToolResult<Record<string, unknown>> {
  return { ok: false, error: { code, message } };
}
