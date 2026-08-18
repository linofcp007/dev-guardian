/**
 * `sbom_diff` — compare two SBOM scan rows by their persisted `meta`
 * (which `generate_sbom` populates with components_count + top_packages).
 *
 * We compare on package name+version. Output buckets:
 *   - added:     present in `to`, not in `from`
 *   - removed:   present in `from`, not in `to`
 *   - changed:   same name, different version
 *   - unchanged: same name and version
 */

import { existsSync, readFileSync } from 'node:fs';
import { z } from 'zod';
import type { PluginContext } from '../context.js';
import type { DomainError, ToolResult } from '../types.js';
import { registerToolModule, type ToolModule } from './index.js';

const inputSchema = {
  from_scan_id: z.string().uuid().optional(),
  to_scan_id: z.string().uuid().optional(),
  /** When set, prefer reading the SBOM JSON file from disk for a deeper diff. */
  use_full_file: z.boolean().optional(),
};

const tool: ToolModule = {
  name: 'sbom_diff',
  title: 'SBOM diff (added / removed / changed components)',
  description:
    'Compare two generate_sbom scans. By default uses the persisted top_packages summary; pass ' +
    'use_full_file=true for a full-file comparison (reads the SBOM JSON from .guardian/reports/). ' +
    'Default to/from: latest sbom and the one before it.',
  inputSchema,
  handler: async (input, ctx) => handler(input, ctx),
};

registerToolModule(tool);

interface Component {
  name: string;
  version?: string;
}

async function handler(
  input: Record<string, unknown>,
  ctx: PluginContext,
): Promise<ToolResult<Record<string, unknown>>> {
  const inp = input as {
    from_scan_id?: string;
    to_scan_id?: string;
    use_full_file?: boolean;
  };

  const sboms = ctx.storage.scans
    .listHistory(50)
    .filter((s) => s.scan_type === 'sbom' && s.status === 'completed');
  if (sboms.length < 2 && (!inp.from_scan_id || !inp.to_scan_id)) {
    return failDomain(
      'unknown_scan_id',
      `Need at least two completed SBOM scans (found ${sboms.length}). Call generate_sbom twice or pass explicit ids.`,
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

  const fromComps = await loadComponents(ctx, fromId, inp.use_full_file === true);
  const toComps = await loadComponents(ctx, toId, inp.use_full_file === true);
  if (!fromComps || !toComps) {
    return failDomain('unknown_scan_id', 'One or both SBOM scans have no components recorded.');
  }

  const fromMap = new Map(fromComps.map((c) => [c.name, c.version ?? '']));
  const toMap = new Map(toComps.map((c) => [c.name, c.version ?? '']));

  const added: Component[] = [];
  const removed: Component[] = [];
  const changed: Array<{ name: string; from_version: string; to_version: string }> = [];
  const unchanged: Component[] = [];

  for (const [name, version] of toMap) {
    if (!fromMap.has(name)) {
      added.push({ name, version });
    } else if (fromMap.get(name) !== version) {
      changed.push({
        name,
        from_version: fromMap.get(name) ?? '',
        to_version: version,
      });
    } else {
      unchanged.push({ name, version });
    }
  }
  for (const [name, version] of fromMap) {
    if (!toMap.has(name)) removed.push({ name, version });
  }

  return {
    ok: true,
    from_scan_id: fromId,
    to_scan_id: toId,
    summary: {
      added: added.length,
      removed: removed.length,
      changed: changed.length,
      unchanged: unchanged.length,
    },
    added,
    removed,
    changed,
  };
}

async function loadComponents(
  ctx: PluginContext,
  scanId: string,
  useFullFile: boolean,
): Promise<Component[] | null> {
  const rec = ctx.storage.scans.getById(scanId);
  if (!rec) return null;
  if (useFullFile) {
    const filePath = (rec.meta as { file_path?: string } | undefined)?.file_path;
    if (filePath && existsSync(filePath)) {
      try {
        const raw = readFileSync(filePath, 'utf8');
        return extractFromSbomJson(raw);
      } catch {
        /* fall through to meta */
      }
    }
  }
  const top = (rec.meta as { top_packages?: Component[] } | undefined)?.top_packages;
  return top && top.length > 0 ? top : null;
}

function extractFromSbomJson(raw: string): Component[] {
  let root: unknown;
  try {
    root = JSON.parse(raw);
  } catch {
    return [];
  }
  const cdx = (root as { components?: Array<{ name?: string; version?: string }> })?.components;
  if (Array.isArray(cdx)) {
    // flatMap rather than filter+map: the filter narrowed nothing for the
    // compiler, so the map needed an assertion to re-state what the filter
    // had already checked.
    return cdx.flatMap((c) => {
      if (typeof c?.name !== 'string') return [];
      const out: Component = { name: c.name };
      if (typeof c.version === 'string') out.version = c.version;
      return [out];
    });
  }
  const spdx = (root as { packages?: Array<{ name?: string; versionInfo?: string }> })?.packages;
  if (Array.isArray(spdx)) {
    return spdx.flatMap((p) => {
      if (typeof p?.name !== 'string') return [];
      const out: Component = { name: p.name };
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
