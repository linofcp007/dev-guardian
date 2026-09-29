/**
 * `generate_sbom` — produce an SBOM (CycloneDX or SPDX, JSON).
 *
 * Standalone tool (not via the scan-tool factory) because SBOM data is not
 * a Finding stream — it is a structured artefact about installed packages.
 *
 * Source preference:
 *   1. Syft (`anchore/syft`) — emits both CycloneDX and SPDX natively.
 *   2. Trivy fs `--format cyclonedx` / `--format spdx-json` — fallback when
 *      Syft is not installed; Trivy supports both formats too.
 *
 * The full SBOM is always persisted to `.guardian/reports/sbom-<scan>/`.
 * It is also inlined in the response when the file size is ≤ `inline_max_kb`
 * (default {@link DEFAULT_INLINE_KB} KB, at most {@link MAX_INLINE_KB} KB) —
 * bigger SBOMs are referenced by path only so the MCP channel never carries
 * a huge blob. The default was 256 KB and the cap 8 MB, and the document
 * went out TWICE, in the text block and again in `structuredContent`: a
 * 256 KB SBOM cost over half a megabyte of context. It now travels once, in
 * the text block (`contentOnlyKeys`); `inlined` says whether it did.
 */

import { existsSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { z } from 'zod';
import { runProcess } from '../runners/processRunner.js';
import { summarize as summariseSbom } from '../runners/scannerParsers/syft.js';
import { ProjectPath } from '../schemas.js';
import type { DomainError, ToolResult } from '../types.js';
import { resolveProjectPath } from '../platform/projectPath.js';
import { computeTreeHash } from '../treeHash/computeTreeHash.js';
import {
  ensureReportDir,
  scannerAvailable,
} from './scanHelpers.js';
import { registerToolModule, type ToolModule } from './index.js';

type SbomFormat = 'cyclonedx-json' | 'spdx-json';

/** Inline the document by default only up to this many KB. */
export const DEFAULT_INLINE_KB = 64;
/** Never inline more than this many KB (1 MB), whatever the caller asks. */
export const MAX_INLINE_KB = 1024;

const inputSchema = {
  project_path: ProjectPath,
  format: z
    .enum(['cyclonedx-json', 'spdx-json'])
    .optional()
    .describe('SBOM output format. Default: cyclonedx-json.'),
  inline_max_kb: z
    .number()
    .int()
    .min(0)
    .max(MAX_INLINE_KB)
    .optional()
    .describe(
      `Inline the SBOM document in the response when its size is at most this many KB. ` +
        `Default: ${DEFAULT_INLINE_KB}; maximum ${MAX_INLINE_KB} (1 MB). 0 never inlines.`,
    ),
};

const tool: ToolModule = {
  name: 'generate_sbom',
  title: 'Generate SBOM (Syft / Trivy)',
  description:
    'Produce a Software Bill of Materials (CycloneDX or SPDX JSON). Prefers Syft; falls back to ' +
    'Trivy fs --format. The full SBOM is always written to .guardian/reports/sbom-<scan>/ ' +
    '(`file_path`). The response inlines the document once, in its text content, when its size ' +
    `is at most inline_max_kb (default ${DEFAULT_INLINE_KB}, max ${MAX_INLINE_KB}); \`inlined\` ` +
    'says whether it did. Read the file for anything larger.',
  inputSchema,
  handler: async (input, ctx) => handler(input, ctx),
  contentOnlyKeys: ['inline'],
};

registerToolModule(tool);

async function handler(
  input: Record<string, unknown>,
  ctx: import('../context.js').PluginContext,
): Promise<ToolResult<Record<string, unknown>>> {
  const inp = input as {
    project_path?: string;
    format?: SbomFormat;
    inline_max_kb?: number;
  };
  let projectPath: string;
  try {
    projectPath = resolveProjectPath(inp.project_path).path;
  } catch (e) {
    return failDomain('not_a_git_repo', (e as Error).message);
  }

  // The tree the SBOM describes, taken before anything is written: export_vex
  // compares it with the dependency scan's before trusting the SBOM's product.
  const treeHash = await computeTreeHash(projectPath);
  const format: SbomFormat = inp.format ?? 'cyclonedx-json';
  const inlineMaxBytes = Math.min(inp.inline_max_kb ?? DEFAULT_INLINE_KB, MAX_INLINE_KB) * 1024;
  const scanId = randomUUID();
  const reportDir = ensureReportDir(projectPath, scanId, 'sbom');
  const outFile = join(reportDir, `sbom.${format === 'cyclonedx-json' ? 'cdx' : 'spdx'}.json`);

  const syftBin = await scannerAvailable('syft');
  let producedBy: 'syft' | 'trivy' | null = null;

  if (syftBin) {
    const syftFormat = format === 'cyclonedx-json' ? 'cyclonedx-json' : 'spdx-json';
    const result = await runProcess({
      command: 'syft',
      args: [projectPath, '-o', `${syftFormat}=${outFile}`, '--quiet'],
      cwd: projectPath,
    });
    if (result.outcome === 'completed' && existsSync(outFile)) {
      producedBy = 'syft';
    }
  }

  if (!producedBy) {
    const trivyBin = await scannerAvailable('trivy');
    if (trivyBin) {
      const trivyFormat = format === 'cyclonedx-json' ? 'cyclonedx' : 'spdx-json';
      const result = await runProcess({
        command: 'trivy',
        args: ['fs', '--format', trivyFormat, '--output', outFile, '--quiet', projectPath],
        cwd: projectPath,
      });
      if (result.outcome === 'completed' && existsSync(outFile)) {
        producedBy = 'trivy';
      }
    }
  }

  if (!producedBy) {
    return {
      ok: false,
      error: {
        code: 'missing_scanner',
        message:
          'Neither Syft nor Trivy is installed. Install one of them via `install_toolchain` ' +
          'or refer to https://github.com/anchore/syft.',
      },
    };
  }

  const stat = statSync(outFile);
  const raw = readFileSync(outFile, 'utf8');
  const summary = summariseSbom(raw);

  // Persist a scan row so `guardian://sbom` can find the latest output
  // without touching the filesystem.
  ctx.storage.scans.insert({
    scan_id: scanId,
    scan_type: 'sbom',
    project_path: projectPath,
    tree_hash: treeHash,
    report_dir: outFile,
  });
  ctx.storage.scans.finalize({
    scan_id: scanId,
    status: 'completed',
    tools_run: [{ name: producedBy, status: 'ok' }],
    missing_tools: [],
    report_dir: outFile,
    meta: {
      format,
      produced_by: producedBy,
      file_path: outFile,
      size_bytes: stat.size,
      components_count: summary.components_count,
      top_packages: summary.top_packages,
    },
  });

  const payload: Record<string, unknown> = {
    ok: true,
    scan_id: scanId,
    format,
    produced_by: producedBy,
    file_path: outFile,
    size_bytes: stat.size,
    components_count: summary.components_count,
    top_packages: summary.top_packages,
  };
  let inlined = false;
  if (stat.size <= inlineMaxBytes) {
    try {
      payload['inline'] = JSON.parse(raw);
      inlined = true;
    } catch {
      // SBOM file unparseable — keep the path, drop the inline.
    }
  }
  payload['inlined'] = inlined;
  payload['inline_max_kb'] = inlineMaxBytes / 1024;

  return payload as ToolResult<Record<string, unknown>>;
}

function failDomain(
  code: DomainError['code'],
  message: string,
): ToolResult<Record<string, unknown>> {
  return { ok: false, error: { code, message } };
}
