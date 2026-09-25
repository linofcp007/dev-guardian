/**
 * `scan_containers` — Trivy on Dockerfile and/or container images.
 *
 * Strategy:
 *   - If `dockerfile_path` is given (or a `Dockerfile` exists at project
 *     root), run `trivy config --format json --output … <dockerfile>`.
 *   - If `image` is given, run `trivy image --format json --output … <image>`.
 *   - Both can be requested in the same call; outputs land in
 *     `.guardian/reports/containers-<scan>/`.
 *
 * Returns `tools_run` with one entry per scanner pass (dockerfile / image).
 *
 * Both inputs are validated before any scan row is written or any process
 * starts: `image` is handed to trivy as a positional argument, so a value
 * starting with `-` would be parsed as an option and one with whitespace is
 * no image reference at all; `dockerfile_path` must resolve INSIDE the
 * project (symlinks included), because the tool scans the project and
 * nothing else.
 */

import { existsSync, realpathSync } from 'node:fs';
import { isAbsolute, join, relative, resolve, sep } from 'node:path';
import { z } from 'zod';
import { InvalidProjectPathError, resolveProjectPath } from '../platform/projectPath.js';
import { trivyParser } from '../runners/scannerParsers/trivy.js';
import { runProcess } from '../runners/processRunner.js';
import { Force, ProjectPath, SeverityMin } from '../schemas.js';
import type { ToolResult, ToolRun } from '../types.js';
import { registerToolModule, type ToolModule } from './index.js';
import {
  ensureReportDir,
  readJsonSafe,
  scannerAvailable,
} from './scanHelpers.js';
import {
  makeScanTool,
  type ScannerInvocation,
} from './scanToolFactory.js';

/** An image reference: non-empty, no whitespace, not starting with `-`. */
const IMAGE_REF = /^(?!-)\S+$/;

const scanContainers = makeScanTool({
    name: 'scan_containers',
    title: 'Container scan (Dockerfile + image)',
    description:
      'Run Trivy against a Dockerfile (config check) and/or a container image (vulnerability check). ' +
      'If neither dockerfile_path nor image is provided, scans ./Dockerfile when present.',
    scan_type: 'containers',
    category: 'security',
    supportsAutoFix: false,
    inputSchema: {
      project_path: ProjectPath,
      severity_min: SeverityMin,
      dockerfile_path: z
        .string()
        .optional()
        .describe('Path to a Dockerfile to scan with `trivy config`.'),
      image: z
        .string()
        .regex(IMAGE_REF, 'image must be an image reference: no whitespace, not starting with "-"')
        .optional()
        .describe('Container image reference to scan with `trivy image`.'),
      force: Force,
    },
    invoke: async (input, ctx): Promise<ScannerInvocation> => {
      const reportDir = ensureReportDir(ctx.projectPath, ctx.scanId, 'containers');
      const tools_run: ToolRun[] = [];
      const missing_tools: string[] = [];
      const parser_inputs: ScannerInvocation['parser_inputs'] = [];

      const trivyBin = await scannerAvailable('trivy');
      if (!trivyBin) {
        tools_run.push({ name: 'trivy', status: 'skipped', reason: 'not_installed' });
        missing_tools.push('trivy');
        return {
          outcome: 'completed',
          tools_run,
          missing_tools,
          parser_inputs,
          report_paths: [reportDir],
        };
      }

      const inp = input as { dockerfile_path?: string; image?: string };
      // Validated by the handler below before this runs; re-checked here so
      // no other caller of `invoke` can bypass it.
      const invalid = invalidInput(ctx.projectPath, inp);
      if (invalid) throw new Error(invalid);
      const dockerfile =
        inp.dockerfile_path !== undefined
          ? resolve(ctx.projectPath, inp.dockerfile_path)
          : existsSync(join(ctx.projectPath, 'Dockerfile'))
            ? join(ctx.projectPath, 'Dockerfile')
            : undefined;

      let anyOutcome: ScannerInvocation['outcome'] = 'completed';

      if (dockerfile) {
        const outFile = join(reportDir, 'dockerfile.json');
        const result = await runProcess({
          command: 'trivy',
          args: ['config', '--format', 'json', '--output', outFile, '--quiet', dockerfile],
          cwd: ctx.projectPath,
          env: ctx.scriptEnv,
          signal: ctx.signal,
          onLog: ctx.onLog,
        });
        const raw = readJsonSafe(outFile);
        if (raw) parser_inputs.push({ parser: trivyParser, input: raw });
        tools_run.push({
          name: 'trivy-dockerfile',
          status: result.outcome === 'completed' ? 'ok' : 'failed',
        });
        if (result.outcome !== 'completed') anyOutcome = result.outcome;
      }

      if (inp.image) {
        const outFile = join(reportDir, 'image.json');
        const result = await runProcess({
          command: 'trivy',
          args: [
            'image',
            '--format',
            'json',
            '--output',
            outFile,
            '--quiet',
            '--scanners',
            'vuln',
            inp.image,
          ],
          cwd: ctx.projectPath,
          env: ctx.scriptEnv,
          signal: ctx.signal,
          onLog: ctx.onLog,
        });
        const raw = readJsonSafe(outFile);
        if (raw) parser_inputs.push({ parser: trivyParser, input: raw });
        tools_run.push({
          name: 'trivy-image',
          status: result.outcome === 'completed' ? 'ok' : 'failed',
        });
        if (result.outcome !== 'completed') anyOutcome = result.outcome;
      }

      if (tools_run.length === 0) {
        // No Dockerfile, no image — nothing to scan.
        tools_run.push({
          name: 'trivy',
          status: 'skipped',
          reason: 'no_dockerfile_or_image',
        });
      }

      return {
        outcome: anyOutcome,
        tools_run,
        missing_tools,
        parser_inputs,
        report_paths: [reportDir],
      };
    },
  });

/**
 * The scan pipeline, behind the argument checks: a rejected input returns a
 * domain error before the factory writes a scan row or starts a process. The
 * MCP layer already rejects a bad `image` through the schema's pattern; this
 * also covers in-process callers, and `dockerfile_path` needs the project
 * path, which no schema knows.
 */
const tool: ToolModule = {
  ...scanContainers,
  handler: async (input, plugin, callMeta): Promise<ToolResult<Record<string, unknown>>> => {
    const inp = input as { project_path?: string; dockerfile_path?: string; image?: string };
    let projectPath: string | null = null;
    try {
      projectPath = resolveProjectPath(inp.project_path).path;
    } catch (e) {
      // The pipeline reports an invalid project_path itself.
      if (!(e instanceof InvalidProjectPathError)) throw e;
    }
    const invalid = projectPath !== null ? invalidInput(projectPath, inp) : null;
    if (invalid) return { ok: false, error: { code: 'unsupported_target', message: invalid } };
    return scanContainers.handler(input, plugin, callMeta);
  },
};

registerToolModule(tool);

/** Why the input cannot be scanned, or null when it can. */
function invalidInput(
  projectPath: string,
  inp: { dockerfile_path?: string; image?: string },
): string | null {
  if (inp.image !== undefined && !IMAGE_REF.test(inp.image)) {
    return `image ${JSON.stringify(inp.image)} is not an image reference: it must not contain whitespace or start with "-".`;
  }
  if (inp.dockerfile_path !== undefined && !isInside(projectPath, inp.dockerfile_path)) {
    return `dockerfile_path ${JSON.stringify(inp.dockerfile_path)} resolves outside the project (${projectPath}); scan_containers only reads files inside it.`;
  }
  return null;
}

/**
 * Whether `candidate` (relative to `root`, or absolute) names a path inside
 * `root`. Checked lexically, and — when the file exists — again on the real
 * paths, so a symlink inside the project pointing out of it is refused too.
 */
function isInside(root: string, candidate: string): boolean {
  const within = (base: string, target: string): boolean => {
    const rel = relative(base, target);
    return rel !== '' && rel !== '..' && !rel.startsWith(`..${sep}`) && !isAbsolute(rel);
  };
  const abs = resolve(root, candidate);
  if (!within(root, abs)) return false;
  if (!existsSync(abs)) return true;
  try {
    return within(realpathSync.native(root), realpathSync.native(abs));
  } catch {
    return false;
  }
}
