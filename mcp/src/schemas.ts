/**
 * Shared zod primitives for MCP tool input validation.
 *
 * Tools compose their input schemas from these — never inline literals — so
 * that descriptions, defaults, and constraints stay consistent across the
 * surface area.
 */

import { z } from 'zod';
import { SEVERITIES, CATEGORIES, DOMAIN_ERROR_CODES } from './types.js';

export const ProjectPath = z
  .string()
  .min(1)
  .optional()
  .describe('Absolute or relative path to the target project. Defaults to the current working directory.');

export const SeverityMin = z
  .enum(SEVERITIES)
  .optional()
  .describe('Filter findings to this minimum severity or above. Default: include all.');

export const Force = z
  .boolean()
  .optional()
  .default(false)
  .describe('Bypass the tree-hash cache and force a fresh scan.');

export const AutoFix = z
  .boolean()
  .optional()
  .default(false)
  .describe('Apply scanner auto-fixes where supported (Semgrep --autofix, Trivy where applicable).');

export const AllowDirty = z
  .boolean()
  .optional()
  .default(false)
  .describe('Allow auto-fix to run even when the working tree has uncommitted changes.');

export const Categories = z
  .array(z.enum(CATEGORIES))
  .optional()
  .describe('Restrict the run to these categories only.');

export const SeverityEnum = z.enum(SEVERITIES);
export const CategoryEnum = z.enum(CATEGORIES);
export const DomainErrorCodeEnum = z.enum(DOMAIN_ERROR_CODES);

/**
 * Common scan-tool input shape. Individual tools extend this with
 * tool-specific fields (e.g. `dockerfile_path`, `target_url`).
 */
export const BaseScanInput = z.object({
  project_path: ProjectPath,
  severity_min: SeverityMin,
  force: Force,
});

export const BaseScanWithFixInput = BaseScanInput.extend({
  auto_fix: AutoFix,
  allow_dirty: AllowDirty,
});

export type BaseScanInputT = z.infer<typeof BaseScanInput>;
export type BaseScanWithFixInputT = z.infer<typeof BaseScanWithFixInput>;
