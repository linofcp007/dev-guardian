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
    .describe("Project root. Default: the server's working directory.");
export const SeverityMin = z
    .enum(SEVERITIES)
    .optional()
    .describe('Response floor only; every finding is still recorded (`severity_filter`).');
export const Force = z
    .boolean()
    .optional()
    .default(false)
    .describe('Bypass the tree-hash cache.');
export const AutoFix = z
    .boolean()
    .optional()
    .default(false)
    .describe("Apply Semgrep's autofixes to the source (a clean tree, unless allow_dirty).");
export const AllowDirty = z
    .boolean()
    .optional()
    .default(false)
    .describe('With auto_fix: allow uncommitted changes in the tree.');
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
//# sourceMappingURL=schemas.js.map