/**
 * Shared zod primitives for MCP tool input validation.
 *
 * Tools compose their input schemas from these — never inline literals — so
 * that descriptions, defaults, and constraints stay consistent across the
 * surface area.
 */

import { z } from 'zod';
import { httpUrl } from './platform/toolArgs.js';
import { SEVERITIES } from './types.js';

export const ProjectPath = z
  .string()
  .min(1)
  .optional()
  .describe("Project root. Default: the server's working directory.");

export const SeverityMin = z
  .enum(SEVERITIES)
  .optional()
  .describe(
    'Response floor only; every finding is still recorded (`severity_filter`).',
  );

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

/**
 * An http or https URL (`platform/toolArgs.ts#httpUrl`): a tool hands the
 * program it runs the RE-SERIALISED URL, never the text. A FACTORY, not one
 * shared instance: the JSON-schema converter emits a reused zod instance as a
 * `$ref` to its first use.
 */
export const httpUrlField = (): z.ZodURL =>
  z.url().refine((text) => httpUrl(text) !== null, { error: 'must be an http:// or https:// URL' });
