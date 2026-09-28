/**
 * `suppress_finding` — mark a finding as a false positive.
 *
 * Pure SQL: inserts a row in `suppressions`. While the row is active
 * (NULL `expires_at`, or `expires_at` in the future), the matching
 * finding is hidden from `findings/open` and `findings/by-severity/*`
 * resources. Historical scan records are untouched.
 *
 * The caller names the finding by fingerprint — the key every scan response
 * shows — but the fingerprint hashes the line numbers, so a suppression that
 * stored only that lapsed the moment a line was inserted above the finding.
 * The row therefore also records the finding's line-independent `identity`,
 * looked up from the newest scan that reported the fingerprint, and hides a
 * finding that matches either.
 *
 * **Suppressions are per project.** One server process can hold scans of
 * several projects in the same storage (each tool resolves its own
 * `project_path`, defaulting to the working directory) — the fingerprint
 * alone does not say which project a caller meant, so this tool now resolves
 * `project_path` too and looks the fingerprint up with
 * `findLatestInProject`, the same project-scoped lookup `suggest_fix`
 * already uses. A fingerprint no COMPLETED scan of THIS project ever
 * reported — because it does not exist anywhere, or because it exists only
 * in another project's history — is `unknown_finding`, not `ok: true`: this
 * used to insert a suppression row for any 64-hex-character string handed
 * to it, silently, and under `unknown_scan_id`, a code that names a
 * completely different failure.
 */

import { z } from 'zod';
import type { PluginContext } from '../context.js';
import { findingCveIds } from '../intel/rank.js';
import { resolveProjectPath } from '../platform/projectPath.js';
import { ProjectPath } from '../schemas.js';
import {
  OPENVEX_JUSTIFICATIONS,
  type DomainError,
  type OpenVexJustification,
  type ToolResult,
  type VexSuppressionStatus,
} from '../types.js';
import { registerToolModule, type ToolModule } from './index.js';

const inputSchema = {
  project_path: ProjectPath,
  finding_fingerprint: z
    .string()
    .regex(/^[0-9a-f]{64}$/)
    .describe('SHA-256 fingerprint of the finding to suppress (from a previous scan response).'),
  reason: z
    .string()
    .min(1)
    .max(1000)
    .describe('Why this finding is being suppressed. Required.'),
  expires_at: z
    .string()
    .datetime()
    .optional()
    .describe('ISO-8601 expiry. When omitted, the suppression never expires.'),
  vex_status: z
    .enum(['not_affected'])
    .optional()
    .describe(
      "Also record a VEX statement: the product is not_affected by the finding's CVE. Requires " +
        'justification; only for a finding that names a CVE. export_vex publishes it.',
    ),
  justification: z
    .enum(OPENVEX_JUSTIFICATIONS)
    .optional()
    .describe('OpenVEX justification for vex_status not_affected. Required with it.'),
  impact_statement: z
    .string()
    .min(1)
    .max(1000)
    .optional()
    .describe('Optional free-text VEX impact statement, with vex_status.'),
};

const tool: ToolModule = {
  name: 'suppress_finding',
  title: 'Suppress finding',
  description:
    "Mark a finding of project_path (default: the server's working directory) — named by the " +
    'fingerprint a scan response shows — as a false positive. Resources that surface open findings ' +
    'exclude it while the suppression is active — including after the code around it moves: the ' +
    "finding's line-independent identity is recorded alongside the fingerprint and either one " +
    'matches. A fingerprint no completed scan of this project ever reported is `unknown_finding`. ' +
    'Pass expires_at for a temporary snooze. For a CVE finding, vex_status: not_affected with an ' +
    'OpenVEX justification (and optional impact_statement) also makes it a VEX statement that ' +
    'export_vex publishes.',
  inputSchema,
  handler: async (input, ctx) => handler(input, ctx),
};

registerToolModule(tool);

async function handler(
  input: Record<string, unknown>,
  ctx: PluginContext,
): Promise<ToolResult<Record<string, unknown>>> {
  const inp = input as {
    project_path?: string;
    finding_fingerprint: string;
    reason: string;
    expires_at?: string;
    vex_status?: VexSuppressionStatus;
    justification?: OpenVexJustification;
    impact_statement?: string;
  };

  if (!inp.finding_fingerprint || !inp.reason) {
    return failDomain(
      'unknown_finding',
      'finding_fingerprint and reason are required.',
    );
  }

  // Checked before anything is looked up or written: a VEX statement that is
  // not valid VEX must never reach the table half-formed.
  const vexProblem = vexArgumentProblem(inp);
  if (vexProblem !== null) return failDomain('unsupported_target', vexProblem);

  let projectPath: string;
  try {
    projectPath = resolveProjectPath(inp.project_path).path;
  } catch (e) {
    return failDomain('not_a_git_repo', (e as Error).message);
  }

  const located = ctx.storage.findings.findLatestInProject(projectPath, inp.finding_fingerprint);
  if (!located) {
    return failDomain(
      'unknown_finding',
      `Finding ${inp.finding_fingerprint} is not in any completed scan of ${projectPath}.`,
    );
  }

  // A VEX statement is about a vulnerability: a finding that names no CVE
  // gives a VEX consumer nothing to match it against.
  const cveIds = findingCveIds(located.finding);
  if (inp.vex_status !== undefined && cveIds.length === 0) {
    return failDomain(
      'unsupported_target',
      `vex_status needs a finding that names a CVE, and ${inp.finding_fingerprint} ` +
        `(${located.finding.tool}${located.finding.rule_id !== undefined ? ` ${located.finding.rule_id}` : ''}) ` +
        'names none. Suppress it without vex_status, or suppress the dependency finding itself.',
    );
  }

  const identity = located.finding.identity;
  const vex =
    inp.vex_status !== undefined && inp.justification !== undefined
      ? {
          status: inp.vex_status,
          justification: inp.justification,
          ...(inp.impact_statement !== undefined ? { impact_statement: inp.impact_statement } : {}),
        }
      : null;
  const id = ctx.storage.suppressions.insert({
    finding_fingerprint: inp.finding_fingerprint,
    ...(identity !== undefined ? { finding_identity: identity } : {}),
    reason: inp.reason,
    ...(inp.expires_at !== undefined ? { expires_at: inp.expires_at } : {}),
    created_by: 'user',
    // Scopes the suppression to THIS project at match time (migration 011) —
    // already resolved above to look the finding up, so no extra lookup.
    project_path: projectPath,
    ...(vex !== null
      ? {
          vex_status: vex.status,
          vex_justification: vex.justification,
          ...(vex.impact_statement !== undefined ? { vex_impact_statement: vex.impact_statement } : {}),
        }
      : {}),
  });

  return {
    ok: true,
    suppression_id: id,
    finding_fingerprint: inp.finding_fingerprint,
    // Null: this project's stored row for this fingerprint has no identity
    // (written before schema 7, or by a tool that computes none), so the
    // suppression matches it by fingerprint only and lapses if lines shift.
    finding_identity: identity ?? null,
    expires_at: inp.expires_at ?? null,
    // Null for an ordinary suppression: it states nothing in VEX terms.
    vex: vex === null ? null : { ...vex, cve_ids: cveIds },
  };
}

/**
 * The VEX arguments go together or not at all: `not_affected` without a
 * justification is not valid VEX (CISA's minimum requirements; OpenVEX
 * recommends the machine-readable label and discourages the free-text
 * impact statement alone, so this tool requires the label), and a
 * justification or impact statement without a status states nothing.
 */
function vexArgumentProblem(inp: {
  vex_status?: string;
  justification?: string;
  impact_statement?: string;
}): string | null {
  if (inp.vex_status !== undefined && inp.justification === undefined) {
    return (
      'vex_status not_affected needs a justification: one of ' + `${OPENVEX_JUSTIFICATIONS.join(', ')}.`
    );
  }
  if (inp.vex_status === undefined && (inp.justification !== undefined || inp.impact_statement !== undefined)) {
    return 'justification and impact_statement describe a VEX statement: pass vex_status: not_affected with them.';
  }
  return null;
}

function failDomain(
  code: DomainError['code'],
  message: string,
): ToolResult<Record<string, unknown>> {
  return { ok: false, error: { code, message } };
}
