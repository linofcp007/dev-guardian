/**
 * SARIF 2.1.0 serializer.
 *
 * Converts canonical `Finding`s into the OASIS SARIF format consumed by CI
 * (GitHub code scanning, GitLab) and IDEs (the SARIF Viewer extensions).
 * This is the interchange format that lets dev-guardian findings show up as
 * inline annotations in a PR or squiggles in an editor without bespoke glue.
 *
 * Pure function: Findings + metadata in, JSON string out. `toSarif` itself
 * performs no I/O and is deterministic in every argument it's given. The one
 * exception is `opts.toolVersion`'s own default, which is resolved from disk
 * ONCE at module load (see `DEFAULT_TOOL_VERSION` below) rather than derived
 * from any argument — fixed for the life of the process, and overridable
 * per call via `opts.toolVersion` for a caller (e.g. a test) that needs to.
 */

import type { Finding, Severity } from '../types.js';
import { resolveVersion } from '../platform/version.js';

export interface SarifOptions {
  toolName?: string;
  /** Defaults to the real plugin/package release version (`platform/version.ts`),
   *  resolved once below — not a hardcoded literal that can drift behind a
   *  release the way this field's absence of any caller previously let it. */
  toolVersion?: string;
  informationUri?: string;
}

// Resolved once per process, at module load — same "read once, reuse many
// times" shape `server.ts` already applies to its own `SERVER_VERSION`, and
// cheaper than re-reading two small JSON files on every `toSarif` call (the
// interactive `report_export`/`scan_skill` tools can call this repeatedly in
// one long-lived MCP server session).
const DEFAULT_TOOL_VERSION = resolveVersion();

interface SarifRule {
  id: string;
  name?: string;
  shortDescription?: { text: string };
  fullDescription?: { text: string };
  defaultConfiguration?: { level: SarifLevel };
}

type SarifLevel = 'error' | 'warning' | 'note' | 'none';

export function toSarif(findings: Finding[], opts: SarifOptions = {}): string {
  const rulesById = new Map<string, SarifRule>();
  for (const f of findings) {
    const id = f.rule_id ?? `${f.tool}/${f.category}`;
    if (!rulesById.has(id)) {
      const rule: SarifRule = { id };
      rule.name = f.subcategory ?? f.category;
      rule.shortDescription = { text: f.title };
      if (f.message) rule.fullDescription = { text: f.message };
      rule.defaultConfiguration = { level: levelFor(f.severity) };
      rulesById.set(id, rule);
    }
  }

  const results = findings.map((f) => {
    const ruleId = f.rule_id ?? `${f.tool}/${f.category}`;
    const result: Record<string, unknown> = {
      ruleId,
      level: levelFor(f.severity),
      message: { text: f.message ? `${f.title} — ${f.message}` : f.title },
      properties: {
        severity: f.severity,
        category: f.category,
        ...(f.subcategory ? { subcategory: f.subcategory } : {}),
        ...(f.fingerprint ? { fingerprint: f.fingerprint } : {}),
      },
    };
    if (f.file_path) {
      const region: Record<string, number> = {};
      if (f.line_start) region.startLine = f.line_start;
      if (f.line_end) region.endLine = f.line_end;
      result.locations = [
        {
          physicalLocation: {
            artifactLocation: { uri: toUri(f.file_path) },
            ...(Object.keys(region).length > 0 ? { region } : {}),
          },
        },
      ];
    }
    if (f.fingerprint) {
      result.partialFingerprints = { devGuardian: f.fingerprint };
    }
    return result;
  });

  const sarif = {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: opts.toolName ?? 'dev-guardian',
            informationUri: opts.informationUri ?? 'https://github.com/linofcp007/dev-guardian',
            version: opts.toolVersion ?? DEFAULT_TOOL_VERSION,
            rules: [...rulesById.values()],
          },
        },
        results,
      },
    ],
  };
  return JSON.stringify(sarif, null, 2);
}

/**
 * Every `Severity` mapped explicitly, as a `Record` rather than a switch
 * with a `default` fallback. A switch's default would let a `Severity`
 * added later compile silently into 'warning' — hiding a critical the same
 * way an unrecognised finding severity would. `Record<Severity, SarifLevel>`
 * makes that a compile-time error instead: TypeScript rejects this object
 * literal itself the day `SEVERITIES` (`../types.ts`) grows a case this file
 * has not been told how to map. Behaviour for today's five severities is
 * unchanged from the switch it replaces.
 */
const SARIF_LEVEL_BY_SEVERITY: Record<Severity, SarifLevel> = {
  critical: 'error',
  high: 'error',
  medium: 'warning',
  low: 'note',
  info: 'note',
};

function levelFor(sev: Severity): SarifLevel {
  return SARIF_LEVEL_BY_SEVERITY[sev];
}

function toUri(p: string): string {
  return p.replace(/\\/g, '/');
}
