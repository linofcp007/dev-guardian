/**
 * SARIF 2.1.0 serializer.
 *
 * Converts canonical `Finding`s into the OASIS SARIF format consumed by CI
 * (GitHub code scanning, GitLab) and IDEs (the SARIF Viewer extensions).
 * This is the interchange format that lets dev-guardian findings show up as
 * inline annotations in a PR or squiggles in an editor without bespoke glue.
 *
 * Pure function: Findings + metadata in, JSON string out. No I/O.
 */

import type { Finding, Severity } from '../types.js';

export interface SarifOptions {
  toolName?: string;
  toolVersion?: string;
  informationUri?: string;
}

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
            version: opts.toolVersion ?? '0.1.0',
            rules: [...rulesById.values()],
          },
        },
        results,
      },
    ],
  };
  return JSON.stringify(sarif, null, 2);
}

function levelFor(sev: Severity): SarifLevel {
  switch (sev) {
    case 'critical':
    case 'high':
      return 'error';
    case 'medium':
      return 'warning';
    case 'low':
    case 'info':
      return 'note';
    default:
      return 'warning';
  }
}

function toUri(p: string): string {
  return p.replace(/\\/g, '/');
}
