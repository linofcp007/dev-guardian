/**
 * Builders for SARIF 2.1.0 logs, and the plumbing the `sarif-import` tests
 * share: calling a tool the way the MCP host does, reading an import's scans
 * back, and writing a log into a project.
 *
 * Each edge case of the feature's test plan builds its own log from these —
 * the synthetic fixtures are code, not files, so a case says what it changes
 * next to the assertion that depends on it.
 */

import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { expect } from 'vitest';
import type { PluginContext } from '../../src/context.js';
import { TOOLS, strictInputSchema, type ToolModule } from '../../src/tools/index.js';
import type { Finding, ScanRecord } from '../../src/types.js';

/** Any JSON value — what a SARIF log is made of. */
export type Json = null | boolean | number | string | Json[] | { [key: string]: Json };
export type JsonObject = { [key: string]: Json };

export interface ResultSpec {
  ruleId?: string;
  ruleIndex?: number;
  /** `result.rule` (a reportingDescriptorReference), e.g. `{ index: 1, toolComponent: { index: 0 } }`. */
  rule?: JsonObject;
  /** `message.text`; `null` leaves `message` out. Default `'finding'`. */
  message?: string | null;
  level?: string;
  kind?: string;
  /** The primary physical location's `artifactLocation.uri`. Omitted with `locations`. */
  uri?: string;
  uriBaseId?: string;
  startLine?: number;
  endLine?: number;
  /** `region.snippet.text`. */
  snippet?: string;
  /** `contextRegion.snippet.text`. */
  contextSnippet?: string;
  /** Replaces the built `locations` entirely (`[]` for none). */
  locations?: Json[];
  partialFingerprints?: Record<string, string>;
  fingerprints?: Record<string, string>;
  suppressions?: JsonObject[];
  properties?: JsonObject;
  taxa?: JsonObject[];
}

/** One SARIF `result`. */
export function sarifResult(spec: ResultSpec = {}): JsonObject {
  const out: JsonObject = {};
  if (spec.ruleId !== undefined) out['ruleId'] = spec.ruleId;
  if (spec.ruleIndex !== undefined) out['ruleIndex'] = spec.ruleIndex;
  if (spec.rule !== undefined) out['rule'] = spec.rule;
  if (spec.kind !== undefined) out['kind'] = spec.kind;
  if (spec.level !== undefined) out['level'] = spec.level;
  if (spec.message !== null) out['message'] = { text: spec.message ?? 'finding' };
  if (spec.locations !== undefined) {
    out['locations'] = spec.locations;
  } else if (spec.uri !== undefined) {
    out['locations'] = [physicalLocation(spec)];
  }
  if (spec.partialFingerprints !== undefined) out['partialFingerprints'] = spec.partialFingerprints;
  if (spec.fingerprints !== undefined) out['fingerprints'] = spec.fingerprints;
  if (spec.suppressions !== undefined) out['suppressions'] = spec.suppressions;
  if (spec.properties !== undefined) out['properties'] = spec.properties;
  if (spec.taxa !== undefined) out['taxa'] = spec.taxa;
  return out;
}

/** A `location` with a physical location built from `spec`'s uri, base, lines and snippets. */
export function physicalLocation(spec: Pick<ResultSpec, 'uri' | 'uriBaseId' | 'startLine' | 'endLine' | 'snippet' | 'contextSnippet'>): JsonObject {
  const artifactLocation: JsonObject = { uri: spec.uri ?? 'src/app.js' };
  if (spec.uriBaseId !== undefined) artifactLocation['uriBaseId'] = spec.uriBaseId;
  const physical: JsonObject = { artifactLocation };
  const region: JsonObject = {};
  if (spec.startLine !== undefined) region['startLine'] = spec.startLine;
  if (spec.endLine !== undefined) region['endLine'] = spec.endLine;
  if (spec.snippet !== undefined) region['snippet'] = { text: spec.snippet };
  if (Object.keys(region).length > 0) physical['region'] = region;
  if (spec.contextSnippet !== undefined) {
    physical['contextRegion'] = { startLine: Math.max(1, (spec.startLine ?? 1) - 1), snippet: { text: spec.contextSnippet } };
  }
  return { physicalLocation: physical };
}

/** One `reportingDescriptor` (a rule). */
export function sarifRule(id: string, extra: JsonObject = {}): JsonObject {
  return { id, shortDescription: { text: `rule ${id}` }, ...extra };
}

export interface RunSpec {
  tool?: string;
  version?: string;
  semanticVersion?: string;
  rules?: JsonObject[];
  /** `tool.extensions` (toolComponents), e.g. CodeQL query packs with their own `rules`. */
  extensions?: JsonObject[];
  results?: JsonObject[];
  originalUriBaseIds?: JsonObject;
  invocations?: JsonObject[];
  /** Any other run-level members (`artifacts`, `taxonomies`, …). */
  extra?: JsonObject;
}

/** One `run`. */
export function sarifRun(spec: RunSpec = {}): JsonObject {
  const driver: JsonObject = { name: spec.tool ?? 'ExternalTool' };
  if (spec.version !== undefined) driver['version'] = spec.version;
  if (spec.semanticVersion !== undefined) driver['semanticVersion'] = spec.semanticVersion;
  if (spec.rules !== undefined) driver['rules'] = spec.rules;
  const tool: JsonObject = { driver };
  if (spec.extensions !== undefined) tool['extensions'] = spec.extensions;
  const run: JsonObject = { tool, results: spec.results ?? [] };
  if (spec.originalUriBaseIds !== undefined) run['originalUriBaseIds'] = spec.originalUriBaseIds;
  if (spec.invocations !== undefined) run['invocations'] = spec.invocations;
  return { ...run, ...(spec.extra ?? {}) };
}

/** A whole log: `version: "2.1.0"` and the given runs. */
export function sarifLog(runs: JsonObject[], extra: JsonObject = {}): JsonObject {
  return { $schema: 'https://json.schemastore.org/sarif-2.1.0.json', version: '2.1.0', runs, ...extra };
}

/** A log as text, the way the importer receives it. */
export function sarifText(log: Json): string {
  return JSON.stringify(log, null, 2);
}

/** Writes `log` (or raw text) to `rel` inside `project`, creating directories; returns the absolute path. */
export function writeSarif(project: string, rel: string, log: Json | string): string {
  const abs = join(project, ...rel.split('/'));
  mkdirSync(dirname(abs), { recursive: true });
  writeFileSync(abs, typeof log === 'string' ? log : sarifText(log));
  return abs;
}

// ---------------------------------------------------------------------------
// Tools, called the way the MCP host calls them.

/** What a tool call came to: its payload, or why not (the strict schema's refusal included). */
export type Outcome =
  | { ok: true; data: Record<string, unknown> }
  | { ok: false; code: string; message: string; rejectedBySchema: boolean };

/** The registered tool `name` — asserted, so a missing tool fails as "`name` registered". */
export function requireTool(name: string): ToolModule {
  const tool = TOOLS.find((t) => t.name === name);
  expect(tool, `${name} registered`).toBeDefined();
  if (tool === undefined) throw new Error(`${name} is not registered`);
  return tool;
}

/**
 * Calls `name` as the MCP host does: the input is validated by the tool's
 * STRICT schema first (`attachAllTools`), so an argument the tool does not
 * take is a refusal (`rejectedBySchema`), never silently dropped.
 */
export async function callTool(name: string, input: Record<string, unknown>, plugin: PluginContext): Promise<Outcome> {
  const tool = requireTool(name);
  const parsed = await strictInputSchema(tool).safeParseAsync(input);
  if (!parsed.success) {
    return { ok: false, code: 'invalid_params', message: parsed.error.message, rejectedBySchema: true };
  }
  const r = await tool.handler(parsed.data, plugin);
  if (!r.ok) return { ok: false, code: r.error.code, message: r.error.message, rejectedBySchema: false };
  const { ok: _ok, ...data } = r;
  return { ok: true, data };
}

/** `outcome`'s payload, asserted to be a success (the refusal is quoted when it is not). */
export function okData<T>(outcome: Outcome): T {
  if (!outcome.ok) {
    throw new Error(`expected a successful tool call, got ${outcome.code}: ${outcome.message}`);
  }
  // The one widening: the payload's shape is the calling test's to assert.
  return outcome.data as unknown as T;
}

/** One run of an `import_sarif` result, as the design's API contract describes it. */
export interface ImportRunOut {
  scan_id: string;
  scan_type: string;
  coverage?: string;
  status?: string;
  meta?: Record<string, unknown>;
  warnings?: string[];
  top_findings?: Finding[];
  findings_count_by_severity?: Record<string, number>;
}

export interface ImportOut {
  runs: ImportRunOut[];
  counts_total: Record<string, unknown>;
}

/** `import_sarif` on `sarifPath`, asserted to succeed. */
export async function importOk(
  plugin: PluginContext,
  project: string,
  sarifPath: string,
  extra: Record<string, unknown> = {},
): Promise<ImportOut> {
  return okData<ImportOut>(await callTool('import_sarif', { project_path: project, sarif_path: sarifPath, ...extra }, plugin));
}

/** The scan row `scanId`, asserted to exist. */
export function scanRow(plugin: PluginContext, scanId: string): ScanRecord {
  const scan = plugin.storage.scans.getById(scanId);
  expect(scan, `scan ${scanId} stored`).not.toBeNull();
  if (scan === null) throw new Error(`scan ${scanId} not stored`);
  return scan;
}

/** `meta.counts` of a `sarif_import` scan. */
export function metaCounts(scan: ScanRecord): Record<string, unknown> {
  const counts = scan.meta?.['counts'];
  expect(counts, `scan ${scan.scan_id} meta.counts`).toBeTypeOf('object');
  return (counts ?? {}) as Record<string, unknown>;
}

/** Every scan of `project`, newest first. */
export function scansOf(plugin: PluginContext, project: string): ScanRecord[] {
  return plugin.storage.scans.listHistoryForProject(project, 10_000);
}

/** Whether `scan` is a SARIF import — compared as a string, since `sarif_import` is not yet a `ScanType`. */
export function isImportScan(scan: Pick<ScanRecord, 'scan_type'>): boolean {
  return String(scan.scan_type) === 'sarif_import';
}

/** The message of a finding wherever the importer put it — `message` or `title`. */
export function messageOf(f: Pick<Finding, 'message' | 'title'>): string[] {
  return [f.message, f.title].filter((s): s is string => typeof s === 'string');
}
