/**
 * zizmor `--format json` (v1) output parser.
 *
 * A flat array of findings (confirmed against zizmorcore/zizmor's own
 * `crates/zizmor/src/output/json/v1.rs` and the worked example in
 * `docs/usage.md`, and against a real fixture, both reproduced in
 * `test/fixtures/scanIac/`):
 *
 *   {
 *     ident, desc, url,
 *     determinations: { confidence, severity, persona },
 *     locations: [ { symbolic: { key, annotation, route, kind: 'Hidden'|'Primary'|'Related', ... },
 *                     concrete: { location: { start_point: {row,column}, end_point, offset_span },
 *                                 feature, comments } } ],
 *     ignored, fixes,
 *   }
 *
 * `ident` -> rule_id, `desc` -> title, `determinations.severity` (one of
 * Informational/Low/Medium/High — no Critical) -> severity via the shared
 * `normalizeSeverity`. `determinations.confidence` has no Finding field of
 * its own, so it rides along in `message` next to the doc URL — dropping it
 * would lose the one signal that tells a probable false positive from a
 * certain one, which `--min-confidence` on the CLI (not used here: it would
 * hide findings from history, the same reason `severity_min` filters only
 * the response — see scanToolFactory.ts) filters at the source, not us.
 *
 * `ignored: true` marks a finding the WORKFLOW's own `# zizmor: ignore[...]`
 * annotation suppressed; zizmor still emits it (so `--persona=auditor` and
 * `--show-ignored`-style tooling can see it) but the repo owner already made
 * this call in their own CI config. Reporting it again as a fresh finding
 * would be `suggest_fix` telling them to undo something they deliberately
 * annotated, so it is dropped here rather than downgraded — same shape as a
 * `nosemgrep` line already being invisible to `scan_sast` before this parser
 * ever runs.
 *
 * `locations[]` almost always holds several entries for one finding — the
 * step, the specific expression, the surrounding block — each tagged
 * `Hidden` / `Primary` / `Related`. The Primary one is what a human reading
 * the workflow would point at; this parser uses it for file/line/snippet and
 * falls back to the first location when none is marked Primary (every real
 * finding observed carries one, but the JSON shape does not guarantee it).
 * `start_point.row` is 0-based per zizmor's own doc note for `--format=json`
 * (unlike `plain` and SARIF); this parser adds 1 for both line_start and
 * line_end, deliberately not using `end_point` — it can land on column 0 of
 * the FOLLOWING line (e.g. a step spanning lines 15-18 reports
 * `end_point.row: 18`), which would overstate the range by one line the way
 * hadolint's and hadolint-alike parsers elsewhere in this codebase avoid by
 * using a single line.
 *
 * A location's file comes from `symbolic.key.Local.verbatim_path` — the
 * path zizmor was invoked with, already project-relative because scan_iac.ts
 * runs it with `cwd: projectPath` and a relative argument. A `Remote` key
 * (an audited `owner/repo` slug rather than a local path) never occurs here:
 * scan_iac only ever hands zizmor a local directory. A location with
 * neither — defensively possible, never observed — is kept with no
 * `file_path` rather than dropped, so the finding itself is not lost.
 */

import type { Finding } from '../../types.js';
import {
  asArray,
  getNumber,
  getProp,
  getString,
  makeFinding,
  normalizeSeverity,
  toRelativeIfPossible,
  parseInputAsJson,
  type ParserContext,
  type ParserOutput,
  type ScannerParser,
} from './index.js';

export const ZIZMOR_TOOL_NAME = 'zizmor';

export const zizmorParser: ScannerParser = {
  name: ZIZMOR_TOOL_NAME,
  parse(input: unknown, ctx: ParserContext = {}): ParserOutput {
    const root = parseInputAsJson(input);
    const findings: Finding[] = [];
    for (const raw of asArray(root)) {
      const finding = mapFinding(raw, ctx);
      if (finding) findings.push(finding);
    }
    return { findings, cves: [] };
  },
};

function mapFinding(raw: unknown, ctx: ParserContext): Finding | null {
  if (getProp(raw, 'ignored') === true) return null;
  const ident = getString(raw, 'ident');
  const desc = getString(raw, 'desc');
  if (!ident || !desc) return null;

  const determinations = getProp(raw, 'determinations');
  const severity = normalizeSeverity(getString(determinations, 'severity'));
  const confidence = getString(determinations, 'confidence');
  const url = getString(raw, 'url');

  const loc = primaryLocation(asArray(getProp(raw, 'locations')));

  const input: Parameters<typeof makeFinding>[0] = {
    tool: ZIZMOR_TOOL_NAME,
    rule_id: ident,
    severity,
    category: 'security',
    subcategory: 'ci',
    title: desc,
    fix_available: false,
  };
  const messageParts: string[] = [];
  if (confidence !== undefined) messageParts.push(`confidence: ${confidence}`);
  if (url !== undefined) messageParts.push(url);
  if (messageParts.length > 0) input.message = `${desc} (${messageParts.join(', ')})`;

  if (loc) {
    const filePath = localVerbatimPath(loc);
    if (filePath !== undefined) input.file_path = toRelativeIfPossible(stripDotSlash(filePath), ctx.project_path);
    const point = getProp(getProp(getProp(loc, 'concrete'), 'location'), 'start_point');
    const row = getNumber(point, 'row');
    if (row !== undefined) {
      const line = row + 1;
      input.line_start = line;
      input.line_end = line;
    }
    const feature = getString(getProp(loc, 'concrete'), 'feature');
    if (feature !== undefined) input.snippet = feature;
  }

  return makeFinding(input);
}

/** The `Primary`-tagged location, or the first when none is tagged so. */
function primaryLocation(locations: unknown[]): unknown | undefined {
  for (const loc of locations) {
    if (getString(getProp(loc, 'symbolic'), 'kind') === 'Primary') return loc;
  }
  return locations[0];
}

/** `symbolic.key.Local.verbatim_path`, or undefined for a `Remote` key. */
function localVerbatimPath(loc: unknown): string | undefined {
  const key = getProp(getProp(loc, 'symbolic'), 'key');
  const local = getProp(key, 'Local');
  return getString(local, 'verbatim_path');
}

function stripDotSlash(p: string): string {
  return p.startsWith('./') ? p.slice(2) : p;
}
