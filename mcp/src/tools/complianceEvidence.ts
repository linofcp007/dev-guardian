/**
 * `compliance_evidence` — assemble a Markdown evidence pack from
 * accumulated state.
 *
 * Strictly read-only. Produces a Markdown string the model can save,
 * attach to a deliverable, or hand to a client/auditor. The framework
 * tag (gdpr / soc2 / iso27001) just shapes the section labels — the data
 * sources are the same DB rows.
 *
 * **The evidence is ONE project's** (`project_path`, default: the server's
 * working directory — Task 24): its newest usable compliance, dependency
 * and SBOM scans, its own active baseline, and the suppressions that apply
 * to it (its own and the legacy ones scoped to no project). It used to take
 * each from the 50 newest scans of the whole database, the newest baseline
 * of any project and every active suppression — an evidence pack handed to
 * an auditor that could describe a different project than the one it named.
 *
 * `owasp-top10-2025` and `nist-csf-2.0` are evidenced per category from the
 * project's OPEN SET (`history/openSet.ts`): its open findings, and the
 * bookkeeping of the scans behind them. An OWASP category is evidenced only
 * when it was `tested` — for every source language of the project, a
 * scanner that ran fully ok has enough rules for it (`frameworks/coverage.ts`);
 * a `partial` one is listed apart, never among the evidenced. A CSF 2.0
 * category is evidenced only through an OWASP category that was tested, via
 * dev-guardian's own OWASP → CSF mapping (`frameworks/nistCsf2.ts`,
 * labelled as ours in the document), and partial when it is reached only
 * through partial ones. CSF categories no code scan can speak for are
 * listed as not covered, never left out.
 */

import { z } from 'zod';
import type { PluginContext } from '../context.js';
import { coverageRunsOf, owaspCoverage, type OwaspCategoryCoverage, type OwaspCoverage } from '../frameworks/coverage.js';
import { CSF_CATEGORIES, owaspForCsfCategory } from '../frameworks/nistCsf2.js';
import { findLatestUsable, openSetForProject } from '../history/openSet.js';
import { languagesOfRunsAsync, resolveProjectLanguagesAsync } from '../frameworks/projectLanguages.js';
import { COVERAGE_RULE, languagesLine, testedByText, unmappedSentence, untestedHint } from '../report/owaspCoverage.js';
import { resolveProjectPath } from '../platform/projectPath.js';
import { ProjectPath } from '../schemas.js';
import { CVE_SOURCE_SCAN_TYPES, type Finding, type ScanRecord, type ToolResult } from '../types.js';
import { registerToolModule, type ToolModule } from './index.js';

const FRAMEWORKS = ['gdpr', 'soc2', 'iso27001', 'owasp-top10-2025', 'nist-csf-2.0', 'generic'] as const;
type Framework = (typeof FRAMEWORKS)[number];
type LabelledFramework = Exclude<Framework, 'generic'>;

const inputSchema = {
  project_path: ProjectPath,
  framework: z
    .enum(FRAMEWORKS)
    .optional()
    .describe(
      'Which framework to label the evidence under. owasp-top10-2025 and nist-csf-2.0 give per-category ' +
        'evidence from the open findings and the scanners that ran. Default: generic.',
    ),
};

const tool: ToolModule = {
  name: 'compliance_evidence',
  title: 'Compliance evidence pack (Markdown)',
  description:
    "Generate a Markdown evidence document from one project's accumulated state (project_path, " +
    "default: the server's working directory): latest compliance scan, license summary, CVE " +
    'counts, baseline status, suppressions, policy docs found. Tag with a framework ' +
    '(gdpr/soc2/iso27001/generic) to shape the section labels, or owasp-top10-2025 / nist-csf-2.0 for ' +
    'per-category evidence: a category counts as covered only when, for every source language of the ' +
    'project, a scanner that ran ok has enough rules for it; partial categories are listed apart ' +
    '(NIST CSF via dev-guardian\'s own OWASP mapping). Read-only.',
  inputSchema,
  handler: async (input, ctx) => handler(input, ctx),
};

registerToolModule(tool);

async function handler(
  input: Record<string, unknown>,
  ctx: PluginContext,
): Promise<ToolResult<Record<string, unknown>>> {
  const inp = input as { project_path?: string; framework?: Framework };
  const framework = inp.framework ?? 'generic';
  let projectPath: string;
  try {
    projectPath = resolveProjectPath(inp.project_path).path;
  } catch (e) {
    return { ok: false, error: { code: 'not_a_git_repo', message: (e as Error).message } };
  }

  const storage = ctx.storage;
  // Policy documents and licenses are read from files, not scanner output,
  // so a compliance run's scanner coverage does not disqualify it (risk_score
  // reads it the same way).
  const compliance = findLatestUsable(storage, projectPath, ['compliance'], { skipCoverageNone: false }).scan;
  // The newest scan that actually measured dependencies — a security_full
  // row judged on its Trivy half — the same CVE source risk_score uses.
  const deps = findLatestUsable(storage, projectPath, CVE_SOURCE_SCAN_TYPES, { slot: 'deps' }).scan;
  const sbom = findLatestUsable(storage, projectPath, ['sbom']).scan;
  const baseline = storage.baselines.getActiveForProject(projectPath);
  // Every suppression that hides a finding of THIS project: its own, and
  // the ones scoped to no project (NULL — rows written before migration
  // 011), exactly the rule `history/openSet.ts#suppressionMatcher` applies.
  const suppressions = storage.suppressions
    .listActive()
    .filter((s) => s.project_path === undefined || s.project_path === projectPath);
  // Per-category frameworks read the open set: open findings (suppressions
  // applied) and the bookkeeping of every scan behind them.
  let owasp: OwaspEvidence | null = null;
  if (framework === 'owasp-top10-2025' || framework === 'nist-csf-2.0') {
    const open = openSetForProject(storage, projectPath);
    const runs = coverageRunsOf(open.bookkeeping, open.scans);
    owasp = {
      coverage: owaspCoverage(
        runs,
        open.findings,
        await languagesOfRunsAsync(runs, () => resolveProjectLanguagesAsync(storage.stack, projectPath)),
      ),
      findings: open.findings,
    };
  }

  const md = build({
    framework,
    project_path: projectPath,
    generated_at: new Date().toISOString(),
    compliance,
    deps,
    sbom,
    baseline,
    suppressionsCount: suppressions.length,
    owasp,
    ctx,
  });

  return {
    ok: true,
    project_path: projectPath,
    framework,
    markdown: md,
    size_bytes: Buffer.byteLength(md, 'utf8'),
    instructions_for_model:
      'Save this to docs/compliance/<framework>-evidence.md or hand to the auditor directly. ' +
      'Sections without underlying scans are flagged as "(no data — run X)".',
  };
}

interface BuildArgs {
  framework: Framework;
  project_path: string;
  generated_at: string;
  compliance: ScanRecord | null;
  deps: ScanRecord | null;
  sbom: ScanRecord | null;
  baseline: ReturnType<NonNullable<PluginContext['storage']['baselines']['getActiveForProject']>>;
  suppressionsCount: number;
  /** Set for the per-category frameworks: OWASP 2025 coverage of the open set. */
  owasp: OwaspEvidence | null;
  ctx: PluginContext;
}

interface OwaspEvidence {
  coverage: OwaspCoverage;
  /** The open findings the coverage counted — CSF counts need them to count each finding once. */
  findings: ReadonlyArray<Pick<Finding, 'owasp'>>;
}

interface ComplianceScanMeta {
  licenses_summary?: Array<{ license: string; risk: string }>;
  risky_licenses?: Array<{ license: string }>;
  policy_documents_found?: Record<string, boolean | string[]>;
}

function complianceMeta(compliance: BuildArgs['compliance']): ComplianceScanMeta | undefined {
  return compliance?.meta as ComplianceScanMeta | undefined;
}

const FRAMEWORK_LABEL: Record<LabelledFramework, string> = {
  gdpr: 'GDPR',
  soc2: 'SOC 2',
  iso27001: 'ISO 27001',
  'owasp-top10-2025': 'OWASP Top 10:2025',
  'nist-csf-2.0': 'NIST CSF 2.0',
};

interface ControlMapping {
  /** The article/criterion/control id, e.g. "Article 25". */
  id: string;
  /** What the control is about, e.g. "privacy by design". */
  description: string;
  /** Whether a scan in THIS document actually backs the claim. */
  evidenced: boolean;
  /**
   * Backed only in part (the per-category frameworks): listed on its own,
   * never among the evidenced. Set only with `evidenced: false`.
   */
  partial?: true;
  /** Evidenced: where to find it above. Not evidenced: what was never run. */
  note: string;
}

/**
 * What each framework's mapping used to claim unconditionally, now gated on
 * whether a scan present in THIS document actually backs it. GDPR Article 5
 * (data minimisation) is not in this list at all: "SBOM components and
 * license posture" was never evidence of minimising personal data collected
 * — a wrong mapping, not an uncovered one, so it is dropped rather than
 * listed as missing. "Scan cadence" and "dep update plan" are dropped for
 * the same reason: neither is tracked by any scan this tool reads, so
 * claiming they were covered — or even naming them as a gap to fill — would
 * promise evidence this tool has no way to produce.
 */
function frameworkControls(
  framework: LabelledFramework,
  args: Pick<BuildArgs, 'compliance' | 'deps' | 'baseline' | 'sbom' | 'owasp'>,
): ControlMapping[] {
  const meta = complianceMeta(args.compliance);
  const hasPolicyDocs = meta?.policy_documents_found !== undefined;
  const hasLicenses = meta?.licenses_summary !== undefined;
  const hasDeps = args.deps !== null;
  const hasBaseline = args.baseline !== null;
  const hasSbom = args.sbom !== null;

  switch (framework) {
    case 'gdpr':
      return [
        {
          id: 'Article 25',
          description: 'privacy by design and by default',
          evidenced: hasPolicyDocs,
          note: hasPolicyDocs
            ? 'privacy and security policy presence — see "Latest compliance scan" above'
            : 'no `compliance_check` scan on file — policy-document presence was never checked',
        },
        {
          id: 'Article 32',
          description: 'security of processing',
          evidenced: hasDeps,
          note: hasDeps
            ? 'dependency CVE posture — see "Dependency vulnerability posture" above'
            : 'no `scan_deps`/`deps_audit` scan on file — vulnerability posture was never measured',
        },
      ];
    case 'soc2':
      return [
        {
          id: 'CC7.1 / CC7.2',
          description: 'vulnerability management',
          evidenced: hasDeps,
          note: hasDeps
            ? 'CVE counts — see "Dependency vulnerability posture" above'
            : 'no `scan_deps`/`deps_audit` scan on file — vulnerability posture was never measured',
        },
        {
          id: 'CC8.1',
          description: 'change management',
          evidenced: hasBaseline,
          note: hasBaseline
            ? 'baseline + suppressions traceability — see "Change-tracking / baseline" above'
            : 'no baseline set — run `set_baseline`',
        },
        {
          id: 'CC9.1',
          description: 'risk mitigation',
          evidenced: hasLicenses,
          note: hasLicenses
            ? 'license posture — see "Latest compliance scan" above'
            : 'no `compliance_check` scan on file — license posture was never measured',
        },
      ];
    case 'owasp-top10-2025':
      return owaspControls(args.owasp);
    case 'nist-csf-2.0':
      return csfControls(args.owasp);
    case 'iso27001':
      return [
        {
          id: 'A.8.8',
          description: 'management of technical vulnerabilities',
          evidenced: hasDeps,
          note: hasDeps
            ? 'CVE counts — see "Dependency vulnerability posture" above'
            : 'no `scan_deps`/`deps_audit` scan on file — vulnerability posture was never measured',
        },
        {
          id: 'A.5.20',
          description: 'supplier relationships',
          evidenced: hasSbom,
          note: hasSbom
            ? 'SBOM — see "Software Bill of Materials (SBOM)" above'
            : 'no SBOM on file — run `generate_sbom`',
        },
        {
          id: 'A.5.32',
          description: 'intellectual property',
          evidenced: hasLicenses,
          note: hasLicenses
            ? 'license compatibility findings — see "Latest compliance scan" above'
            : 'no `compliance_check` scan on file — license posture was never measured',
        },
      ];
  }
}

function openFindings(n: number): string {
  return `${n} open finding${n === 1 ? '' : 's'}`;
}

/** One control per OWASP 2025 category: evidenced only when a capable scanner ran ok. */
function owaspControls(evidence: OwaspEvidence | null): ControlMapping[] {
  if (evidence === null) return [];
  const owasp = evidence;
  return owasp.coverage.categories.map((c) => {
    const found = openFindings(c.findings);
    if (c.status === 'not_tested') {
      return {
        id: c.id,
        description: c.title,
        evidenced: false,
        note:
          `no scanner able to detect it ran ok in the scans behind this document — ${untestedHint(c, owasp.coverage)}` +
          (c.findings > 0 ? ` (${found} from other scanners)` : ''),
      };
    }
    const tested = `tested by ${testedByScans(c)}`;
    if (c.status === 'partial') {
      return {
        id: c.id,
        description: c.title,
        evidenced: false,
        partial: true,
        note: `PARTIAL — ${tested}, but ${c.reasons.join('; ')}; ${found}`,
      };
    }
    return { id: c.id, description: c.title, evidenced: true, note: `${tested}; ${found}` };
  });
}

/** `semgrep (sast, scan 1a2b3c4d)`, once per tool and scan. */
function testedByScans(c: OwaspCategoryCoverage): string {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const e of c.tested_by) {
    const text = `${e.tool} (${e.scan_type}, scan ${e.scan_id.slice(0, 8)})`;
    if (!seen.has(text)) {
      seen.add(text);
      out.push(text);
    }
  }
  return out.length > 0 ? out.join(', ') : testedByText(c.tested_by);
}

/**
 * One control per CSF 2.0 category (all 22), evidenced through the OWASP
 * categories dev-guardian's own mapping files under it — only those that
 * were tested. A category the mapping does not reach is a process no code
 * scan can evidence, and says so.
 */
function csfControls(owasp: OwaspEvidence | null): ControlMapping[] {
  if (owasp === null) return [];
  const byId = new Map(owasp.coverage.categories.map((c) => [c.id, c]));
  return CSF_CATEGORIES.map((csf) => {
    const mapped = owaspForCsfCategory(csf.id);
    if (mapped.length === 0) {
      return {
        id: csf.id,
        description: csf.title,
        evidenced: false,
        note: 'an organisational outcome no code scan evidences — not assessable by dev-guardian',
      };
    }
    const statusOf = (id: string) => byId.get(id as OwaspCategoryCoverage['id'])?.status ?? 'not_tested';
    const tested = mapped.filter((m) => statusOf(m.owasp) === 'tested');
    const partial = mapped.filter((m) => statusOf(m.owasp) === 'partial');
    const looked = [...tested, ...partial];
    const subcategories = [...new Set(looked.flatMap((m) => m.subcategories))].sort();
    // Each finding once, however many of its categories this CSF category takes.
    const lookedIds = new Set<string>(looked.map((m) => m.owasp));
    const findings = owasp.findings.filter((f) => (f.owasp ?? []).some((id) => lookedIds.has(id))).length;
    if (looked.length === 0) {
      return {
        id: csf.id,
        description: csf.title,
        evidenced: false,
        note: `none of the OWASP categories mapped here was tested: ${mapped.map((m) => m.owasp).join(', ')}`,
      };
    }
    const via = [...tested.map((m) => `${m.owasp} (tested)`), ...partial.map((m) => `${m.owasp} (partial)`)];
    const untested = mapped.filter((m) => !looked.includes(m)).map((m) => m.owasp);
    const note =
      `via ${via.join(', ')} — subcategories ${subcategories.join(', ')}; ` +
      `${findings} open finding${findings === 1 ? '' : 's'} in those categories` +
      (untested.length > 0 ? `; not tested here: ${untested.join(', ')}` : '');
    // Reached only through partial OWASP categories: partial, never evidenced.
    if (tested.length === 0) return { id: csf.id, description: csf.title, evidenced: false, partial: true, note: `PARTIAL — ${note}` };
    return { id: csf.id, description: csf.title, evidenced: true, note };
  });
}

/** The paragraph that heads a per-category framework's lists. */
function frameworkPreamble(framework: LabelledFramework, evidence: OwaspEvidence | null): string[] {
  const owasp = evidence?.coverage ?? null;
  if (framework !== 'owasp-top10-2025' && framework !== 'nist-csf-2.0') return [];
  const out: string[] = [];
  out.push(`${COVERAGE_RULE} Source of the categories and their CWEs: https://owasp.org/Top10/2025/.`);
  if (owasp !== null) {
    out.push('');
    out.push(languagesLine(owasp));
  }
  if (framework === 'nist-csf-2.0') {
    out.push('');
    out.push(
      'CSF 2.0 function and category ids are NIST\'s (CSWP 29, https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf). ' +
        "Which OWASP categories evidence which CSF category is dev-guardian's own mapping — neither NIST nor OWASP " +
        'publishes one. A CSF category counts as evidenced only through an OWASP category a capable scanner tested.',
    );
  }
  if (owasp !== null && owasp.findings_total > 0) {
    out.push('');
    out.push(unmappedSentence(owasp, 'open findings'));
  }
  out.push('');
  return out;
}

function build(args: BuildArgs): string {
  const out: string[] = [];
  out.push(`# Compliance evidence — ${args.framework.toUpperCase()}`);
  out.push('');
  out.push(`Generated: ${args.generated_at}`);
  out.push(`Project path: \`${args.project_path}\``);
  out.push('');

  out.push('## Scope');
  out.push(
    `This document compiles evidence from the dev-guardian local scan store. All data is ` +
      `produced by open-source scanners run on the developer machine — no third-party processing.`,
  );
  out.push('');

  out.push('## Latest compliance scan');
  if (args.compliance) {
    out.push(`- Scan id: \`${args.compliance.scan_id}\``);
    out.push(`- Run at: ${args.compliance.started_at}`);
    const meta = complianceMeta(args.compliance);
    if (meta?.licenses_summary) {
      out.push(`- Licenses observed: ${meta.licenses_summary.length}`);
      const risky = meta.risky_licenses ?? [];
      out.push(`- Risky licenses: ${risky.map((l) => l.license).join(', ') || '(none)'}`);
    }
    if (meta?.policy_documents_found) {
      const docs = meta.policy_documents_found;
      out.push(`- Privacy policy doc: ${docs['privacy_policy'] ? '✓' : '✗ MISSING'}`);
      out.push(`- Terms of service doc: ${docs['terms_of_service'] ? '✓' : '✗ MISSING'}`);
      out.push(`- Cookie policy doc: ${docs['cookie_policy'] ? '✓' : '— n/a or missing'}`);
      out.push(`- Security policy doc: ${docs['security_policy'] ? '✓' : '✗ MISSING'}`);
    }
  } else {
    out.push('(no data — run `compliance_check` first)');
  }
  out.push('');

  out.push('## Dependency vulnerability posture');
  if (args.deps) {
    out.push(`- Scan id: \`${args.deps.scan_id}\``);
    out.push(`- Run at: ${args.deps.started_at}`);
    const cves = args.ctx.storage.cves.listActive(args.deps.scan_id);
    const bySev = cves.reduce<Record<string, number>>((acc, c) => {
      acc[c.severity] = (acc[c.severity] ?? 0) + 1;
      return acc;
    }, {});
    out.push(`- Active CVEs: ${cves.length}`);
    for (const k of ['critical', 'high', 'medium', 'low']) {
      out.push(`  - ${k}: ${bySev[k] ?? 0}`);
    }
  } else {
    out.push('(no data — run `scan_deps` or `deps_audit` first)');
  }
  out.push('');

  out.push('## Software Bill of Materials (SBOM)');
  if (args.sbom?.meta) {
    const m = args.sbom.meta as {
      format?: string;
      components_count?: number;
      file_path?: string;
    };
    out.push(`- Format: ${m.format ?? '(unknown)'}`);
    out.push(`- Components: ${m.components_count ?? '(unknown)'}`);
    out.push(`- Stored at: \`${m.file_path ?? '(unknown)'}\``);
  } else {
    out.push('(no data — run `generate_sbom`)');
  }
  out.push('');

  out.push('## Change-tracking / baseline');
  if (args.baseline) {
    out.push(`- Active baseline: \`${args.baseline.scan_id}\` (set at ${args.baseline.set_at})`);
    out.push(`- Suppressions active: ${args.suppressionsCount}`);
  } else {
    out.push(`- No baseline set. Future regressions can't be auditable without one — run \`set_baseline\`.`);
  }
  out.push('');

  out.push('## Frameworks');
  if (args.framework === 'generic') {
    out.push(
      'No framework specified. Re-run with `framework=gdpr|soc2|iso27001` for a labelled mapping, or ' +
        '`owasp-top10-2025|nist-csf-2.0` for per-category evidence.',
    );
  } else {
    const label = FRAMEWORK_LABEL[args.framework] ?? args.framework.toUpperCase();
    out.push(...frameworkPreamble(args.framework, args.owasp));
    const controls = frameworkControls(args.framework, args);
    const evidenced = controls.filter((c) => c.evidenced);
    const partial = controls.filter((c) => !c.evidenced && c.partial === true);
    const notCovered = controls.filter((c) => !c.evidenced && c.partial !== true);
    const perCategory = args.framework === 'owasp-top10-2025' || args.framework === 'nist-csf-2.0';

    out.push(`### ${label} controls evidenced by this document`);
    if (evidenced.length === 0) {
      out.push('(none — see "not covered" below)');
    } else {
      for (const c of evidenced) out.push(`- ${c.id} (${c.description}): ${c.note}`);
    }
    out.push('');
    // A partial category is not evidence of the control; it gets its own list.
    if (perCategory) {
      out.push(`### ${label} controls PARTIALLY covered by this document`);
      if (partial.length === 0) out.push('(none)');
      else for (const c of partial) out.push(`- ${c.id} (${c.description}): ${c.note}`);
      out.push('');
    }
    out.push(`### ${label} controls NOT covered by this document`);
    if (notCovered.length === 0) {
      out.push('(none)');
    } else {
      for (const c of notCovered) out.push(`- ${c.id} (${c.description}): NOT COVERED — ${c.note}`);
    }
  }
  out.push('');

  out.push('---');
  out.push(
    '_Generated by dev-guardian. dev-guardian sends no telemetry of its own; ' +
      "Semgrep's registry mode sends metrics — pass `local_only: true` to avoid it._",
  );
  return out.join('\n');
}

