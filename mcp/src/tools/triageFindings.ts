/**
 * `triage_findings` — heuristic suggestions for findings the calling model
 * should consider suppressing.
 *
 * No LLM calls — we apply boring, well-known patterns:
 *   - Findings in test files (`test/`, `tests/`, `__tests__/`, `*.spec.*`)
 *   - Findings in generated / vendored code (`vendor/`, `node_modules/`,
 *     `dist/`, `build/`, `generated/`, `*.min.js`)
 *   - Findings in fixtures / mocks
 *   - Findings already-suppressed-by-fingerprint (just surface them so the
 *     model knows)
 *
 * Output buckets each finding into one of:
 *   - likely_false_positive (high confidence pattern match)
 *   - probably_safe (path-based hint)
 *   - keep (no heuristic fired — model should review)
 *
 * Resource cost: zero scanners, no I/O beyond storage queries.
 */

import type { PluginContext } from '../context.js';
import type { Finding, ToolResult } from '../types.js';
import { registerToolModule, type ToolModule } from './index.js';

const TEST_PATTERNS = [
  /(^|\/)tests?\//i,
  /(^|\/)__tests__\//i,
  /\.spec\.(ts|js|tsx|jsx|py|rb|go|rs)$/i,
  /\.test\.(ts|js|tsx|jsx|py|rb|go|rs)$/i,
  /(^|\/)test_[^/]+\.py$/i,
];
const GENERATED_PATTERNS = [
  /(^|\/)vendor\//i,
  /(^|\/)node_modules\//i,
  /(^|\/)dist\//i,
  /(^|\/)build\//i,
  /(^|\/)generated\//i,
  /(^|\/)gen\//i,
  /\.min\.(js|css)$/i,
  /\.generated\.(ts|js|py)$/i,
];
const FIXTURE_PATTERNS = [
  /(^|\/)fixtures?\//i,
  /(^|\/)mocks?\//i,
  /(^|\/)stubs?\//i,
  /(^|\/)examples?\//i,
];

const tool: ToolModule = {
  name: 'triage_findings',
  title: 'Heuristic triage of findings',
  description:
    'Bucket the latest scan\'s open findings into likely_false_positive / probably_safe / keep ' +
    'using path-based heuristics (test files, generated code, fixtures). No LLM call — the model ' +
    'that invoked the tool decides whether to call suppress_finding on the suggestions.',
  inputSchema: {},
  handler: async (_input, ctx) => handler(ctx),
};

registerToolModule(tool);

interface Bucket {
  fingerprint: string;
  file_path: string | null;
  severity: string;
  title: string;
  rule_id: string | null;
  reason: string;
  suggested_suppression_reason: string;
}

async function handler(ctx: PluginContext): Promise<ToolResult<Record<string, unknown>>> {
  const open = ctx.storage.findings.listOpen();
  const likely_false_positive: Bucket[] = [];
  const probably_safe: Bucket[] = [];
  const keep: Bucket[] = [];

  for (const f of open) {
    const path = f.file_path ?? '';
    const bucket = classifyByPath(f, path);
    if (bucket === 'likely_fp') {
      likely_false_positive.push(toBucket(f, 'matches test/fixture pattern'));
    } else if (bucket === 'safe') {
      probably_safe.push(toBucket(f, 'in vendored/generated/build artefact'));
    } else {
      keep.push(toBucket(f, 'no heuristic fired'));
    }
  }

  return {
    ok: true,
    summary: {
      total: open.length,
      likely_false_positive: likely_false_positive.length,
      probably_safe: probably_safe.length,
      keep: keep.length,
    },
    likely_false_positive,
    probably_safe,
    keep_sample: keep.slice(0, 20),
    instructions_for_model:
      'For each entry in `likely_false_positive`, consider calling `suppress_finding` with the ' +
      'suggested_suppression_reason. Be more conservative with `probably_safe` — review one before ' +
      'batch-suppressing. Never auto-suppress severity=critical without explicit human approval.',
  };
}

function classifyByPath(_f: Finding, path: string): 'likely_fp' | 'safe' | 'keep' {
  if (!path) return 'keep';
  if (TEST_PATTERNS.some((p) => p.test(path))) return 'likely_fp';
  if (FIXTURE_PATTERNS.some((p) => p.test(path))) return 'likely_fp';
  if (GENERATED_PATTERNS.some((p) => p.test(path))) return 'safe';
  return 'keep';
}

function toBucket(f: Finding, reason: string): Bucket {
  return {
    fingerprint: f.fingerprint,
    file_path: f.file_path ?? null,
    severity: f.severity,
    title: f.title,
    rule_id: f.rule_id ?? null,
    reason,
    suggested_suppression_reason: `triage_findings: ${reason}`,
  };
}

