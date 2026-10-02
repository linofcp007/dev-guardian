/**
 * What the open set — and so triage, the report, risk and the gates — makes
 * of `llm` verdicts (`finding_validations`, provider `llm`):
 *
 *   - a native finding with an INDEPENDENT `not_exploitable` and a decisive
 *     line is demoted (triage's likely false positives, the report), never
 *     deleted or suppressed; a credential stays `keep` (US-1.AC-6);
 *   - a `same_context` verdict is shown and nothing more: it neither demotes
 *     nor confirms (US-1.AC-7);
 *   - an `llm-hunt` finding enters the open set only with an independent
 *     `exploitable`; native findings are the same with and without LLM plans
 *     (US-2.AC-5).
 *
 * Verdict rows are written the way the feature writes them — through
 * `llmscan/submission.ts#toFindingValidation` and the existing
 * `ValidationsRepo` — and `llm-hunt` findings as a completed `llm_scan` scan.
 *
 * T-06, T-07, T-21.
 */

import { readFileSync } from 'node:fs';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import type { PluginContext } from '../../src/context.js';
import { openSetForProject, type OpenFinding } from '../../src/history/openSet.js';
import { HUNT_CLASSES } from '../../src/llmscan/classes.js';
import { computeReport } from '../../src/llmscan/report.js';
import { toFindingValidation } from '../../src/llmscan/submission.js';
import type { Independence, LlmScanPlan, LlmScanTask, LlmVerdict, VerifyVerdict } from '../../src/llmscan/types.js';
import { resolveProjectPath } from '../../src/platform/projectPath.js';
import { GuardianDatabase as Database } from '../../src/storage/db.js';
import { Storage } from '../../src/storage/index.js';
import { runMigrations } from '../../src/storage/migrations/runner.js';
import { TOOLS } from '../../src/tools/index.js';
import type { Finding } from '../../src/types.js';
import {
  AWS_KEY_LINE,
  PARAM_INSERT,
  SHELL,
  at,
  callTool,
  harness,
  leaseWhere,
  llmOf,
  seedScan,
  seedStandard,
  start,
  submit,
  verdictAt,
  type Harness,
  type SeedSpec,
  type SubmitOut,
} from '../helpers/llmScanHarness.js';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';
import { okResult } from '../helpers/toolResult.js';
import { mulberry32 } from '../helpers/yamlFuzz.js';

vi.setConfig({ testTimeout: 120_000 });
afterAll(cleanupTempDirs);
beforeAll(async () => {
  await import('../../src/registerAll.js');
});

function writeVerdict(
  storage: Storage,
  project: string,
  fingerprint: string,
  verdict: LlmVerdict,
  independence: Independence,
  decisive_line = 'src/x.ts:1 — reason',
  reasoning = 'Followed the value.',
): void {
  storage.validations.upsert(project, [
    toFindingValidation({
      fingerprint,
      verdict,
      independence,
      decisive_line,
      reasoning,
      prompt_version: 'v1',
      tree_hash: 'tree-under-test',
      computed_at: '2026-10-02T12:00:00.000Z',
    }),
  ]);
}

interface Bucket {
  fingerprint: string;
  reason: string;
}
interface Triage {
  summary: { total: number };
  likely_false_positive: Bucket[];
  probably_safe: Bucket[];
  keep: Bucket[];
}

async function triage(plugin: PluginContext, project: string): Promise<Triage> {
  const tool = TOOLS.find((t) => t.name === 'triage_findings');
  if (tool === undefined) throw new Error('triage_findings is not registered');
  return okResult<Triage>(await tool.handler({ project_path: project }, plugin));
}

const DECISIVE = `${at(PARAM_INSERT)} — the values are passed as bound parameters, never concatenated`;
const REASONING = 'The statement text is a constant; the driver binds name, email and role.';

describe('T-06 an independent not_real with a decisive line demotes the finding, never deleting or suppressing it (US-1.AC-6, EC-5)', () => {
  function demoted(): { h: Harness; insert: Finding; others: Finding[] } {
    const h = harness();
    const s = seedStandard(h);
    writeVerdict(h.storage, h.project, s.insert.fingerprint, 'not_exploitable', 'subagent', DECISIVE, REASONING);
    return { h, insert: s.insert, others: [s.sqli, s.shell] };
  }

  it('T-06 triage lists it among the likely false positives, the decisive line as the reason', async () => {
    const { h, insert, others } = demoted();
    const t = await triage(h.plugin, h.project);
    const entry = t.likely_false_positive.find((b) => b.fingerprint === insert.fingerprint);
    expect(entry, JSON.stringify(t)).toBeDefined();
    expect(entry?.reason).toContain(at(PARAM_INSERT));
    expect(entry?.reason).toContain('bound parameters');
    expect(t.keep.map((b) => b.fingerprint)).not.toContain(insert.fingerprint);
    for (const f of others) expect(t.keep.map((b) => b.fingerprint)).toContain(f.fingerprint);
    expect(t.summary.total).toBe(3);
  });

  it('T-06 the open set still holds it, marked with the verdict; nothing was suppressed', () => {
    const { h, insert } = demoted();
    const set = openSetForProject(h.storage, h.project);
    const f = set.findings.find((x) => x.fingerprint === insert.fingerprint);
    expect(f).toBeDefined();
    if (f === undefined) return;
    expect(llmOf(f)).toMatchObject({ verdict: 'not_exploitable', independent: true, decisive_line: DECISIVE, prompt_version: 'v1' });
    expect(set.suppressed).toBe(0);
    expect(h.storage.suppressions.listAll()).toEqual([]);
  });

  it('T-06 the exported report still lists it, with the decisive line and the reasoning', async () => {
    const { h } = demoted();
    const out = okResult<{ file_path: string; findings_count: number }>(
      await callTool(h, 'report_export', { project_path: h.project, format: 'markdown' }),
    );
    expect(out.findings_count).toBe(3);
    const md = readFileSync(out.file_path, 'utf8');
    expect(md).toContain(at(PARAM_INSERT));
    expect(md).toContain(DECISIVE);
    expect(md).toContain(REASONING);
  });

  it('T-06 a credential finding stays keep, whatever the verdict', async () => {
    const h = harness();
    const { findings } = seedScan(h.storage, h.db, h.project, 'secrets', [
      { tool: 'gitleaks', rule_id: 'aws-access-token', subcategory: 'secret', loc: AWS_KEY_LINE, title: 'AWS access key' },
    ]);
    const key = findings[0];
    if (key === undefined) throw new Error('seed');
    writeVerdict(h.storage, h.project, key.fingerprint, 'not_exploitable', 'subagent', `${at(AWS_KEY_LINE)} — a documentation key`);
    const t = await triage(h.plugin, h.project);
    expect(t.keep.map((b) => b.fingerprint)).toContain(key.fingerprint);
    expect(t.likely_false_positive.map((b) => b.fingerprint)).not.toContain(key.fingerprint);
  });

  it('T-06 EC-5: a real verdict on a finding suppressed after the plan was made keeps the suppression and records the verdict', async () => {
    const h = harness();
    const s = seedStandard(h);
    const out = await start(h, { modes: ['verify'] });
    h.storage.suppressions.insert({ finding_fingerprint: s.shell.fingerprint, reason: 'accepted risk', project_path: h.project });
    const t = await leaseWhere(h, out.plan_id, (x) => h.repo.getTask(out.plan_id, x.task_id)?.target.fingerprint === s.shell.fingerprint);
    expect(okResult<SubmitOut>(await submit(h, out.plan_id, t, verdictAt(SHELL, 'real'))).accepted).toBe(true);

    const set = openSetForProject(h.storage, h.project);
    expect(set.findings.map((f) => f.fingerprint)).not.toContain(s.shell.fingerprint);
    expect(set.suppressed).toBeGreaterThanOrEqual(1);
    const row = h.storage.validations
      .listByProject(h.project)
      .find((v) => v.fingerprint === s.shell.fingerprint && String(v.provider) === 'llm');
    expect(row === undefined ? undefined : String(row.verdict)).toBe('exploitable');
  });
});

const VERDICTS = ['exploitable', 'not_exploitable', 'undetermined'] as const;
const INDEPENDENCE: Independence[] = ['subagent', 'sampling', 'same_context'];
const TO_VERIFY: Record<LlmVerdict, VerifyVerdict['verdict']> = { exploitable: 'real', not_exploitable: 'not_real', undetermined: 'undetermined' };

type Choice = { verdict: LlmVerdict; independence: Independence } | null;

function choose(rand: () => number): Choice {
  if (rand() < 0.25) return null;
  return {
    verdict: VERDICTS[Math.floor(rand() * VERDICTS.length)] ?? 'undetermined',
    independence: INDEPENDENCE[Math.floor(rand() * INDEPENDENCE.length)] ?? 'same_context',
  };
}

const independent = (c: Choice): boolean => c !== null && c.independence !== 'same_context';

describe('T-07 a same_context verdict never demotes nor confirms; the report shows the split by independence (US-1.AC-7)', () => {
  it('T-07 220 seeded mixes of subagent, sampling and same_context verdicts', async () => {
    const rand = mulberry32(0x07_0007);
    // triage resolves its project_path: a real directory, shared; a fresh database per case.
    const project = resolveProjectPath(makeTempDir('llm-openset-t07-')).path;
    for (let c = 0; c < 220; c += 1) {
      const db = new Database(':memory:');
      runMigrations(db);
      const storage = new Storage(db);
      const plugin: PluginContext = { storage, shell: null, scriptsDir: '', progressNotifier: { send: () => {} } };

      const nativeSpecs: SeedSpec[] = Array.from({ length: 1 + Math.floor(rand() * 4) }, (_, i) => ({
        tool: 'semgrep',
        rule_id: `case${c}.rule${i}`,
        loc: { file: `src/mod${i}.ts`, line: i + 1 },
      }));
      const huntSpecs: SeedSpec[] = Array.from({ length: Math.floor(rand() * 4) }, (_, i) => ({
        tool: 'llm-hunt',
        rule_id: HUNT_CLASSES[Math.floor(rand() * HUNT_CLASSES.length)] ?? 'business-logic',
        loc: { file: `src/hunt${i}.ts`, line: i + 1 },
      }));
      const natives = seedScan(storage, db, project, 'sast', nativeSpecs).findings;
      const hunts = huntSpecs.length > 0 ? seedScan(storage, db, project, 'llm_scan', huntSpecs, [{ name: 'llm-hunt', status: 'ok' }]).findings : [];

      const choices = new Map<string, Choice>();
      for (const f of [...natives, ...hunts]) {
        const ch = choose(rand);
        choices.set(f.fingerprint, ch);
        if (ch !== null) writeVerdict(storage, project, f.fingerprint, ch.verdict, ch.independence, `${f.file_path ?? ''}:${f.line_start ?? 0} — case ${c}`);
      }
      const ctx = `case ${c}: ${JSON.stringify([...choices])}`;

      const set = openSetForProject(storage, project);
      const inSet = new Map<string, OpenFinding>(set.findings.map((f) => [f.fingerprint, f]));
      const t = await triage(plugin, project);
      const lfp = new Set(t.likely_false_positive.map((b) => b.fingerprint));

      for (const f of natives) {
        const ch = choices.get(f.fingerprint) ?? null;
        const open = inSet.get(f.fingerprint);
        expect(open, ctx).toBeDefined();
        if (open === undefined) continue;
        const marker = llmOf(open);
        if (ch === null) expect(marker, ctx).toBeUndefined();
        else expect(marker, ctx).toMatchObject({ verdict: ch.verdict, independent: independent(ch) });
        const demote = ch !== null && ch.verdict === 'not_exploitable' && independent(ch);
        expect(lfp.has(f.fingerprint), `${ctx} — ${f.fingerprint} demoted?`).toBe(demote);
      }
      for (const f of hunts) {
        const ch = choices.get(f.fingerprint) ?? null;
        const confirmed = ch !== null && ch.verdict === 'exploitable' && independent(ch);
        expect(inSet.has(f.fingerprint), `${ctx} — ${f.fingerprint} confirmed?`).toBe(confirmed);
      }

      // The report: one closed verify task per verdict given.
      const judged = [...choices].filter((e): e is [string, NonNullable<Choice>] => e[1] !== null);
      const plan: LlmScanPlan = {
        id: `plan-${c}`,
        project_path: project,
        scan_id: `scan-${c}`,
        modes: ['verify'],
        prompt_version: 'v1',
        tree_hash: 'tree-under-test',
        surface_snapshot_id: null,
        limits: { max_tasks: 200, max_estimated_tokens: 500_000, per_task_overhead: 60_000 },
        estimate: { tasks: judged.length, brief_tokens: 0, total_tokens: 0, assumptions: 'test' },
        confirmed: true,
        status: 'complete',
        not_eligible: [],
        set_aside: [],
        created_at: '2026-10-02T12:00:00.000Z',
        updated_at: '2026-10-02T12:00:00.000Z',
      };
      const tasks: LlmScanTask[] = judged.map(([fp, ch], i) => ({
        plan_id: plan.id,
        task_id: `t-${String(i + 1).padStart(4, '0')}`,
        kind: 'verify',
        target: { fingerprint: fp, files: ['src/x.ts'] },
        status: 'closed',
        lease_token: null,
        lease_expires_at: null,
        attempts: 0,
        file_hashes: {},
        brief_chars: 1000,
        response_chars: 200,
        independence: ch.independence,
        result: {
          verdict: TO_VERIFY[ch.verdict],
          attacker_input: 'none',
          operation: 'src/x.ts:1',
          decisive_line: 'src/x.ts:1 — reason',
          reasoning: 'r',
        },
        closed_reason: 'valid',
        delivered_at: '2026-10-02T12:00:01.000Z',
        closed_at: '2026-10-02T12:00:02.000Z',
      }));
      if (tasks.length > 0) {
        const report = computeReport(plan, tasks);
        for (const ind of INDEPENDENCE) {
          expect(report.counts.by_independence[ind], `${ctx} — ${ind}`).toBe(judged.filter(([, ch]) => ch.independence === ind).length);
        }
        const expectDemoted = judged.filter(([, ch]) => ch.verdict === 'not_exploitable' && ch.independence !== 'same_context').map(([fp]) => fp);
        expect(report.demoted.map((d) => d.fingerprint).sort(), ctx).toEqual(expectDemoted.sort());
      }
      db.close();
    }
  });
});

describe('T-21 unverified and not_exploitable hunt findings never enter the open set or its totals; native findings are unchanged by LLM plans (US-2.AC-5)', () => {
  it('T-21 240 seeded projects, each beside a plain twin with the same native findings', () => {
    const rand = mulberry32(0x21_0021);
    const db = new Database(':memory:');
    runMigrations(db);
    const storage = new Storage(db);
    let confirmable = 0;

    for (let c = 0; c < 240; c += 1) {
      const withLlm = `/t21/case-${c}`;
      const plain = `/t21/plain-${c}`;
      const nativeSpecs: SeedSpec[] = Array.from({ length: Math.floor(rand() * 6) }, (_, i) => ({
        tool: 'semgrep',
        rule_id: `case${c}.rule${i}`,
        loc: { file: `src/n${i}.ts`, line: 1 + i },
      }));
      const secret = rand() < 0.3;
      const secretSpec: SeedSpec[] = secret
        ? [{ tool: 'gitleaks', rule_id: 'aws-access-token', subcategory: 'secret', loc: { file: 'src/config.ts', line: 6 } }]
        : [];
      const suppressFirst = rand() < 0.3;

      let nativeFps: string[] = [];
      for (const project of [withLlm, plain]) {
        const sast = nativeSpecs.length > 0 ? seedScan(storage, db, project, 'sast', nativeSpecs).findings : [];
        const sec = secret ? seedScan(storage, db, project, 'secrets', secretSpec, [{ name: 'gitleaks', status: 'ok' }]).findings : [];
        nativeFps = [...sast, ...sec].map((f) => f.fingerprint);
        const first = nativeFps[0];
        if (suppressFirst && first !== undefined) {
          storage.suppressions.insert({ finding_fingerprint: first, reason: 'accepted', project_path: project });
        }
      }

      const huntSpecs: SeedSpec[] = Array.from({ length: Math.floor(rand() * 6) }, (_, i) => ({
        tool: 'llm-hunt',
        rule_id: HUNT_CLASSES[Math.floor(rand() * HUNT_CLASSES.length)] ?? 'business-logic',
        loc: { file: `src/h${i}.ts`, line: 1 + i },
      }));
      const hunts = huntSpecs.length > 0 ? seedScan(storage, db, withLlm, 'llm_scan', huntSpecs, [{ name: 'llm-hunt', status: 'ok' }]).findings : [];
      const expected: string[] = [];
      for (const f of hunts) {
        const ch = choose(rand);
        if (ch !== null) writeVerdict(storage, withLlm, f.fingerprint, ch.verdict, ch.independence);
        if (ch !== null && ch.verdict === 'exploitable' && independent(ch)) expected.push(f.fingerprint);
      }
      // Verdicts on native findings too: they may mark them, never remove them.
      for (const fp of nativeFps) {
        const ch = choose(rand);
        if (ch !== null) writeVerdict(storage, withLlm, fp, ch.verdict, ch.independence);
      }
      confirmable += expected.length;

      const a = openSetForProject(storage, withLlm);
      const b = openSetForProject(storage, plain);
      const ctx = `case ${c}`;
      const strip = (f: OpenFinding): Record<string, unknown> => {
        const { scan_id: _scan, ...rest } = f as OpenFinding & { llm?: unknown };
        const { llm: _llm, ...bare } = rest as typeof rest & { llm?: unknown };
        return bare;
      };
      const nativeA = a.findings.filter((f) => f.tool !== 'llm-hunt');
      expect(nativeA.map(strip), ctx).toEqual(b.findings.map(strip));
      expect(a.suppressed, ctx).toBe(b.suppressed);

      const huntsIn = a.findings.filter((f) => f.tool === 'llm-hunt').map((f) => f.fingerprint).sort();
      expect(huntsIn, ctx).toEqual([...expected].sort());
      expect(a.findings.length, ctx).toBe(b.findings.length + expected.length);
    }
    // The generator really offered confirmable hunt findings.
    expect(confirmable).toBeGreaterThan(30);
  });
});
