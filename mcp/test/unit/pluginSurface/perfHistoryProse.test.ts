/**
 * What the prose says about `perf_check`'s history (3.17.0, review 1's area H),
 * held to what the code does:
 *
 *   - retention keeps a project's N newest `perf` rows across ALL its targets
 *     (one scan type), so measuring many targets in rotation can leave a series
 *     below the 3 runs a judgment needs — the guardian-performance skill, the
 *     `GUARDIAN_RETENTION_SCANS` row of docs/env.md and the CHANGELOG say so
 *     (R1-DG-H-4);
 *   - `guardian://scans/history` holds no `perf` row, so /guardian-report
 *     trend and /guardian-incident never tell the model to leave them out, and
 *     say they are not there (R1-DG-H-3);
 *   - the k6 series is keyed by its inputs only — the script, its content and
 *     the `K6_*` settings perf_check hands k6 —, never a VU count k6 measured
 *     (R2-DG-HZ-1, the user's ruling; R1-DG-H-2's `vus_max` min jittered).
 */

import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { REPO_ROOT } from './pluginDocs.js';

const read = (rel: string): string => readFileSync(resolve(REPO_ROOT, rel), 'utf8').replace(/\s+/g, ' ');

describe("perf_check's history in the prose", () => {
  it('H-4: the skill and docs/env.md say retention is the project\'s N newest perf runs across all its targets', () => {
    const skill = read('skills/guardian-performance/SKILL.md');
    expect(skill).toContain(
      'A retenção guarda as 50 corridas `perf` mais recentes do projeto, de todos os alvos juntos (`GUARDIAN_RETENTION_SCANS`',
    );
    expect(skill).toContain('com muitos alvos em rotação, uma série pode ficar abaixo de 3 corridas e não ser julgada');
    const retention =
      readFileSync(resolve(REPO_ROOT, 'docs/env.md'), 'utf8')
        .split('\n')
        .find((l) => l.startsWith('| `GUARDIAN_RETENTION_SCANS`')) ?? '';
    expect(retention).toContain("`perf_check`'s runs are one type, so a project keeps its N newest across all its targets");
    expect(retention).toContain('can leave a target below the 3 runs its `history` needs to judge');
    expect(read('CHANGELOG.md')).toContain(
      "Retention keeps a project's 50 newest runs across all its targets (`GUARDIAN_RETENTION_SCANS`), so measuring many targets in rotation can leave one below 3 runs.",
    );
  });

  it('H-3: /guardian-report trend and /guardian-incident say perf_check runs are not in guardian://scans/history', () => {
    const report = read('commands/guardian-report.md');
    expect(report).toContain("guardian://scans/history` (the 50 most recent scans of every type but `perf_check`'s runs, which are not in it)");
    expect(report).not.toMatch(/perf` scan there too/);
    expect(read('commands/guardian-incident.md')).toContain("`perf_check`'s runs are not in it");
  });

  // Review 2 (R2-DG-HZ-1, the user's ruling): the k6 series is keyed by its inputs only — never a VU count k6
  // measured, whose min jitters when the VUs' init outlasts k6's first sample.
  it('R2-DG-HZ-1: the prose says the k6 series is the script, its content and the K6_* settings, a changed setting a new series', () => {
    const skill = read('skills/guardian-performance/SKILL.md');
    expect(skill).toContain('no k6, o script, o conteúdo e as variáveis `K6_*` que o `perf_check` lhe passa (mudar uma começa outra série)');
    expect(skill).not.toMatch(/vus_max/);
    const changelog = read('CHANGELOG.md');
    expect(changelog).toContain(
      'for k6 the script, its content and the `K6_*` settings perf_check hands k6 (a digest of them: a value is never stored or shown) — never a VU count k6 measured, so a changed setting starts a new series',
    );
    expect(changelog).not.toMatch(/VUs k6 set up before the start/);
    expect(read('docs/maintainers/architecture.md')).toContain(
      'the k6 series from its inputs only: the script, its content and a digest of the `K6_*` settings perf_check hands k6, never a VU count k6 measured',
    );
    const source = read('mcp/src/metrics/perfSeries.ts');
    expect(source).toContain('and the `K6_*` settings perf_check hands k6');
    expect(source).not.toMatch(/vus_max/);
  });
});
