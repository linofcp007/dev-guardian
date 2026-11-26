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
 *   - the k6 series is keyed by the VUs k6 set up before the start, `vus_max`'s
 *     min (R1-DG-H-2).
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

  it("H-2: the skill names the k6 load the series is keyed by, vus_max's min", () => {
    expect(read('skills/guardian-performance/SKILL.md')).toContain('os VUs criados antes do arranque, o mínimo de `vus_max`');
  });
});
