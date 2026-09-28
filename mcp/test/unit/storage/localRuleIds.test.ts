/**
 * Fix round 2, item 4 — stored rows. Findings stored before the parser
 * normalised local rule ids carry the path of the install that found them
 * (`….configs.semgrep.<id>`), two installs two paths. The startup step
 * re-keys them to the rule's own id with the fingerprint and identity a
 * fresh scan computes, and moves every suppression with them — so a finding
 * stored under install A's id, re-found under the short id after the update,
 * is the same finding: still suppressed, one entry in the open set.
 */

import { describe, expect, it } from 'vitest';
import { assignIdentities } from '../../../src/fingerprint/findingIdentity.js';
import { openSetForProject } from '../../../src/history/openSet.js';
import { makeFinding } from '../../../src/runners/scannerParsers/index.js';
import { semgrepConfigPrefix } from '../../../src/runners/semgrepRuleIds.js';
import { GuardianDatabase } from '../../../src/storage/db.js';
import { Storage } from '../../../src/storage/index.js';
import { rekeyStoredLocalRuleIds } from '../../../src/storage/localRuleIds.js';
import { runMigrations } from '../../../src/storage/migrations/runner.js';
import type { Finding } from '../../../src/types.js';

const P = '/work/project';
const SOURCE = 'const a = [1, 2];\nfor (let i = 0; i <= a.length; i++) {}\nconst AWS = "placeholder-not-a-key";\n';
const INSTALL_A = String.raw`C:\Users\dev\.claude\plugins\cache\dev-guardian\2.0.0\configs\semgrep\bugfix-js.yml`;
const INSTALL_B = '/home/runner/tools/dev-guardian-2.1.0/configs/semgrep/bugfix-js.yml';
const PROJECT_RULES = `${P}/.semgrep.yml`;

function fresh(): { db: GuardianDatabase; storage: Storage } {
  const db = new GuardianDatabase(':memory:');
  runMigrations(db);
  // runMigrations ran the step on an empty database and recorded it; this
  // test plays a database written by an older build, so it runs it again.
  db.prepare("DELETE FROM schema_meta WHERE key = 'local_rule_ids_rekeyed'").run();
  return { db, storage: new Storage(db) };
}

/** Findings as the scan pipeline stores them: parsed, then identities over the file on disk. */
function scanned(ruleIds: { offByOne: string; aws: string }): Array<Finding & { identity: string; content_key: string }> {
  const findings = [
    makeFinding({ tool: 'semgrep', rule_id: ruleIds.offByOne, severity: 'high', category: 'bug', title: 'off by one', file_path: 'app.js', line_start: 2, line_end: 2, snippet: 'for (let i = 0; i <= a.length; i++) {}' }),
    makeFinding({ tool: 'semgrep', rule_id: ruleIds.aws, severity: 'high', category: 'security', title: 'aws key', file_path: 'app.js', line_start: 3, line_end: 3, snippet: 'const AWS = "placeholder-not-a-key";' }),
  ];
  return assignIdentities(findings, { projectPath: P, readSource: () => SOURCE });
}

function store(storage: Storage, scanId: string, findings: ReturnType<typeof scanned>): void {
  storage.scans.insert({ scan_id: scanId, scan_type: 'bugs', project_path: P, tree_hash: `h-${scanId}` });
  storage.findings.bulkInsert(findings.map((f) => ({ ...f, scan_id: scanId })));
  storage.scans.finalize({ scan_id: scanId, status: 'completed', tools_run: [{ name: 'semgrep', status: 'ok' }], missing_tools: [] });
}

const longIds = (install: string) => ({
  offByOne: `${semgrepConfigPrefix(install)}.bugfix-js-off-by-one`,
  aws: `${semgrepConfigPrefix(PROJECT_RULES)}.hardcoded-aws-key`,
});
const SHORT = { offByOne: 'bugfix-js-off-by-one', aws: 'hardcoded-aws-key' };

describe('re-keying stored local-rule findings (two install paths)', () => {
  it('gives each the fingerprint and identity a fresh scan computes, and moves the suppression with it', () => {
    const { db, storage } = fresh();
    const a = scanned(longIds(INSTALL_A));
    const b = scanned(longIds(INSTALL_B));
    // The two installs' ids differ, and so did everything hashed from them.
    expect(a[0]?.identity).not.toBe(b[0]?.identity);
    store(storage, 'scan-a', a);
    store(storage, 'scan-b', b);
    const old = a[0];
    if (old === undefined) throw new Error('fixture');
    storage.suppressions.insert({ finding_fingerprint: old.fingerprint, finding_identity: old.identity, reason: 'accepted', project_path: P });

    expect(rekeyStoredLocalRuleIds(db)).toBe(4);

    const now = scanned(SHORT);
    for (const scanId of ['scan-a', 'scan-b']) {
      const rows = storage.findings.listByScan(scanId);
      expect(rows.map((f) => f.rule_id).sort()).toEqual([SHORT.offByOne, SHORT.aws].sort());
      for (const fresh of now) {
        const row = rows.find((f) => f.rule_id === fresh.rule_id);
        expect(row?.identity, `${scanId} ${fresh.rule_id}`).toBe(fresh.identity);
        // The credential finding's stored snippet is the redaction
        // placeholder; its identity (above) never used it.
        if (fresh.rule_id === SHORT.offByOne) expect(row?.fingerprint).toBe(fresh.fingerprint);
      }
    }
    const suppression = storage.suppressions.listAll()[0];
    expect(suppression?.finding_identity).toBe(now[0]?.identity);
    expect(suppression?.finding_fingerprint).toBe(now[0]?.fingerprint);

    // A scan after the update, parsed with the short ids: the old finding
    // is the same finding — still suppressed, not doubled in the open set.
    store(storage, 'scan-c', now);
    const set = openSetForProject(storage, P);
    expect(set.findings.map((f) => f.rule_id)).toEqual([SHORT.aws]);
  });

  it("a project rule in a subdirectory, stored with the project's absolute path, becomes its id from the project root — at startup", () => {
    const { db, storage } = fresh();
    const teamFile = `${P}/rules/team.yml`;
    const long = `${semgrepConfigPrefix(teamFile)}.team-off-by-one`;
    expect(long).toBe('work.project.rules.team-off-by-one');
    store(storage, 'scan-t', scanned({ offByOne: long, aws: SHORT.aws }));
    // The step runs from runMigrations, as every server start does.
    runMigrations(db);
    const fresh2 = scanned({ offByOne: 'rules.team-off-by-one', aws: SHORT.aws });
    const row = storage.findings.listByScan('scan-t').find((f) => f.rule_id === 'rules.team-off-by-one');
    expect(row?.identity).toBe(fresh2[0]?.identity);
    expect(row?.fingerprint).toBe(fresh2[0]?.fingerprint);
  });

  it('runs once, leaves registry ids and unknown prefixes alone, and a second start changes nothing', () => {
    const { db, storage } = fresh();
    const findings = assignIdentities(
      [
        makeFinding({ tool: 'semgrep', rule_id: 'javascript.lang.security.audit.eval-detected', severity: 'high', category: 'security', title: 'eval', file_path: 'app.js', line_start: 1 }),
        makeFinding({ tool: 'semgrep', rule_id: 'opt.elsewhere.custom-rule', severity: 'high', category: 'security', title: 'custom', file_path: 'app.js', line_start: 2 }),
      ],
      { projectPath: P, readSource: () => SOURCE },
    );
    store(storage, 'scan-r', findings);
    expect(rekeyStoredLocalRuleIds(db)).toBe(0);
    expect(storage.findings.listByScan('scan-r').map((f) => f.rule_id).sort()).toEqual(
      ['javascript.lang.security.audit.eval-detected', 'opt.elsewhere.custom-rule'].sort(),
    );
    store(storage, 'scan-late', scanned(longIds(INSTALL_A)));
    expect(rekeyStoredLocalRuleIds(db)).toBe(0); // recorded as done
  });
});
