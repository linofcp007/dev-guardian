/**
 * Fix rounds 2 and 3 — stored rows. Findings a plugin pack found before the
 * parser stored its rules under their own id carry the path of the install
 * that found them (`<install>.configs.semgrep.<id>`), two installs two paths.
 * The startup step re-keys them to the rule's own id with the fingerprint and
 * identity a fresh scan computes, and moves every suppression with them — so
 * a finding stored under install A's id, re-found under the own id after the
 * update, is the same finding: still suppressed, one entry in the open set.
 *
 * Round 3: only an install of THIS plugin is re-keyed (its root, or a sibling
 * version directory), and only a rule id its packs declare; a project's own
 * rules and rule files elsewhere keep what they stored, so two distinct rules
 * are never merged (I-2) and a registry id never changes (M-6). The step is
 * resumable and incremental (M-2): batches commit with a watermark, a killed
 * start keeps its progress, and later starts re-key only scans written since.
 */

import { join, resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { assignIdentities } from '../../../src/fingerprint/findingIdentity.js';
import { openSetForProject } from '../../../src/history/openSet.js';
import { makeFinding } from '../../../src/runners/scannerParsers/index.js';
import { pluginPackIdMatcher, semgrepConfigPrefix } from '../../../src/runners/semgrepRuleIds.js';
import { GuardianDatabase } from '../../../src/storage/db.js';
import { Storage } from '../../../src/storage/index.js';
import { rekeyStoredLocalRuleIds, WATERMARK_KEY } from '../../../src/storage/localRuleIds.js';
import { runMigrations } from '../../../src/storage/migrations/runner.js';
import type { Finding } from '../../../src/types.js';

// Host-shaped paths (C:\work\… on Windows, /work/… elsewhere).
const BASE = resolve('/work');
const P = join(BASE, 'project');
const CACHE = join(BASE, 'home', '.claude', 'plugins', 'cache', 'market', 'dev-guardian');
const PACKS = join(CACHE, '2.1.0', 'configs', 'semgrep'); // the install running now
const OLD_PACK = join(CACHE, '2.0.0', 'configs', 'semgrep', 'bugfix-js.yml'); // the one that found them
const NOW_PACK = join(PACKS, 'bugfix-js.yml');
const PACK_IDS: ReadonlySet<string> = new Set(['bugfix-js-off-by-one']);
const SOURCE = 'const a = [1, 2];\nfor (let i = 0; i <= a.length; i++) {}\nconst AWS = "placeholder-not-a-key";\n';

const opts = { packsDir: PACKS, packRuleIds: PACK_IDS };

function fresh(): { db: GuardianDatabase; storage: Storage } {
  const db = new GuardianDatabase(':memory:');
  runMigrations(db);
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

function store(storage: Storage, scanId: string, findings: ReturnType<typeof scanned>, project = P, finalize = true): void {
  storage.scans.insert({ scan_id: scanId, scan_type: 'bugs', project_path: project, tree_hash: `h-${scanId}` });
  storage.findings.bulkInsert(findings.map((f) => ({ ...f, scan_id: scanId })));
  if (finalize) {
    storage.scans.finalize({ scan_id: scanId, status: 'completed', tools_run: [{ name: 'semgrep', status: 'ok' }], missing_tools: [] });
  }
}

const packId = (pack: string): string => `${semgrepConfigPrefix(pack)}.bugfix-js-off-by-one`;
const ruleIds = (storage: Storage, scanId: string): string[] => storage.findings.listByScan(scanId).map((f) => f.rule_id ?? '').sort();

describe('re-keying stored plugin-pack findings', () => {
  it('an older install\'s pack id becomes the own id, with the fingerprint and identity a fresh scan computes and its suppression', () => {
    const { db, storage } = fresh();
    const aws = 'hardcoded-aws-key'; // a project rule at the root: already its stored id
    const a = scanned({ offByOne: packId(OLD_PACK), aws });
    const b = scanned({ offByOne: packId(NOW_PACK), aws });
    expect(a[0]?.identity).not.toBe(b[0]?.identity);
    store(storage, 'scan-a', a);
    store(storage, 'scan-b', b);
    const old = a[0];
    if (old === undefined) throw new Error('fixture');
    storage.suppressions.insert({ finding_fingerprint: old.fingerprint, finding_identity: old.identity, reason: 'accepted', project_path: P });

    expect(rekeyStoredLocalRuleIds(db, opts)).toBe(2);

    const now = scanned({ offByOne: 'bugfix-js-off-by-one', aws });
    for (const scanId of ['scan-a', 'scan-b']) {
      const row = storage.findings.listByScan(scanId).find((f) => f.rule_id === 'bugfix-js-off-by-one');
      expect(row?.identity, scanId).toBe(now[0]?.identity);
      expect(row?.fingerprint, scanId).toBe(now[0]?.fingerprint);
    }
    const suppression = storage.suppressions.listAll()[0];
    expect(suppression?.finding_identity).toBe(now[0]?.identity);
    expect(suppression?.finding_fingerprint).toBe(now[0]?.fingerprint);

    // A scan after the update: the old finding is the same finding — still
    // suppressed, not doubled in the open set.
    store(storage, 'scan-c', now);
    expect(openSetForProject(storage, P).findings.map((f) => f.rule_id)).toEqual([aws]);
  });

  it('never touches a project rule, a rule file elsewhere, another configs/semgrep, or a registry id — two distinct rules stay two', () => {
    const { db, storage } = fresh();
    const team = join(BASE, 'opt', 'team');
    const cases = [
      // A project's own rule reported with its absolute path (review_pr ran elsewhere).
      `${semgrepConfigPrefix(join(P, 'rules', 'team.yml'))}.bugfix-js-off-by-one`,
      // The project's own configs/semgrep/ (M-3): relative, as a scan from the project stores it.
      'configs.semgrep.bugfix-js-off-by-one',
      // A registered rule directory outside the project, two files, one rule id (I-2).
      `${semgrepConfigPrefix(join(team, 'js', 'no-eval.yml'))}.no-eval`,
      `${semgrepConfigPrefix(join(team, 'v2', 'no-eval.yml'))}.no-eval`,
      // Someone else's configs/semgrep, with a rule id the packs also declare.
      `${semgrepConfigPrefix(join(BASE, 'opt', 'configs', 'semgrep', 'x.yml'))}.bugfix-js-off-by-one`,
      // A pack-shaped id whose rule the packs do not declare.
      `${semgrepConfigPrefix(OLD_PACK)}.not-a-pack-rule`,
      // A registry id, for a project whose path spells its namespace (M-6).
      'python.lang.security.audit.eval-detected',
    ];
    cases.forEach((id, i) => store(storage, `scan-${i}`, scanned({ offByOne: id, aws: 'hardcoded-aws-key' })));
    const python = resolve('/python/lang');
    store(storage, 'scan-py', scanned({ offByOne: 'python.lang.security.audit.eval-detected', aws: 'x' }), python);

    expect(rekeyStoredLocalRuleIds(db, opts)).toBe(0);
    cases.forEach((id, i) => expect(ruleIds(storage, `scan-${i}`)).toEqual([id, 'hardcoded-aws-key'].sort()));
    expect(ruleIds(storage, 'scan-py')).toEqual(['python.lang.security.audit.eval-detected', 'x']);
  });

  it("leaves the plugin's own repository alone: there its packs are project files", () => {
    const { db, storage } = fresh();
    const repo = join(BASE, 'src', 'dev-guardian');
    const repoPacks = join(repo, 'configs', 'semgrep');
    store(storage, 'dog', scanned({ offByOne: packId(join(repoPacks, 'bugfix-js.yml')), aws: 'x' }), repo);
    expect(rekeyStoredLocalRuleIds(db, { packsDir: repoPacks, packRuleIds: PACK_IDS })).toBe(0);
  });

  it('the matcher: the running install and its sibling versions, a declared rule id — nothing else', () => {
    const match = pluginPackIdMatcher(PACKS, PACK_IDS);
    expect(match(packId(NOW_PACK))).toBe('bugfix-js-off-by-one');
    expect(match(packId(OLD_PACK))).toBe('bugfix-js-off-by-one');
    expect(match(packId(join(BASE, 'elsewhere', 'dev-guardian', '2.0.0', 'configs', 'semgrep', 'x.yml')))).toBeNull();
    expect(match('configs.semgrep.bugfix-js-off-by-one')).toBeNull();
    expect(match(`${semgrepConfigPrefix(OLD_PACK)}.other-rule`)).toBeNull();
  });

  it('only ONE version directory beside a versioned root — never deeper, never beside a root that is not a version (review M-3)', () => {
    const match = pluginPackIdMatcher(PACKS, PACK_IDS);
    const at = (...dirs: string[]): string => packId(join(CACHE, ...dirs, 'configs', 'semgrep', 'x.yml'));
    expect(match(at('3.0.0-rc.1'))).toBe('bugfix-js-off-by-one');
    expect(match(at('a1b2c3d4'))).toBe('bugfix-js-off-by-one');
    expect(match(at('2.0.1', 'nested', 'x'))).toBeNull();
    expect(match(at('my-fork'))).toBeNull();
    // A shallow root that is not a version directory (--plugin-dir C:\dg): its own id only.
    const shallow = join(BASE, 'dg', 'configs', 'semgrep');
    const matchShallow = pluginPackIdMatcher(shallow, PACK_IDS);
    expect(matchShallow(packId(join(shallow, 'x.yml')))).toBe('bugfix-js-off-by-one');
    expect(matchShallow(packId(join(BASE, 'other', 'configs', 'semgrep', 'x.yml')))).toBeNull();
    expect(matchShallow(packId(join(BASE, '2.0.0', 'configs', 'semgrep', 'x.yml')))).toBeNull();
  });
});

describe('the re-key is resumable and incremental (M-2)', () => {
  const seedOld = (storage: Storage, n: number, from = 0, finalize = true): void => {
    for (let i = from; i < from + n; i++) store(storage, `s${String(i).padStart(3, '0')}`, scanned({ offByOne: packId(OLD_PACK), aws: 'x' }), P, finalize);
  };
  const reKeyed = (storage: Storage, n: number): number =>
    Array.from({ length: n }, (_, i) => ruleIds(storage, `s${String(i).padStart(3, '0')}`)).filter((ids) => ids.includes('bugfix-js-off-by-one')).length;
  const watermark = (db: GuardianDatabase): number =>
    Number(db.prepare<[string], { value: string }>('SELECT value FROM schema_meta WHERE key = ?').get(WATERMARK_KEY)?.value ?? 0);

  it('a start killed after two batches keeps them; the next carries on from there and redoes nothing', () => {
    const { db, storage } = fresh();
    seedOld(storage, 10);
    expect(() =>
      rekeyStoredLocalRuleIds(db, {
        ...opts,
        batchScans: 2,
        afterBatch: (n) => {
          if (n === 2) throw new Error('killed');
        },
      }),
    ).toThrow('killed');
    expect(reKeyed(storage, 10)).toBe(4);
    const mark = watermark(db);
    expect(mark).toBeGreaterThan(0);

    let batches = 0;
    expect(rekeyStoredLocalRuleIds(db, { ...opts, batchScans: 2, afterBatch: (n) => (batches = n) })).toBe(6);
    expect(batches).toBe(3);
    expect(reKeyed(storage, 10)).toBe(10);
  });

  it('a later start re-keys only rows written since — an older process sharing the database', () => {
    const { db, storage } = fresh();
    seedOld(storage, 6);
    expect(rekeyStoredLocalRuleIds(db, opts)).toBe(6);
    expect(rekeyStoredLocalRuleIds(db, opts)).toBe(0);
    seedOld(storage, 2, 6); // an older plugin process wrote these since
    let batches = 0;
    expect(rekeyStoredLocalRuleIds(db, { ...opts, afterBatch: (n) => (batches = n) })).toBe(2);
    expect(batches).toBe(1);
    expect(reKeyed(storage, 8)).toBe(8);
  });

  it("does not wait on a running scan whose owner is gone (the reaper's rule): one start re-keys it (review M-1)", () => {
    const { db, storage } = fresh();
    seedOld(storage, 1);
    seedOld(storage, 1, 1, false); // running, its owner dead (below)
    seedOld(storage, 1, 2);
    expect(rekeyStoredLocalRuleIds(db, { ...opts, reap: { isAlive: () => false } })).toBe(3);
    expect(reKeyed(storage, 3)).toBe(3);
  });

  it('stops before a scan still being written, and picks it up once it is done', () => {
    const { db, storage } = fresh();
    seedOld(storage, 1);
    seedOld(storage, 1, 1, false); // running: its findings may not all be in
    seedOld(storage, 1, 2);
    expect(rekeyStoredLocalRuleIds(db, opts)).toBe(1);
    expect(reKeyed(storage, 3)).toBe(1);
    storage.scans.finalize({ scan_id: 's001', status: 'completed', tools_run: [{ name: 'semgrep', status: 'ok' }], missing_tools: [] });
    expect(rekeyStoredLocalRuleIds(db, opts)).toBe(2);
    expect(reKeyed(storage, 3)).toBe(3);
  });
});
