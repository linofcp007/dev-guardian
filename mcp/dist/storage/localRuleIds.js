/**
 * Re-key stored local-rule findings to their canonical rule id — once, at
 * startup.
 *
 * Until fix round 2 the Semgrep parser stored a local rule under the id
 * Semgrep reports: the dotted directory of the rule file plus the rule's id,
 * the whole absolute path whenever the file was not under Semgrep's working
 * directory (`runners/semgrepRuleIds.ts`). For the plugin's own packs that is
 * the plugin's install — every version has its own, every CI runner
 * another — and `rule_id` is hashed into the fingerprint AND the identity.
 * The parser now stores the canonical id (a pack rule's own id; a project
 * rule's id from the project root); without this step every finding stored
 * before it would stop matching the same finding re-found after it —
 * suppressions stop applying, the open set holds both, a diff reports one
 * new plus one resolved.
 *
 * So each stored Semgrep finding whose `rule_id` is recognisably a
 * path-prefixed local id (`storedLocalRuleId`: a pack rule in any
 * `configs/semgrep/`, or a project rule reported with the project's absolute
 * path) gets:
 *   - the canonical id;
 *   - the fingerprint a fresh scan computes for it — except for a credential
 *     finding, whose stored snippet is the redaction placeholder (its
 *     identity, which never used the snippet, still matches);
 *   - the identity a fresh scan computes (`rekeyStoredIdentities`: the stored
 *     content key, the occurrence recounted within the scan);
 * and every suppression and cached validation naming the old fingerprint or
 * identity follows it. Additive and idempotent: it changes values, never the
 * schema; a re-keyed row no longer looks prefixed, and the step records
 * itself in `schema_meta` so a later start does not scan again. A rule file
 * outside the project and outside a `configs/semgrep/` directory is left as
 * it is: its id cannot be told from a registry id by its text. A row whose
 * new fingerprint would collide with another row of the same scan (two
 * copies of one rule loaded from two directories) keeps its old one
 * (`UPDATE OR IGNORE`).
 *
 * `.guardian/baseline.json` cannot be re-keyed: its entries carry no rule id.
 * A committed baseline that lists local-rule findings needs one
 * `dev-guardian baseline update` (docs/ci.md, CHANGELOG).
 */
import { computeFingerprint } from '../fingerprint/findingFingerprint.js';
import { rekeyStoredIdentities } from '../fingerprint/findingIdentity.js';
import { storedLocalRuleId } from '../runners/semgrepRuleIds.js';
const DONE_KEY = 'local_rule_ids_rekeyed';
/** Re-keys every prefixed local-rule finding; returns how many rows changed. */
export function rekeyStoredLocalRuleIds(db) {
    const done = db.prepare('SELECT value FROM schema_meta WHERE key = ?').get(DONE_KEY);
    if (done !== undefined)
        return 0;
    const candidates = db
        .prepare(`SELECT f.rowid AS rid, f.scan_id, s.project_path, f.fingerprint, f.tool, f.rule_id, f.subcategory,
              f.file_path, f.line_start, f.line_end, f.snippet, f.identity, f.content_key
         FROM findings f JOIN scans s ON s.id = f.scan_id
        WHERE lower(f.tool) = 'semgrep' AND f.rule_id LIKE '%.%'`)
        .all();
    const byScan = new Map();
    for (const row of candidates) {
        if (storedLocalRuleId(row.rule_id, row.project_path) === null)
            continue;
        const list = byScan.get(row.scan_id) ?? [];
        list.push(row);
        byScan.set(row.scan_id, list);
    }
    let changed = 0;
    db.transaction(() => {
        // Another process may have re-keyed in the meantime (runner.ts's rule).
        if (db.prepare('SELECT value FROM schema_meta WHERE key = ?').get(DONE_KEY) !== undefined) {
            return;
        }
        const updateFinding = db.prepare('UPDATE OR IGNORE findings SET rule_id = ?, fingerprint = ?, identity = ?, content_key = ? WHERE rowid = ?');
        const moveSuppressionFp = db.prepare('UPDATE suppressions SET finding_fingerprint = ? WHERE finding_fingerprint = ?');
        const moveSuppressionId = db.prepare('UPDATE suppressions SET finding_identity = ? WHERE finding_identity = ?');
        const moveValidation = db.prepare('UPDATE OR IGNORE finding_validations SET fingerprint = ? WHERE fingerprint = ?');
        for (const rows of byScan.values()) {
            // The whole scan's rows of the same rules, re-keyed together so each
            // occurrence is counted as a fresh scan would count it.
            const renamed = rows.map((row) => ({
                ...row,
                short: storedLocalRuleId(row.rule_id, row.project_path) ?? row.rule_id,
            }));
            const projectPath = renamed[0]?.project_path;
            const keys = rekeyStoredIdentities(renamed.map((r) => ({
                tool: r.tool,
                rule_id: r.short,
                fingerprint: r.fingerprint,
                ...(r.subcategory !== null ? { subcategory: r.subcategory } : {}),
                ...(r.file_path !== null ? { file_path: r.file_path } : {}),
                ...(r.line_start !== null ? { line_start: r.line_start } : {}),
                ...(r.line_end !== null ? { line_end: r.line_end } : {}),
                ...(r.snippet !== null ? { snippet: r.snippet } : {}),
                ...(r.content_key !== null ? { content_key: r.content_key } : {}),
            })), projectPath);
            renamed.forEach((r, i) => {
                const key = keys[i];
                const fingerprint = computeFingerprint({
                    tool: r.tool,
                    rule_id: r.short,
                    ...(r.file_path !== null ? { file_path: r.file_path } : {}),
                    ...(r.line_start !== null ? { line_start: r.line_start } : {}),
                    ...(r.line_end !== null ? { line_end: r.line_end } : {}),
                    ...(r.snippet !== null ? { snippet: r.snippet } : {}),
                });
                const identity = r.identity === null ? null : (key?.identity ?? null);
                const contentKey = r.content_key === null ? null : (key?.content_key ?? r.content_key);
                if (updateFinding.run(r.short, fingerprint, identity, contentKey, r.rid).changes === 0)
                    return;
                changed += 1;
                if (fingerprint !== r.fingerprint) {
                    moveSuppressionFp.run(fingerprint, r.fingerprint);
                    moveValidation.run(fingerprint, r.fingerprint);
                }
                if (r.identity !== null && identity !== null && identity !== r.identity)
                    moveSuppressionId.run(identity, r.identity);
            });
        }
        db.prepare(`INSERT INTO schema_meta(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`).run(DONE_KEY, '1');
    })();
    return changed;
}
//# sourceMappingURL=localRuleIds.js.map