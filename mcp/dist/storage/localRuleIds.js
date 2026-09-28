/**
 * Re-key stored plugin-pack findings to the rule's own id — at startup,
 * resumably, and again for rows written since.
 *
 * Until fix round 2 the Semgrep parser stored a rule of the plugin's own
 * packs (`configs/semgrep/*.yml`: bug_hunt's bugfix packs, compliance_check's
 * RGPD pack) under the id Semgrep reports: the dotted absolute path of the
 * plugin's install plus the rule's id (`runners/semgrepRuleIds.ts`). Every
 * version installs elsewhere, and `rule_id` is hashed into the fingerprint
 * AND the identity. The parser now stores the pack rule's own id; without
 * this step every such finding stored before it would stop matching the same
 * finding re-found after it — suppressions stop applying, the open set holds
 * both, a diff reports one new plus one resolved.
 *
 * So each stored Semgrep finding whose `rule_id` is recognisably one of the
 * plugin's pack rules under an install of this plugin
 * (`pluginPackIdMatcher`: the plugin's root or a sibling version directory,
 * and a rule id its packs declare) gets:
 *   - the pack rule's own id;
 *   - the fingerprint a fresh scan computes for it — except for a credential
 *     finding, whose stored snippet is the redaction placeholder (its
 *     identity, which never used the snippet, still matches);
 *   - the identity a fresh scan computes (`rekeyStoredIdentities`: the stored
 *     content key, the occurrence recounted within the scan);
 * and every suppression and cached validation naming the old fingerprint or
 * identity follows it. Nothing else is touched (fix round 3, I-2): a
 * project's own rules are stored as scans run from the project always stored
 * them, and a rule file elsewhere keeps Semgrep's own id — so two distinct
 * rules are never merged. A project that contains the plugin's packs (the
 * plugin's own repository) is left alone: there its packs are project files.
 * A row whose new fingerprint would collide with another row of the same scan
 * keeps its old one (`UPDATE OR IGNORE`).
 *
 * ---- Resumable and incremental (fix round 3, M-2) ---------------------
 *
 * Scans are walked in rowid order, a bounded batch per transaction, and each
 * batch commits with the rowid it reached (`schema_meta`,
 * {@link WATERMARK_KEY}). A start that is killed keeps every batch it
 * committed; the next start carries on from there. Later starts look only at
 * scans written since — rows an older plugin process sharing the database
 * wrote with the old ids are re-keyed then — so a start with nothing new
 * costs one indexed query. The walk stops before a scan still `running`: its
 * findings may not all be in yet — unless its owner is gone, by the reaper's
 * own rule (`scansRepo.ts#runningScanIsOrphan`): that scan will never be
 * finished, and the reaper, which runs after the database is opened, has not
 * failed it yet. Waiting on it held the re-key back a whole start (round 3's
 * review, M-1). Changes values, never the schema.
 *
 * `.guardian/baseline.json` is not touched and needs nothing: it never holds
 * a plugin-pack finding (`dev-guardian scan` runs no plugin pack), and the
 * ids of a project's own rules did not change.
 */
import path from 'node:path';
import { computeFingerprint } from '../fingerprint/findingFingerprint.js';
import { rekeyStoredIdentities } from '../fingerprint/findingIdentity.js';
import { pluginPackIdMatcher, pluginPacksDir, ruleIdsInDir } from '../runners/semgrepRuleIds.js';
import { runningScanIsOrphan } from './scansRepo.js';
/** The last `scans.rowid` whose findings the re-key has looked at. */
export const WATERMARK_KEY = 'local_rule_ids_rekey_rowid';
/** Scans per committed batch. */
const BATCH_SCANS = 50;
function readWatermark(db) {
    const row = db.prepare('SELECT value FROM schema_meta WHERE key = ?').get(WATERMARK_KEY);
    const n = row === undefined ? 0 : Number(row.value);
    return Number.isFinite(n) && n > 0 ? n : 0;
}
/** Whether the plugin's pack directory lies inside `projectPath` (the plugin's own repository). */
function containsPacks(projectPath, packsDir) {
    const fp = /^([A-Za-z]:[\\/]|[\\/]{2})/.test(packsDir) ? path.win32 : path.posix;
    const rel = fp.relative(projectPath, packsDir);
    return rel === '' || !(rel === '..' || rel.startsWith(`..${fp.sep}`) || rel.startsWith('../') || fp.isAbsolute(rel));
}
/** Re-keys the plugin-pack findings of every scan past the watermark; returns how many rows changed. */
export function rekeyStoredLocalRuleIds(db, opts = {}) {
    const packsDir = opts.packsDir ?? pluginPacksDir();
    const batchScans = opts.batchScans ?? BATCH_SCANS;
    let matcher = null;
    const matcherNow = () => {
        matcher ??= pluginPackIdMatcher(packsDir, opts.packRuleIds ?? ruleIdsInDir(packsDir));
        return matcher;
    };
    const nextScans = db.prepare('SELECT rowid AS rid, id, project_path, status, started_at, owner_pid, owner_host FROM scans WHERE rowid > ? ORDER BY rowid LIMIT ?');
    // This process has started no scan yet, but it is alive: its own pid is
    // judged like any other, never taken as a dead owner's.
    const reap = { ownPid: -1, ...opts.reap };
    let changed = 0;
    let batches = 0;
    let watermark = readWatermark(db);
    for (;;) {
        const page = nextScans.all(watermark, batchScans);
        const running = page.findIndex((s) => s.status === 'running' && !runningScanIsOrphan(s, reap));
        const scans = running < 0 ? page : page.slice(0, running);
        const last = scans[scans.length - 1];
        if (last === undefined)
            break;
        const candidates = scans.filter((s) => !containsPacks(s.project_path, packsDir)).map((s) => s.id);
        const rows = candidates.length === 0
            ? []
            : db
                .prepare(`SELECT rowid AS rid, scan_id, fingerprint, tool, rule_id, subcategory, file_path, line_start, line_end,
                      snippet, identity, content_key
                 FROM findings
                WHERE scan_id IN (${candidates.map(() => '?').join(', ')})
                  AND lower(tool) = 'semgrep' AND rule_id LIKE '%.configs.semgrep.%'`)
                .all(...candidates);
        db.transaction(() => {
            // Another process may have got here first.
            if (readWatermark(db) >= last.rid)
                return;
            if (rows.length > 0)
                changed += rekeyRows(db, rows, matcherNow(), new Map(scans.map((s) => [s.id, s.project_path])));
            db.prepare(`INSERT INTO schema_meta(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`).run(WATERMARK_KEY, String(last.rid));
        })();
        watermark = last.rid;
        batches += 1;
        opts.afterBatch?.(batches);
        if (running >= 0 || page.length < batchScans)
            break;
    }
    return changed;
}
/** Re-keys `rows` (candidate rows of some scans) in place; returns how many changed. */
function rekeyRows(db, rows, match, projectOf) {
    const byScan = new Map();
    for (const row of rows) {
        const short = match(row.rule_id);
        if (short === null)
            continue;
        const list = byScan.get(row.scan_id) ?? [];
        list.push({ ...row, short });
        byScan.set(row.scan_id, list);
    }
    const updateFinding = db.prepare('UPDATE OR IGNORE findings SET rule_id = ?, fingerprint = ?, identity = ?, content_key = ? WHERE rowid = ?');
    const moveSuppressionFp = db.prepare('UPDATE suppressions SET finding_fingerprint = ? WHERE finding_fingerprint = ?');
    const moveSuppressionId = db.prepare('UPDATE suppressions SET finding_identity = ? WHERE finding_identity = ?');
    const moveValidation = db.prepare('UPDATE OR IGNORE finding_validations SET fingerprint = ? WHERE fingerprint = ?');
    // Nothing to follow the rows when nothing names them (the common case):
    // three statements per row fewer.
    const hasSuppressions = db.prepare('SELECT 1 AS n FROM suppressions LIMIT 1').get() !== undefined;
    const hasValidations = db.prepare('SELECT 1 AS n FROM finding_validations LIMIT 1').get() !== undefined;
    let changed = 0;
    for (const [scanId, renamed] of byScan) {
        // One scan's rows of the same rules, re-keyed together so each
        // occurrence is counted as a fresh scan would count it.
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
        })), projectOf.get(scanId));
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
                if (hasSuppressions)
                    moveSuppressionFp.run(fingerprint, r.fingerprint);
                if (hasValidations)
                    moveValidation.run(fingerprint, r.fingerprint);
            }
            if (hasSuppressions && r.identity !== null && identity !== null && identity !== r.identity) {
                moveSuppressionId.run(identity, r.identity);
            }
        });
    }
    return changed;
}
//# sourceMappingURL=localRuleIds.js.map