/**
 * `scan_secrets verify_live` — the step between gitleaks and the scan-tool
 * factory.
 *
 * gitleaks has run (`runners/gitleaksScan.ts` with `captureSecrets`): its
 * parser inputs are sanitized reports, and the raw values of the verifiable
 * rules sit in memory, aligned with each report's items. This:
 *
 *   1. parses each item the way the factory will, and verifies only the
 *      findings the scan KEEPS — a secret `.guardianignore` excludes, or one
 *      outside the scope, is dropped from the scan anyway and is never sent;
 *   2. verifies the distinct values (`verify.ts`: bounded, deduplicated);
 *   3. returns the parser inputs with each item's verdict applied
 *      (`apply.ts`), a summary for the result and the scan row, and warnings;
 *   4. clears the raw values it was given, whatever happened.
 *
 * Nothing it returns holds a raw value: the verdicts' reasons are built from
 * constants (see `verify.ts`), and the summary names findings by
 * fingerprint, rule, path and line.
 */
import { parseInputAsJson } from '../../runners/scannerParsers/index.js';
import { withSecretChecks } from './apply.js';
import { PROVIDERS } from './providers.js';
import { DEFAULT_MAX_SECRETS, unsentCheck, verifySecrets, } from './verify.js';
export { isVerifiableRule } from './providers.js';
export { OFFLINE_REASON } from './verify.js';
const MAX_RECORDS = 200;
export async function verifyGitleaksFindings(input) {
    const ctx = { project_path: input.projectPath };
    const candidates = [];
    try {
        const perEntry = [];
        const pending = [];
        input.parser_inputs.forEach((task, e) => {
            const root = parseInputAsJson(task.input);
            const values = input.secrets?.get(task) ?? null;
            const items = [];
            if (Array.isArray(root)) {
                root.forEach((raw, i) => {
                    const finding = task.parser.parse([raw], ctx).findings[0];
                    // Positions must stay aligned with the report even for an item
                    // that yields no finding; it simply gets no check.
                    if (finding === undefined) {
                        items.push({ finding: null, check: null });
                        return;
                    }
                    const rule = finding.rule_id;
                    if (rule === undefined || !input.keep(finding)) {
                        items.push({ finding, check: null });
                        return;
                    }
                    if (input.unavailable !== null) {
                        items.push({ finding, check: unsentCheck(rule, `not verified: ${input.unavailable}`) });
                        return;
                    }
                    const value = values?.[i] ?? null;
                    if (value === null) {
                        // No value captured means no verifier wanted it (or gitleaks gave none).
                        items.push({ finding, check: unsentCheck(rule, 'not verified: gitleaks reported no value for it') });
                        return;
                    }
                    pending.push({ entry: e, item: i, candidate: candidates.length });
                    candidates.push({ rule, secret: value });
                    items.push({ finding, check: null });
                });
            }
            perEntry.push({ task, items });
        });
        const results = await verifySecrets(candidates, input.options);
        for (const p of pending) {
            const slot = perEntry[p.entry]?.items[p.item];
            const check = results[p.candidate];
            if (slot !== undefined && check !== undefined)
                slot.check = check;
        }
        const parser_inputs = perEntry.map(({ task, items }) => items.some((x) => x.check !== null)
            ? { parser: withSecretChecks(task.parser, items.map((x) => x.check)), input: task.input }
            : task);
        const checked = perEntry.flatMap(({ items }) => items.flatMap((x) => (x.check === null || x.finding === null ? [] : [{ finding: x.finding, check: x.check }])));
        const summary = summarize(checked);
        return { parser_inputs, summary, warnings: warningsFor(summary, input.unavailable) };
    }
    finally {
        // The raw values live exactly as long as this call.
        for (const c of candidates)
            c.secret = '';
        candidates.length = 0;
        discardCaptured(input.secrets);
    }
}
/**
 * Let go of what gitleaks captured: every array nulled in place (a caller
 * may still hold a reference to one) and the map emptied. The one way the raw
 * values are dropped — after verification, and on a cancelled scan that never
 * got there.
 */
export function discardCaptured(captured) {
    if (captured === null || captured === undefined)
        return;
    for (const values of captured.values())
        values.fill(null);
    captured.clear();
}
function summarize(checked) {
    const count = (v) => checked.filter((c) => c.check.verdict === v).length;
    const sent = checked.filter((c) => c.check.sent);
    const records = [];
    for (const { finding, check } of checked) {
        if (check.verdict === 'skipped')
            continue;
        const record = {
            fingerprint: finding.fingerprint,
            rule_id: finding.rule_id ?? '',
            provider: check.provider,
            host: check.host,
            verified: check.verdict,
            reason: check.reason,
        };
        if (finding.file_path !== undefined)
            record.file_path = finding.file_path;
        if (finding.line_start !== undefined)
            record.line_start = finding.line_start;
        records.push(record);
    }
    const summary = {
        verified: sent.length,
        live: count('live'),
        revoked: count('revoked'),
        unknown: count('unknown'),
        skipped: count('skipped'),
        // One check object answers every finding that holds the same value.
        distinct_secrets_sent: new Set(sent.map((c) => c.check)).size,
        distinct_secrets_over_limit: new Set(checked.filter((c) => c.check.overLimit === true).map((c) => c.check)).size,
        limit: DEFAULT_MAX_SECRETS,
        hosts_contacted: [...new Set(sent.flatMap((c) => (c.check.host === null ? [] : [c.check.host])))].sort(),
        verifiable_rules: PROVIDERS.flatMap((p) => p.rules),
        findings: records.slice(0, MAX_RECORDS),
    };
    if (records.length > MAX_RECORDS)
        summary.findings_not_listed = records.length - MAX_RECORDS;
    return summary;
}
function warningsFor(s, unavailable) {
    const out = [];
    if (s.live > 0) {
        out.push(`⚠️ verify_live: ${s.live} secret finding(s) are LIVE — the credential authenticated with its provider. ` +
            'Rotate each now (its message says where); severity raised to critical.');
    }
    if (unavailable !== null) {
        out.push(`verify_live: nothing was verified — ${unavailable}.`);
    }
    if (s.distinct_secrets_over_limit > 0) {
        out.push(`verify_live: the per-scan limit of ${s.limit} distinct secrets was reached — ${s.distinct_secrets_over_limit} ` +
            'more were not sent and their findings are unknown. Narrow the scan with scope to verify the rest.');
    }
    out.push(`verify_live: ${s.distinct_secrets_sent} distinct secret(s) sent, each only to its own provider's API` +
        `${s.hosts_contacted.length > 0 ? ` (${s.hosts_contacted.join(', ')})` : ''}. Findings: ${s.live} live, ` +
        `${s.revoked} revoked, ${s.unknown} unknown, ${s.skipped} skipped (no verifier for the rule).`);
    return out;
}
//# sourceMappingURL=index.js.map