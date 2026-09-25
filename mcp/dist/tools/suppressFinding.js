/**
 * `suppress_finding` — mark a finding as a false positive.
 *
 * Pure SQL: inserts a row in `suppressions`. While the row is active
 * (NULL `expires_at`, or `expires_at` in the future), the matching
 * finding is hidden from `findings/open` and `findings/by-severity/*`
 * resources. Historical scan records are untouched.
 *
 * The caller names the finding by fingerprint — the key every scan response
 * shows — but the fingerprint hashes the line numbers, so a suppression that
 * stored only that lapsed the moment a line was inserted above the finding.
 * The row therefore also records the finding's line-independent `identity`,
 * looked up from the newest scan that reported the fingerprint, and hides a
 * finding that matches either. A fingerprint no stored scan carries an
 * identity for (a row from before schema 7, or a tool that computes none) is
 * still suppressed by fingerprint alone, and the response says so.
 */
import { z } from 'zod';
import { registerToolModule } from './index.js';
const inputSchema = {
    finding_fingerprint: z
        .string()
        .regex(/^[0-9a-f]{64}$/)
        .describe('SHA-256 fingerprint of the finding to suppress (from a previous scan response).'),
    reason: z
        .string()
        .min(1)
        .max(1000)
        .describe('Why this finding is being suppressed. Required.'),
    expires_at: z
        .string()
        .datetime()
        .optional()
        .describe('ISO-8601 expiry. When omitted, the suppression never expires.'),
};
const tool = {
    name: 'suppress_finding',
    title: 'Suppress finding',
    description: 'Mark a finding (by the fingerprint a scan response shows) as a false positive. Resources that ' +
        'surface open findings exclude it while the suppression is active — including after the code ' +
        "around it moves: the finding's line-independent identity is recorded alongside the fingerprint " +
        'and either one matches. Pass expires_at for a temporary snooze.',
    inputSchema,
    handler: async (input, ctx) => handler(input, ctx),
};
registerToolModule(tool);
async function handler(input, ctx) {
    const inp = input;
    if (!inp.finding_fingerprint || !inp.reason) {
        return failDomain('unknown_scan_id', 'finding_fingerprint and reason are required.');
    }
    const identity = ctx.storage.findings.identityForFingerprint(inp.finding_fingerprint);
    const id = ctx.storage.suppressions.insert({
        finding_fingerprint: inp.finding_fingerprint,
        ...(identity !== null ? { finding_identity: identity } : {}),
        reason: inp.reason,
        ...(inp.expires_at !== undefined ? { expires_at: inp.expires_at } : {}),
        created_by: 'user',
    });
    return {
        ok: true,
        suppression_id: id,
        finding_fingerprint: inp.finding_fingerprint,
        // Null: no stored scan has an identity for this fingerprint, so the
        // suppression matches it by fingerprint only and lapses if lines shift.
        finding_identity: identity,
        expires_at: inp.expires_at ?? null,
    };
}
function failDomain(code, message) {
    return { ok: false, error: { code, message } };
}
//# sourceMappingURL=suppressFinding.js.map