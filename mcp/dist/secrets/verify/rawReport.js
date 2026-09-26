/**
 * The one place a raw secret value is read from disk — for
 * `scan_secrets verify_live`, and only there.
 *
 * Every other gitleaks run in this codebase uses `--redact`, and the parser
 * strips `Match`/`Secret` besides. Verification needs the value itself, so a
 * verifying run omits `--redact` — but ONLY into a report file inside a
 * private directory made for that one scan:
 *
 *   - `mkdtemp` under the OS temp directory; on POSIX the directory is 0700
 *     and each report file is created 0600 BEFORE gitleaks writes it (gitleaks
 *     truncates an existing file and keeps its mode). On Windows the
 *     per-user temp directory (`%LOCALAPPDATA%\Temp`) is the protection: its
 *     ACL admits only the user, SYSTEM and Administrators, and POSIX mode
 *     bits mean nothing there.
 *   - Each raw report is read once, by {@link sanitizeGitleaksReport}, and
 *     deleted straight after; the directory is removed when the scan's
 *     gitleaks passes are done (`runners/gitleaksScan.ts`, in `finally`).
 *   - What the rest of the scan sees — the parser input, the report kept
 *     under `.guardian/reports` — is the sanitized text: every raw value, of
 *     every rule, replaced by `REDACTED`, exactly as `--redact` would have
 *     left it. Only the values of rules `verify_live` can check survive, in
 *     memory, aligned with the report's items.
 */
import { chmodSync, closeSync, mkdtempSync, openSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
/** What gitleaks `--redact` writes in place of a value. */
export const REDACTED = 'REDACTED';
const POSIX = process.platform !== 'win32';
/** See the module comment. Throws when no private directory can be made — the caller then does not capture. */
export function openPrivateReportDir() {
    const dir = mkdtempSync(join(tmpdir(), 'guardian-verify-'));
    // mkdtemp already creates 0700 on POSIX; stated, not assumed.
    if (POSIX)
        chmodSync(dir, 0o700);
    return {
        dir,
        pathFor(name) {
            const path = join(dir, name);
            closeSync(openSync(path, 'w', 0o600));
            if (POSIX)
                chmodSync(path, 0o600);
            return path;
        },
        remove() {
            try {
                rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
                return null;
            }
            catch (e) {
                const code = typeof e === 'object' && e !== null ? e.code : undefined;
                return typeof code === 'string' ? code : 'unknown error';
            }
        },
    };
}
/**
 * Split an unredacted gitleaks report into its sanitized text and the raw
 * values of the rules `keep` accepts. Null when the text is not a JSON array
 * — it is then never passed on or written anywhere, since it may hold raw
 * values in a shape this cannot clean.
 */
export function sanitizeGitleaksReport(text, keep) {
    let root;
    try {
        root = JSON.parse(text);
    }
    catch {
        return null;
    }
    if (!Array.isArray(root))
        return null;
    const values = new Set();
    const secrets = root.map((item) => {
        const secret = stringField(item, 'Secret');
        if (secret === null || secret.length === 0)
            return null;
        values.add(secret);
        const rule = stringField(item, 'RuleID');
        return rule !== null && keep(rule) ? secret : null;
    });
    // Longest first, so a value that contains another is replaced whole.
    const needles = [...values].sort((a, b) => b.length - a.length);
    const scrub = (v) => {
        if (typeof v === 'string')
            return needles.reduce((acc, n) => acc.split(n).join(REDACTED), v);
        if (Array.isArray(v))
            return v.map(scrub);
        if (isRecord(v))
            return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, scrub(x)]));
        return v;
    };
    const clean = root.map((item) => {
        const c = scrub(item);
        if (!isRecord(c))
            return c;
        const hadValue = stringField(item, 'Secret');
        // With no value to find, what the rule matched cannot be cleaned: withheld.
        if (hadValue === null || hadValue.length === 0) {
            if ('Match' in c)
                c['Match'] = REDACTED;
        }
        if ('Secret' in c)
            c['Secret'] = REDACTED;
        return c;
    });
    return { text: JSON.stringify(clean), secrets };
}
function isRecord(v) {
    return typeof v === 'object' && v !== null && !Array.isArray(v);
}
function stringField(v, key) {
    if (!isRecord(v))
        return null;
    const x = v[key];
    return typeof x === 'string' ? x : null;
}
//# sourceMappingURL=rawReport.js.map