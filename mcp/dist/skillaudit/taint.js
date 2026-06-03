/**
 * Taint-light: intra-file source→sink detection.
 *
 * Full inter-procedural taint analysis needs a real engine per language.
 * What catches the highest-value case cheaply is co-occurrence within a
 * single file: if a file BOTH reads a secret/credential/sensitive source
 * AND has a network/exec egress sink, that file can exfiltrate. We report it
 * as one `taint` finding citing the source and sink lines, so a human can
 * confirm the flow.
 *
 * This deliberately errs toward signal over proof — it's a "look here"
 * pointer, scored as high (not critical) precisely because it's a
 * co-occurrence heuristic, not a proven data flow.
 *
 * Pure functions. No I/O.
 */
const SOURCES = [
    { id: 'env', re: /\b(process\.env|os\.environ|getenv|ENV\[|System\.getenv)/i },
    { id: 'ssh_key', re: /(id_rsa|id_ed25519|\.ssh\/|PRIVATE KEY-----)/ },
    { id: 'cloud_creds', re: /(\.aws\/credentials|AWS_SECRET|GCP_|AZURE_|\.npmrc|\.netrc)/i },
    { id: 'browser_data', re: /(cookies\.sqlite|Login Data|Local Storage|key4\.db|logins\.json)/i },
    { id: 'token_var', re: /\b[A-Za-z_]*(TOKEN|SECRET|PASSWORD|APIKEY|API_KEY|CREDENTIAL)[A-Za-z_]*\b/ },
    { id: 'fs_read', re: /(readFileSync|fs\.readFile|open\s*\(|Get-Content|cat\s+[^\n]*\/)/ },
];
const SINKS = [
    { id: 'http', re: /\b(fetch|axios|XMLHttpRequest|http[s]?\.request|requests?\.(post|get|put)|urllib|httpx|Invoke-WebRequest|Invoke-RestMethod)\b/i },
    { id: 'curl', re: /\b(curl|wget)\b/i },
    { id: 'socket', re: /(socket\.socket|net\.connect|new\s+WebSocket|\/dev\/tcp\/)/i },
    { id: 'dns', re: /\b(dig|nslookup|resolve4|dns\.lookup)\b/i },
    { id: 'mail', re: /\b(smtplib|sendmail|nodemailer|Send-MailMessage)\b/i },
];
/**
 * Returns at most one TaintFlow per file (the first source paired with the
 * first sink). One finding per file is enough to flag it for review; the
 * pattern/yara passes surface the specific calls.
 */
export function detectTaint(content) {
    const lines = content.split(/\r?\n/);
    const source = locateFirst(lines, SOURCES);
    if (!source)
        return null;
    const sink = locateFirst(lines, SINKS);
    if (!sink)
        return null;
    return {
        source_id: source.id,
        source_line: source.line,
        source_snippet: source.snippet,
        sink_id: sink.id,
        sink_line: sink.line,
        sink_snippet: sink.snippet,
    };
}
function locateFirst(lines, defs) {
    for (let i = 0; i < lines.length; i += 1) {
        const line = lines[i] ?? '';
        for (const def of defs) {
            def.re.lastIndex = 0;
            if (def.re.test(line)) {
                return { id: def.id, line: i + 1, snippet: line.trim().slice(0, 240) };
            }
        }
    }
    return null;
}
//# sourceMappingURL=taint.js.map