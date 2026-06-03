/**
 * Skill-audit orchestrator.
 *
 * Given an ingested target (a list of text files), runs every analysis pass
 * and produces canonical `Finding`s plus the rolled-up risk score and
 * per-category breakdown:
 *
 *   1. Pattern rules     (patterns.ts)      — prompt-level + code-level signals
 *   2. YARA signatures   (yaraSignatures.ts)— known-bad artifacts
 *   3. Taint-light       (taint.ts)         — source→sink within a file
 *   4. Hidden Unicode    (here)             — invisible instruction smuggling
 *   5. MCP manifest      (here)             — least-privilege / tool poisoning
 *   6. Dependencies+OSV  (deps.ts, osv.ts)  — known CVEs in declared deps
 *
 * Every signal becomes a Finding with `category: 'security'` and
 * `subcategory: <ThreatCategory>` so it flows through the existing storage,
 * scoring, reporting and resource surfaces unchanged. The install
 * recommendation comes from `score.ts`.
 */
import { makeFinding } from '../runners/scannerParsers/index.js';
import { queryOsv } from '../runners/osv.js';
import { extractDependencies } from './deps.js';
import { scanContent, severityOfRule } from './patterns.js';
import { scoreFindings } from './score.js';
import { detectTaint } from './taint.js';
import { THREAT_CATEGORIES } from './taxonomy.js';
import { matchSignatures } from './yaraSignatures.js';
const TOOL = 'guardian-scanskill';
export async function analyzeSkill(files, opts = {}) {
    const findings = [];
    const signals = [];
    let executableFiles = 0;
    let hiddenUnicodeFiles = 0;
    const push = (f, isExecutable) => {
        findings.push(f);
        signals.push({ severity: f.severity, isExecutable });
    };
    for (const file of files) {
        if (file.isExecutable)
            executableFiles += 1;
        // 1. Pattern rules.
        for (const m of scanContent(file.content, file.isCode)) {
            const sev = severityOfRule(m.rule);
            push(makeFinding({
                tool: TOOL,
                rule_id: m.rule.id,
                severity: sev,
                category: 'security',
                subcategory: m.rule.category,
                title: m.rule.title,
                message: m.rule.message,
                file_path: file.relPath,
                line_start: m.line,
                line_end: m.line,
                snippet: m.snippet,
            }), file.isExecutable);
        }
        // 2. YARA signatures.
        for (const m of matchSignatures(file.content)) {
            push(makeFinding({
                tool: TOOL,
                rule_id: m.signature.id,
                severity: m.signature.severity,
                category: 'security',
                subcategory: m.signature.category,
                title: m.signature.title,
                message: m.signature.description,
                file_path: file.relPath,
                line_start: m.line,
                line_end: m.line,
                snippet: m.snippet,
            }), file.isExecutable);
        }
        // 3. Taint-light (code files only).
        if (file.isCode || file.isExecutable) {
            const flow = detectTaint(file.content);
            if (flow) {
                push(makeFinding({
                    tool: TOOL,
                    rule_id: 'taint-source-to-sink',
                    severity: 'high',
                    category: 'security',
                    subcategory: 'taint',
                    title: `Possible exfiltration flow: ${flow.source_id} → ${flow.sink_id}`,
                    message: `Source (${flow.source_id}) at line ${flow.source_line} co-occurs with a network/exec sink ` +
                        `(${flow.sink_id}) at line ${flow.sink_line} in the same file. Confirm the data flow.`,
                    file_path: file.relPath,
                    line_start: flow.source_line,
                    line_end: flow.sink_line,
                    snippet: flow.sink_snippet,
                }), file.isExecutable);
            }
        }
        // 4. Hidden Unicode.
        const hidden = findHiddenUnicode(file.content);
        if (hidden) {
            hiddenUnicodeFiles += 1;
            push(makeFinding({
                tool: TOOL,
                rule_id: 'ra-hidden-unicode',
                severity: 'high',
                category: 'security',
                subcategory: 'rogue_agent',
                title: 'Hidden / invisible Unicode characters',
                message: `Invisible code point(s) found (e.g. U+${hidden.code.toString(16).toUpperCase()}). ` +
                    'Zero-width / tag characters are a channel for instructions invisible to humans but read by the model.',
                file_path: file.relPath,
                line_start: hidden.line,
                line_end: hidden.line,
                snippet: `<invisible code point U+${hidden.code.toString(16).toUpperCase()}>`,
            }), file.isExecutable);
        }
        // 5. MCP manifest checks.
        for (const f of analyzeMcpManifest(file))
            push(f, file.isExecutable);
    }
    // 6. Dependencies → OSV.
    let osv = null;
    if (opts.checkDeps !== false) {
        const deps = extractDependencies(files.map((f) => ({ relPath: f.relPath, content: f.content })));
        if (deps.length > 0) {
            const osvOpts = {};
            if (opts.signal)
                osvOpts.signal = opts.signal;
            osv = await queryOsv(deps, osvOpts);
            for (const grp of osv.vulnerable_packages) {
                push(makeFinding({
                    tool: TOOL,
                    rule_id: 'osv-vulnerable-dependency',
                    severity: grp.severity,
                    category: 'security',
                    subcategory: 'supply_chain',
                    title: `Vulnerable dependency: ${grp.name}${grp.version ? `@${grp.version}` : ''}`,
                    message: `OSV reports ${grp.vuln_ids.length} known vulnerabilit${grp.vuln_ids.length === 1 ? 'y' : 'ies'} ` +
                        `for ${grp.ecosystem} package ${grp.name}: ${grp.vuln_ids.slice(0, 8).join(', ')}.`,
                    file_path: grp.name,
                }), false);
            }
        }
    }
    const category_breakdown = emptyBreakdown();
    for (const f of findings) {
        const cat = f.subcategory;
        if (cat && cat in category_breakdown)
            category_breakdown[cat] += 1;
    }
    return {
        findings,
        score: scoreFindings(signals),
        category_breakdown,
        osv,
        files_scanned: files.length,
        executable_files: executableFiles,
        hidden_unicode_files: hiddenUnicodeFiles,
    };
}
function emptyBreakdown() {
    const out = {};
    for (const c of THREAT_CATEGORIES)
        out[c] = 0;
    return out;
}
/** First invisible code point + its line, or null. */
function findHiddenUnicode(content) {
    const lines = content.split(/\r?\n/);
    for (let i = 0; i < lines.length; i += 1) {
        const line = lines[i] ?? '';
        for (const ch of line) {
            const code = ch.codePointAt(0);
            if (isInvisible(code))
                return { code, line: i + 1 };
        }
    }
    return null;
}
function isInvisible(code) {
    return ((code >= 0x200b && code <= 0x200f) || // zero-width space/joiner/non-joiner + LRM/RLM
        (code >= 0x202a && code <= 0x202e) || // bidi overrides
        (code >= 0x2060 && code <= 0x2064) || // word joiner / invisible operators
        code === 0xfeff || // BOM / zero-width no-break space
        (code >= 0xe0000 && code <= 0xe007f) // Unicode tag block
    );
}
/**
 * MCP-specific manifest checks: least-privilege (over-broad declared
 * capability) and tool poisoning (instructions hidden in tool descriptions).
 * Only runs on JSON manifests that actually look like MCP configs.
 */
function analyzeMcpManifest(file) {
    const name = file.relPath.split('/').pop()?.toLowerCase() ?? '';
    const looksMcp = /mcp.*\.json$/.test(name) ||
        name === 'plugin.json' ||
        /"mcpservers"\s*:/i.test(file.content) ||
        (/"command"\s*:/.test(file.content) && /"args"\s*:/.test(file.content) && name.endsWith('.json'));
    if (!looksMcp)
        return [];
    const out = [];
    let json;
    try {
        json = JSON.parse(file.content);
    }
    catch {
        json = null;
    }
    // Least privilege: wildcard scopes/permissions.
    if (/"(permissions|scopes|allowedTools|capabilities)"\s*:\s*(\[[^\]]*"(\*|all)"|"(\*|all)")/i.test(file.content)) {
        out.push(finding(file, 'mcp-wildcard-scope', 'medium', 'mcp_least_privilege', 'MCP manifest grants wildcard scope', 'The manifest declares "*"/"all" permissions or capabilities — far broader than any single purpose needs.'));
    }
    // Tool poisoning: hidden directives inside tool descriptions.
    const desc = collectDescriptions(json);
    for (const d of desc) {
        if (/(ignore\s+(previous|all)|do\s+not\s+(tell|mention|inform)|system\s+prompt|<important>|<secret>|<system>)/i.test(d)) {
            out.push(finding(file, 'mcp-tool-description-poisoning', 'high', 'mcp_tool_poisoning', 'Hidden instructions in MCP tool description', 'A tool description embeds directives that manipulate the model when the host loads the tool list.'));
            break;
        }
    }
    return out;
}
function collectDescriptions(json, acc = []) {
    if (!json || typeof json !== 'object')
        return acc;
    if (Array.isArray(json)) {
        for (const item of json)
            collectDescriptions(item, acc);
        return acc;
    }
    for (const [key, value] of Object.entries(json)) {
        if ((key === 'description' || key === 'name' || key === 'instructions') && typeof value === 'string') {
            acc.push(value);
        }
        else if (value && typeof value === 'object') {
            collectDescriptions(value, acc);
        }
    }
    return acc;
}
function finding(file, ruleId, severity, subcategory, title, message) {
    return makeFinding({
        tool: TOOL,
        rule_id: ruleId,
        severity,
        category: 'security',
        subcategory,
        title,
        message,
        file_path: file.relPath,
        line_start: 1,
    });
}
//# sourceMappingURL=analyze.js.map