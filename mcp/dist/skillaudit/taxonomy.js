/**
 * AI-agent skill threat taxonomy.
 *
 * dev-guardian's answer to "is this skill / MCP server / agent safe to
 * INSTALL?" — the supply-chain question for the agent ecosystem, distinct
 * from the rest of the suite which asks "is MY code safe to SHIP?".
 *
 * The 16 categories below mirror the threat model the field has converged
 * on for agentic AI artifacts (prompt injection, exfiltration, excessive
 * agency, MCP tool poisoning, …). Every rule in `patterns.ts`,
 * `yaraSignatures.ts` and `taint.ts` maps to exactly one of these keys, and
 * the scorer in `score.ts` rolls them up into a single 0–100 risk number
 * plus an install recommendation.
 *
 * Pure data + pure functions: no I/O, no time, no global state.
 */
export const THREAT_CATEGORIES = [
    'prompt_injection',
    'data_exfiltration',
    'privilege_escalation',
    'supply_chain',
    'excessive_agency',
    'output_handling',
    'system_prompt_leakage',
    'memory_poisoning',
    'tool_misuse',
    'rogue_agent',
    'trigger_abuse',
    'dangerous_code',
    'taint',
    'yara',
    'mcp_least_privilege',
    'mcp_tool_poisoning',
];
export const THREAT_CATEGORY_META = {
    prompt_injection: {
        key: 'prompt_injection',
        label: 'Prompt injection',
        description: 'Instructions embedded in the skill that try to override the host, ignore prior rules, or hijack the model.',
        defaultSeverity: 'high',
    },
    data_exfiltration: {
        key: 'data_exfiltration',
        label: 'Data exfiltration',
        description: 'Code or instructions that send local data (env, files, history, keys) to an external destination.',
        defaultSeverity: 'critical',
    },
    privilege_escalation: {
        key: 'privilege_escalation',
        label: 'Privilege escalation',
        description: 'Attempts to gain elevated rights — sudo, chmod 777, writing to system paths, disabling protections.',
        defaultSeverity: 'high',
    },
    supply_chain: {
        key: 'supply_chain',
        label: 'Supply chain',
        description: 'Untrusted installs / fetch-and-run, pinned-to-HEAD deps, curl|bash, post-install hooks, typosquats.',
        defaultSeverity: 'high',
    },
    excessive_agency: {
        key: 'excessive_agency',
        label: 'Excessive agency',
        description: 'The skill grants itself broad, unscoped capability — autonomous loops, self-modification, unattended destructive ops.',
        defaultSeverity: 'medium',
    },
    output_handling: {
        key: 'output_handling',
        label: 'Output handling',
        description: 'Untrusted output rendered/executed without sanitisation — HTML/JS injection, eval of model output, command echo.',
        defaultSeverity: 'medium',
    },
    system_prompt_leakage: {
        key: 'system_prompt_leakage',
        label: 'System prompt leakage',
        description: 'Instructions designed to extract or reveal the host system prompt, hidden instructions, or other skills.',
        defaultSeverity: 'medium',
    },
    memory_poisoning: {
        key: 'memory_poisoning',
        label: 'Memory poisoning',
        description: 'Attempts to write durable, attacker-controlled content into agent memory / rules files / CLAUDE.md so it persists.',
        defaultSeverity: 'high',
    },
    tool_misuse: {
        key: 'tool_misuse',
        label: 'Tool misuse',
        description: 'Legitimate tools driven toward harm — shell from a "formatter", network from a "linter", file writes from a "reader".',
        defaultSeverity: 'medium',
    },
    rogue_agent: {
        key: 'rogue_agent',
        label: 'Rogue agent behaviour',
        description: 'Hidden second agenda — conditional/time-bombed behaviour, hidden Unicode, instructions only the model sees.',
        defaultSeverity: 'high',
    },
    trigger_abuse: {
        key: 'trigger_abuse',
        label: 'Trigger abuse',
        description: 'Over-broad / deceptive activation: trigger phrases or descriptions crafted to fire on unrelated requests.',
        defaultSeverity: 'medium',
    },
    dangerous_code: {
        key: 'dangerous_code',
        label: 'Dangerous code',
        description: 'Directly dangerous calls — eval/exec, subprocess with shell=True, deserialisation, dynamic import of remote code.',
        defaultSeverity: 'high',
    },
    taint: {
        key: 'taint',
        label: 'Taint flow',
        description: 'A source→sink data flow within one file: reads a secret/credential AND has a network egress in the same unit.',
        defaultSeverity: 'high',
    },
    yara: {
        key: 'yara',
        label: 'Signature match',
        description: 'A byte/string signature for known-bad artifacts — obfuscation blobs, known C2 hosts, encoded payloads.',
        defaultSeverity: 'high',
    },
    mcp_least_privilege: {
        key: 'mcp_least_privilege',
        label: 'MCP least privilege',
        description: 'An MCP server declaring far broader scopes/capabilities than its stated purpose needs.',
        defaultSeverity: 'medium',
    },
    mcp_tool_poisoning: {
        key: 'mcp_tool_poisoning',
        label: 'MCP tool poisoning',
        description: 'Hidden instructions inside MCP tool names/descriptions/schemas that manipulate the model when the tool list is read.',
        defaultSeverity: 'high',
    },
};
/** Install recommendation bands, mirroring the field-standard 0–100 split. */
export const RECOMMENDATIONS = [
    'SAFE',
    'REVIEW',
    'CAUTION',
    'DO_NOT_INSTALL',
];
export const RECOMMENDATION_BANDS = [
    { recommendation: 'SAFE', min: 0, max: 20 },
    { recommendation: 'REVIEW', min: 21, max: 35 },
    { recommendation: 'CAUTION', min: 36, max: 50 },
    { recommendation: 'DO_NOT_INSTALL', min: 51, max: 100 },
];
export function recommendationFor(score) {
    const clamped = Math.max(0, Math.min(100, score));
    for (const band of RECOMMENDATION_BANDS) {
        if (clamped >= band.min && clamped <= band.max)
            return band.recommendation;
    }
    return 'DO_NOT_INSTALL';
}
/** Per-severity points contributed to the risk score (field-standard weights). */
export const SEVERITY_POINTS = {
    critical: 50,
    high: 25,
    medium: 10,
    low: 5,
    info: 0,
};
/**
 * Findings in executable artifacts (scripts that actually run) weigh more
 * than the same pattern in inert docs — a malicious instruction in a README
 * still needs the model to act, but a malicious line in `install.sh` runs.
 */
export const EXECUTABLE_MULTIPLIER = 1.3;
//# sourceMappingURL=taxonomy.js.map