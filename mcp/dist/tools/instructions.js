/**
 * The MCP `instructions` this server sends at initialize — what a host with
 * no rules file (or a truncated one) still tells the model about the tools as
 * a whole: which family serves which job, how to read a result, and the
 * rules whose breach costs the user something. Hosts put them in the system
 * prompt, so they are counted in the `tools/list` budget
 * (`descriptionLimits.test.ts`) and kept to about 800 characters; the host
 * rules template (`hostsetup/rulesTemplate.ts`) says the same at length.
 */
export const SERVER_INSTRUCTIONS = [
    'dev-guardian runs open-source scanners locally and keeps their history (baselines, diffs, suppressions). Use its tools, not the scanners in a shell.',
    'Whole project: security_scan_full; a diff: review_pr or a scan with scope; bugs: bug_hunt; deps: deps_audit, and vet_packages before an install; WordPress: scan_wordpress, wp_*; .NET: dotnet_check; history: diff_scans, prioritize_findings, health_status.',
    'A scanner that did not run is a gap, never 0 findings: read tools_run, missing_tools and coverage first.',
    'Never run db adopt for the user. Never run baseline update to accept one finding: it accepts all of them.',
    'create_fix_pr: dry run first. Ask before scan_secrets verify_live or audit_mcp_tools.',
    'With .specs/ (dev-spec-driven): spec_next_action first; a reported bug goes to /spec-bugfix.',
].join('\n');
//# sourceMappingURL=instructions.js.map