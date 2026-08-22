/**
 * Shared types for the local dashboard (`dev-guardian status` /
 * `dev-guardian dashboard`) — see
 *
 * This file currently carries the risk-score slice (§3.1) and the
 * delta/hotspot slice (§7, §8 of the design). Later tasks extend it with
 * `DashboardSnapshot` and its other parts.
 */
/** Tools whose absence removes a whole class of finding from the numbers.
 *  A tool absent from this table contributes its own name, never nothing. */
export const TOOL_CATEGORIES = {
    semgrep: 'static-analysis',
    gitleaks: 'secrets',
    trivy: 'container and dependency',
    nuclei: 'dynamic',
};
//# sourceMappingURL=types.js.map