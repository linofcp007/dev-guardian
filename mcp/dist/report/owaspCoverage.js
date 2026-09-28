/**
 * Rendering a finding's taxonomy and an OWASP Top 10:2025 coverage table
 * (`frameworks/coverage.ts`) — shared by `report_export` (Markdown, HTML)
 * and `compliance_evidence`, so the two say the same thing the same way.
 *
 * Wording rules, all of them load-bearing:
 *   - a category no capable scanner ran for is "NOT TESTED", in capitals,
 *     and the table says outright that this is not a clean result;
 *   - a finding with no taxonomy shows "—" and is counted as unmapped,
 *     never under a category;
 *   - `partial` names why.
 */
import { escapeHtml } from './htmlTheme.js';
/** `CWE-89 · A05:2025` — or `—` when the finding's taxonomy is unknown. */
export function taxonomyCell(f) {
    const parts = [...(f.cwe ?? []), ...(f.owasp ?? [])];
    return parts.length > 0 ? parts.join(' · ') : '—';
}
export const COVERAGE_RULE = 'A category counts as tested only when a scanner able to detect it ran ok in the scans this document ' +
    'covers. "not tested" is not a clean result: nothing looked. A finding can map to more than one category.';
const STATUS_LABEL = {
    tested: 'tested',
    partial: 'partial',
    not_tested: 'NOT TESTED',
};
export function statusLabel(c) {
    return STATUS_LABEL[c.status];
}
/** `semgrep (sast)`, once per tool and scan type. */
export function testedByText(by) {
    const seen = new Set();
    const out = [];
    for (const e of by) {
        const text = `${e.tool} (${e.scan_type})`;
        if (seen.has(text))
            continue;
        seen.add(text);
        out.push(text);
    }
    return out.length > 0 ? out.join(', ') : '—';
}
/** Why a partial category is partial — every distinct reason, once. */
export function partialReasons(c) {
    return [...new Set(c.tested_by.map((e) => e.partial).filter((r) => r !== undefined))];
}
export function unmappedSentence(cov, noun) {
    return (`${cov.findings_unmapped} of ${cov.findings_total} ${noun} carry no OWASP 2025 category ` +
        '(no CWE from their scanner, a CWE outside the Top 10, or stored before dev-guardian recorded one).');
}
/** The "## OWASP Top 10:2025 coverage" section of a Markdown report. */
export function owaspCoverageMarkdown(cov) {
    const lines = [];
    lines.push('## OWASP Top 10:2025 coverage');
    lines.push('');
    lines.push(`_${COVERAGE_RULE} Categories and CWE mapping: https://owasp.org/Top10/2025/_`);
    lines.push('');
    lines.push('| Category | Coverage | Tested by | Findings |');
    lines.push('| --- | --- | --- | --- |');
    for (const c of cov.categories) {
        lines.push(`| ${c.id} ${c.title} | ${statusLabel(c)} | ${testedByText(c.tested_by)} | ${c.findings} |`);
    }
    lines.push('');
    for (const c of cov.categories) {
        if (c.status === 'partial')
            lines.push(`- ${c.id} partial: ${partialReasons(c).join('; ')}.`);
    }
    const untested = cov.categories.filter((c) => c.status === 'not_tested');
    for (const c of untested)
        lines.push(`- ${c.id} would be tested by: ${c.could_be_tested_by.join('; ')}.`);
    if (cov.findings_total > 0)
        lines.push(`- ${unmappedSentence(cov, 'findings')}`);
    return lines;
}
/** The same section for the branded HTML report. */
export function owaspCoverageHtml(cov) {
    const rows = cov.categories
        .map((c) => {
        const why = c.status === 'partial'
            ? `<br><small>${escapeHtml(partialReasons(c).join('; '))}</small>`
            : c.status === 'not_tested'
                ? `<br><small>would be tested by: ${escapeHtml(c.could_be_tested_by.join('; '))}</small>`
                : '';
        return `<tr>
  <td><a href="${escapeHtml(c.url)}" target="_blank" rel="noopener">${escapeHtml(c.id)}</a> ${escapeHtml(c.title)}</td>
  <td>${c.status === 'not_tested' ? '<strong>NOT TESTED</strong>' : escapeHtml(statusLabel(c))}${why}</td>
  <td>${escapeHtml(testedByText(c.tested_by))}</td>
  <td>${c.findings}</td>
</tr>`;
    })
        .join('');
    const unmapped = cov.findings_total > 0 ? `<p>${escapeHtml(unmappedSentence(cov, 'findings'))}</p>` : '';
    return (`<h2>OWASP Top 10:2025 coverage</h2>\n<p class="pdk-meta">${escapeHtml(COVERAGE_RULE)}</p>\n` +
        `<table><thead><tr><th>Category</th><th>Coverage</th><th>Tested by</th><th>Findings</th></tr></thead><tbody>${rows}</tbody></table>\n` +
        unmapped);
}
//# sourceMappingURL=owaspCoverage.js.map