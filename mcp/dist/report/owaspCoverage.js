/**
 * Rendering a finding's taxonomy and an OWASP Top 10:2025 coverage table
 * (`frameworks/coverage.ts`) — shared by `report_export` (Markdown, HTML)
 * and `compliance_evidence`, so the two say the same thing the same way.
 *
 * Wording rules, all of them load-bearing:
 *   - a category no capable scanner ran for is "NOT TESTED", in capitals,
 *     and the table says outright that this is not a clean result;
 *   - the languages the table was judged against, and where they came
 *     from, are printed above it — "tested" is a claim about them;
 *   - a finding with no taxonomy shows "—" and is counted as unmapped,
 *     never under a category;
 *   - `partial` names why (thin rule counts, uncovered languages,
 *     incomplete runs), and a category nothing dev-guardian runs can test
 *     in these languages says so instead of pointing at a scanner.
 */
import { escapeHtml } from './htmlTheme.js';
/** `CWE-89 · A05:2025` — or `—` when the finding's taxonomy is unknown. */
export function taxonomyCell(f) {
    const parts = [...(f.cwe ?? []), ...(f.owasp ?? [])];
    return parts.length > 0 ? parts.join(' · ') : '—';
}
export const COVERAGE_RULE = 'A category counts as tested only when, for every source language of the project, a scanner that ran ' +
    'fully ok has at least three rules for it in that language. A scanner that sees only a slice of a ' +
    'category, whatever the language — gitleaks (hard-coded credentials) for A07, Trivy and the dependency ' +
    'auditors (known-vulnerable components, not build and distribution integrity) for A03 — makes it partial ' +
    'at most. "not tested" is not a clean result: nothing looked. A finding can map to more than one category; a ' +
    'vulnerable dependency counts under A03 only — the CWEs of the flaw inside it are listed, not counted.';
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
/** `Project languages: go, javascript (detect_stack snapshot of …)`. */
export function languagesLine(cov) {
    const list = cov.languages === null ? 'unknown' : cov.languages.length === 0 ? 'none detected' : cov.languages.join(', ');
    return `Project languages: ${list} (${cov.languages_source})`;
}
/**
 * What would test a category that was not tested — or, when nothing
 * dev-guardian runs reaches it in the project's languages, that sentence.
 */
export function untestedHint(c, cov) {
    if (c.could_be_tested_by.length > 0)
        return `would be tested by: ${c.could_be_tested_by.join('; ')}`;
    const langs = cov.languages === null || cov.languages.length === 0 ? 'these languages' : cov.languages.join(', ');
    return `no scanner dev-guardian runs has rules for ${langs}`;
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
    lines.push(languagesLine(cov));
    lines.push('');
    lines.push('| Category | Coverage | Tested by | Findings |');
    lines.push('| --- | --- | --- | --- |');
    for (const c of cov.categories) {
        lines.push(`| ${c.id} ${c.title} | ${statusLabel(c)} | ${testedByText(c.tested_by)} | ${c.findings} |`);
    }
    lines.push('');
    for (const c of cov.categories) {
        if (c.status === 'partial')
            lines.push(`- ${c.id} partial: ${c.reasons.join('; ')}.`);
    }
    for (const c of cov.categories) {
        if (c.status !== 'not_tested')
            continue;
        lines.push(c.could_be_tested_by.length > 0 ? `- ${c.id} ${untestedHint(c, cov)}.` : `- ${c.id}: ${untestedHint(c, cov)}.`);
    }
    if (cov.findings_total > 0)
        lines.push(`- ${unmappedSentence(cov, 'findings')}`);
    return lines;
}
/** The same section for the branded HTML report. */
export function owaspCoverageHtml(cov) {
    const rows = cov.categories
        .map((c) => {
        const why = c.status === 'partial'
            ? `<br><small>${escapeHtml(c.reasons.join('; '))}</small>`
            : c.status === 'not_tested'
                ? `<br><small>${escapeHtml(untestedHint(c, cov))}</small>`
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
        `<p class="pdk-meta">${escapeHtml(languagesLine(cov))}</p>\n` +
        `<table><thead><tr><th>Category</th><th>Coverage</th><th>Tested by</th><th>Findings</th></tr></thead><tbody>${rows}</tbody></table>\n` +
        unmapped);
}
//# sourceMappingURL=owaspCoverage.js.map