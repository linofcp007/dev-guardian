/**
 * `renderDashboard` — the self-contained HTML page behind `dev-guardian
 * dashboard`. See
 * `docs/superpowers/specs/2026-08-15-local-dashboard-design.md` §2, §5.1, §8,
 * §9 for the rules this reproduces.
 *
 * Pure: a `DashboardSnapshot` in, an HTML string out. No storage, no clock,
 * no I/O, no network — every value shown is read straight from the snapshot.
 *
 * Two properties this file exists to hold, both load-bearing enough that the
 * committed tests parse the output rather than eyeball it (design §11):
 *
 *  - **Self-contained.** No `<link>`, no `<script src>`, no CDN, no web font,
 *    no `@import url`. All CSS/JS is inline (built on `report/htmlTheme.ts`'s
 *    shell) and the one data dependency — the snapshot itself — is inlined as
 *    JSON in a `<script type="application/json">` block. The one outbound
 *    `<a href="https://nvd.nist.gov/...">` per CVE (mirroring
 *    `tools/reportExport.ts`'s existing convention) is a user-clicked
 *    hyperlink, not an auto-fetched asset, so it does not compromise this: the
 *    page still renders and functions with zero network activity.
 *  - **Untrusted text stays text.** Every field that can carry scanner- or
 *    user-supplied free text (finding title/message/file_path, hotspot
 *    file_path, CVE package name, suppression reason, baseline note, and
 *    project_path itself) is passed through `escapeHtml` before it reaches
 *    the visible document. The inlined JSON payload carries the RAW,
 *    unescaped values (that is what makes it a faithful round trip — see
 *    `payloadScript` below); the visible HTML never does.
 *
 * The interaction script (`interactionScript`) is progressive enhancement,
 * not the primary rendering path: `findingsTableSection` below renders the
 * full, already-escaped `<tbody>` server-side, so a project with JavaScript
 * disabled — or a script that throws for a reason this file did not
 * anticipate — still sees a complete, correctly-escaped table. The script
 * only ADDS filtering (show/hide existing rows via their `data-*`
 * attributes), sorting (reordering existing rows, never rebuilding their
 * content) and per-row message/snippet detail (built with
 * `createElement`/`textContent`, never `innerHTML`, so the untrusted text it
 * pulls from the JSON payload for that detail view is exposed to the exact
 * same "stays text" guarantee as the server-rendered table).
 */
import { escapeHtml, renderHtmlDocument, severityBar, severityChip, SEVERITY_COLORS } from '../report/htmlTheme.js';
const SEV_RANK = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'];
export function renderDashboard(snapshot) {
    if (snapshot.scan === null)
        return renderNoScan(snapshot);
    const scan = snapshot.scan;
    const sections = [];
    sections.push(riskSection(snapshot));
    const banner = coverageBanner(snapshot.coverage);
    if (banner !== null)
        sections.push(banner);
    const truncationNotice = truncationSection(snapshot.truncation);
    if (truncationNotice !== null)
        sections.push(truncationNotice);
    sections.push(severitySection(snapshot.findings));
    sections.push(deltasSection(snapshot, scan.scan_type));
    sections.push(findingsTableSection(snapshot.findings));
    sections.push(hotspotsSection(snapshot.findings.hotspots));
    sections.push(cvesSection(snapshot.cves));
    sections.push(suppressionsSection(snapshot.suppressions));
    sections.push(scanMetaSection(snapshot));
    sections.push(payloadScript(snapshot));
    sections.push(interactionScript());
    return renderHtmlDocument({
        title: 'dev-guardian dashboard',
        // renderHtmlDocument escapes title/subtitle itself — passing raw text
        // here and letting it do so is what avoids a double-escape.
        subtitle: `${snapshot.project_path} · generated ${snapshot.generated_at}`,
        sections,
        lang: 'en',
    });
}
/**
 * Design §5.1: a project with no completed scan is *unknown*, not safe. A
 * single line naming the command to run, still inside the same branded
 * shell — never the full layout built over data that does not exist. The
 * JSON payload is still inlined (the snapshot's every field carries its
 * documented empty value already, per §5.1), so the page keeps its "one
 * self-contained file" property even in this state.
 */
function renderNoScan(snapshot) {
    const sections = [
        `<section>
  <p>No scan yet — run <code>dev-guardian scan</code> (or <code>/guardian-scan</code> inside Claude Code) to get started.</p>
</section>`,
        payloadScript(snapshot),
        interactionScript(),
    ];
    return renderHtmlDocument({
        title: 'dev-guardian dashboard',
        subtitle: `${snapshot.project_path} · generated ${snapshot.generated_at}`,
        sections,
        lang: 'en',
    });
}
// ---------------------------------------------------------------------------
// RISK — design §2's corollary: a score computed over a partial scan carries
// its caveat attached, never as a bare number.
// ---------------------------------------------------------------------------
function riskSection(snapshot) {
    const { risk } = snapshot;
    const colors = SEVERITY_COLORS[risk.band];
    const caveat = risk.coverage_caveat
        ? `<p class="pdk-risk-caveat">⚠ partial coverage — this score does not reflect everything the scan intended to check.</p>`
        : '';
    return `<section>
  <h2>Risk</h2>
  <div class="pdk-risk-badge" style="display:inline-block;padding:8px 16px;border-radius:8px;font-weight:700;background:${colors.bg};color:${colors.fg};">${risk.score}/100 · ${escapeHtml(risk.band.toUpperCase())}</div>
  <p>${escapeHtml(risk.next_action)}</p>
  ${caveat}
</section>`;
}
// ---------------------------------------------------------------------------
// Coverage banner — design §2's governing rule, made visible as a banner
// (not a footnote): present only when coverage is partial, naming both the
// missing tools and what the numbers therefore do not contain.
// ---------------------------------------------------------------------------
/**
 * **The "<tools> did not run this scan" clause only when there ARE missing
 * tools** (coordinator review, Important). `snapshot.ts`'s `cveGap` can put
 * coverage into `'partial'` with `missing_tools` genuinely empty — no
 * scanner failed to run; there is simply no `deps`/`security_full` scan
 * anywhere in this project's history to source CVE data from. Rendering the
 * "did not run this scan" clause unconditionally left an empty subject
 * ("` did not run this scan —`") that also misattributed the cause. When
 * there is nothing to name, this states only the consequence — from
 * `coverage.omitted_categories`, exactly as the non-empty branch already
 * does for its own second half — rather than claiming something failed to
 * run when nothing did.
 */
function coverageBanner(coverage) {
    if (coverage.level !== 'partial')
        return null;
    const categories = coverage.omitted_categories.map((c) => escapeHtml(c)).join(', ');
    const message = coverage.missing_tools.length > 0
        ? `${coverage.missing_tools.map((t) => escapeHtml(t)).join(', ')} did not run this scan — ` +
            `${categories} findings are NOT in these numbers.`
        : `${categories} findings are NOT in these numbers.`;
    return `<div class="guardian-coverage-banner" role="alert" style="border:1px solid #FFD700;background:rgba(255,215,0,0.12);border-radius:8px;padding:12px 16px;margin:1em 0;">
  <strong>⚠ Partial coverage.</strong> ${message}
</div>`;
}
// ---------------------------------------------------------------------------
// Truncation notices (design §8: no cap is ever silent). Rendered generically
// — one line per notice, regardless of what `what` says — deliberately NOT
// matched to a specific section by exact string: `TruncationNotice.what` is
// documented as free-form ("which field was capped, e.g. 'new_findings'"),
// and different producers phrase it differently (`snapshot.ts` emits
// 'findings.items' / 'deltas.since_previous.new_findings' / …). A renderer
// that tries to match an exact string here is one producer-side rename away
// from silently dropping a notice it can no longer recognise; mirrors
// renderStatus.ts's own renderTruncationLines for exactly this reason.
// ---------------------------------------------------------------------------
function truncationSection(notices) {
    if (notices.length === 0)
        return null;
    const items = notices
        .map((n) => `<li><code>${escapeHtml(n.what)}</code>: showing ${n.shown} of ${n.total} (${escapeHtml(n.reason)})</li>`)
        .join('');
    return `<section>
  <h2>What was cut</h2>
  <ul>${items}</ul>
</section>`;
}
// ---------------------------------------------------------------------------
// Severity distribution — reuses htmlTheme's severityBar verbatim.
// ---------------------------------------------------------------------------
function severitySection(findings) {
    const body = findings.total > 0
        ? severityBar(findings.by_severity)
        : '<p class="pdk-empty">No open findings.</p>';
    return `<section>
  <h2>Findings by severity</h2>
  ${body}
</section>`;
}
// ---------------------------------------------------------------------------
// The two deltas (design §7) — an absent reference renders as an explicit
// sentence, never as zeros; a present-but-flat delta renders its zeros.
// ---------------------------------------------------------------------------
function deltasSection(snapshot, scanType) {
    const previous = renderDelta('Since last scan', snapshot.deltas.since_previous, `no previous ${scanType} scan to compare`);
    const baseline = renderDelta('Since baseline', snapshot.deltas.since_baseline, 'no baseline set');
    return `<section>
  <h2>Change</h2>
  ${previous}
  ${baseline}
</section>`;
}
function renderDelta(label, delta, emptyMessage) {
    if (delta === null) {
        return `<p><strong>${escapeHtml(label)}:</strong> ${escapeHtml(emptyMessage)}</p>`;
    }
    const rows = delta.new_findings.map((f) => deltaRow(f)).join('');
    const table = delta.new_findings.length > 0
        ? `<table><thead><tr><th>Sev</th><th>Title</th><th>Location</th></tr></thead><tbody>${rows}</tbody></table>`
        : '';
    return `<div>
  <p><strong>${escapeHtml(label)}:</strong> +${delta.new_count} new · -${delta.resolved_count} resolved · ${delta.unchanged_count} unchanged</p>
  ${table}
</div>`;
}
function deltaRow(f) {
    const severity = f.severity ?? 'info';
    const file = f.file_path ?? '';
    const loc = file + (f.line_start ? `:${f.line_start}` : '');
    return `<tr>
  <td>${severityChip(severity)}</td>
  <td>${escapeHtml(f.title ?? '')}</td>
  <td><code>${escapeHtml(loc)}</code></td>
</tr>`;
}
// ---------------------------------------------------------------------------
// The filterable findings table — server-rendered in full (every cell
// escaped), so the table exists and is correct even if the interaction
// script never runs. The script (see interactionScript below) only shows,
// hides and reorders these already-rendered rows.
// ---------------------------------------------------------------------------
function findingsTableSection(findings) {
    if (findings.items.length === 0) {
        return `<section>
  <h2>Open findings</h2>
  <p class="pdk-empty">No open findings.</p>
</section>`;
    }
    const severityOptions = SEVERITY_ORDER
        .map((s) => `<option value="${s}">${s} (${findings.by_severity[s]})</option>`)
        .join('');
    const toolOptions = optionsFor(findings.by_tool);
    const categoryOptions = optionsFor(findings.by_category);
    const rows = findings.items.map((f) => findingRow(f)).join('');
    const shownCount = findings.items.length;
    return `<section>
  <h2>Open findings (<span id="pdk-findings-count">${shownCount} of ${shownCount} shown</span>)</h2>
  <div class="pdk-filters">
    <label>Severity <select id="pdk-filter-severity"><option value="">All</option>${severityOptions}</select></label>
    <label>Tool <select id="pdk-filter-tool"><option value="">All</option>${toolOptions}</select></label>
    <label>Category <select id="pdk-filter-category"><option value="">All</option>${categoryOptions}</select></label>
    <label>File <input id="pdk-filter-file" type="text" placeholder="filter by file path"></label>
  </div>
  <p id="pdk-findings-empty" class="pdk-empty" style="display:none;">No findings match the current filters.</p>
  <table>
    <thead>
      <tr>
        <th id="pdk-th-severity">Sev</th>
        <th id="pdk-th-tool">Tool</th>
        <th id="pdk-th-rule">Rule</th>
        <th id="pdk-th-title">Title</th>
        <th id="pdk-th-file">Location</th>
      </tr>
    </thead>
    <tbody id="pdk-findings-body">${rows}</tbody>
  </table>
</section>`;
}
function optionsFor(counts) {
    return Object.keys(counts)
        .sort()
        .map((k) => {
        const n = counts[k] ?? 0;
        const label = escapeHtml(k);
        return `<option value="${label}">${label} (${n})</option>`;
    })
        .join('');
}
/**
 * Every field is defended with a fallback, including ones `Finding` marks
 * non-optional (`severity`, `tool`, `title`, `category`, `fingerprint`) —
 * not gold-plating: the brief's own given fixtures build finding literals
 * via `as never` that omit `category` entirely (see e.g. its "inlines data"
 * and "escapes finding text" tests), so `f.category` is genuinely
 * `undefined` at runtime for those. `escapeHtml(undefined)` throws — a
 * fallback here is what lets those given tests render at all rather than
 * crash before their own assertions run.
 */
function findingRow(f) {
    const severity = f.severity ?? 'info';
    const sevRank = SEV_RANK[severity] ?? 0;
    const tool = f.tool ?? '';
    const category = f.category ?? '';
    const file = f.file_path ?? '';
    const title = f.title ?? '';
    const ruleId = f.rule_id ?? '';
    const fingerprint = f.fingerprint ?? '';
    const message = f.message ?? '';
    const loc = file + (f.line_start ? `:${f.line_start}` : '');
    const attrs = `data-fp="${escapeHtml(fingerprint)}" ` +
        `data-severity="${escapeHtml(severity)}" ` +
        `data-sevrank="${sevRank}" ` +
        `data-tool="${escapeHtml(tool)}" ` +
        `data-category="${escapeHtml(category)}" ` +
        `data-file="${escapeHtml(file.toLowerCase())}" ` +
        `data-title="${escapeHtml(title.toLowerCase())}" ` +
        `data-rule="${escapeHtml(ruleId.toLowerCase())}"`;
    // The message is also reachable through click-to-expand (interactionScript
    // below), which is where the full text lives — but a `title` attribute
    // puts it in the static, no-JS document too, as a native hover tooltip.
    // Same hazard as every other field here (attribute-breakout via an
    // unescaped quote), same fix.
    const titleAttr = message.length > 0 ? ` title="${escapeHtml(message)}"` : '';
    return (`<tr ${attrs}${titleAttr}>` +
        `<td>${severityChip(severity)}</td>` +
        `<td>${escapeHtml(tool)}</td>` +
        `<td><code>${escapeHtml(ruleId)}</code></td>` +
        `<td>${escapeHtml(title)}</td>` +
        `<td><code>${escapeHtml(loc)}</code></td>` +
        `</tr>`);
}
// ---------------------------------------------------------------------------
// Hotspots — plain counts, not severity-weighted (design §12).
// ---------------------------------------------------------------------------
function hotspotsSection(hotspots) {
    if (hotspots.length === 0) {
        return `<section>
  <h2>Hottest files</h2>
  <p class="pdk-empty">No hotspots.</p>
</section>`;
    }
    const rows = hotspots
        .map((h) => `<tr><td><code>${escapeHtml(h.file_path)}</code></td><td>${h.count}</td></tr>`)
        .join('');
    return `<section>
  <h2>Hottest files</h2>
  <table><thead><tr><th>File</th><th>Findings</th></tr></thead><tbody>${rows}</tbody></table>
</section>`;
}
// ---------------------------------------------------------------------------
// CVEs — mirrors tools/reportExport.ts's existing HTML convention (including
// the outbound NVD link, a user-clicked hyperlink, not an auto-fetched
// asset — see this file's header comment).
// ---------------------------------------------------------------------------
function cvesSection(cves) {
    if (cves.items.length === 0) {
        return `<section>
  <h2>Active CVEs</h2>
  <p class="pdk-empty">No CVEs indexed for this scan.</p>
</section>`;
    }
    const rows = cves.items.map((c) => cveRow(c)).join('');
    return `<section>
  <h2>Active CVEs (${cves.total})</h2>
  <table><thead><tr><th>CVE</th><th>Sev</th><th>Package</th><th>Installed</th><th>Fixed</th></tr></thead><tbody>${rows}</tbody></table>
</section>`;
}
function cveRow(c) {
    const severity = c.severity ?? 'info';
    const cveId = c.cve_id ?? '';
    return `<tr>
  <td><a href="https://nvd.nist.gov/vuln/detail/${escapeHtml(cveId)}" target="_blank" rel="noopener">${escapeHtml(cveId)}</a></td>
  <td>${severityChip(severity)}</td>
  <td>${escapeHtml(c.package_name ?? '')}</td>
  <td><code>${escapeHtml(c.installed_version ?? '')}</code></td>
  <td><code>${escapeHtml(c.fixed_version ?? '')}</code></td>
</tr>`;
}
// ---------------------------------------------------------------------------
// Suppressions.
// ---------------------------------------------------------------------------
function suppressionsSection(s) {
    if (s.active_count === 0) {
        return `<section>
  <h2>Suppressions</h2>
  <p class="pdk-empty">No suppressions active.</p>
</section>`;
    }
    const rows = s.expiring_soon
        .map((e) => `<tr>
  <td><code>${escapeHtml(e.fingerprint)}</code></td>
  <td>${escapeHtml(e.reason)}</td>
  <td>${escapeHtml(e.expires_at)}</td>
</tr>`)
        .join('');
    const expiring = s.expiring_soon.length > 0
        ? `<h3>Expiring within 7 days</h3><table><thead><tr><th>Fingerprint</th><th>Reason</th><th>Expires</th></tr></thead><tbody>${rows}</tbody></table>`
        : '';
    return `<section>
  <h2>Suppressions</h2>
  <p>${s.active_count} active.</p>
  ${expiring}
</section>`;
}
// ---------------------------------------------------------------------------
// Scan metadata — project_path is an arbitrary filesystem path chosen by
// whoever ran the scan; escaped like every other field here.
// ---------------------------------------------------------------------------
function scanMetaSection(snapshot) {
    const scan = snapshot.scan;
    if (scan === null)
        return '';
    const baselineLine = baselineMetaLine(snapshot.baseline);
    const toolsRun = snapshot.coverage.tools_run.map((t) => escapeHtml(t)).join(', ');
    const toolsRunLine = toolsRun.length > 0 ? `<br><strong>Tools run:</strong> ${toolsRun}` : '';
    return `<section>
  <h2>Scan</h2>
  <div class="pdk-meta">
    <strong>Project:</strong> <code>${escapeHtml(snapshot.project_path)}</code><br>
    <strong>Scan ID:</strong> ${escapeHtml(scan.scan_id)}<br>
    <strong>Type:</strong> ${escapeHtml(scan.scan_type)}<br>
    <strong>Status:</strong> ${escapeHtml(scan.status)}<br>
    <strong>Started:</strong> ${escapeHtml(scan.started_at)}<br>
    <strong>Finished:</strong> ${escapeHtml(scan.finished_at ?? 'n/a')}<br>
    <strong>Generated:</strong> ${escapeHtml(snapshot.generated_at)}${toolsRunLine}${baselineLine}
  </div>
</section>`;
}
function baselineMetaLine(baseline) {
    if (baseline.active === null)
        return '';
    const note = baseline.active.note ? ` — ${escapeHtml(baseline.active.note)}` : '';
    const age = baseline.age_days === null ? '' : ` (${baseline.age_days}d ago)`;
    return `<br><strong>Baseline:</strong> ${escapeHtml(baseline.active.set_at)}${age}${note}`;
}
// ---------------------------------------------------------------------------
// The inlined data payload.
// ---------------------------------------------------------------------------
/**
 * `</script>` inside a finding's title/message would otherwise terminate
 * this block early and spill the rest of the JSON into the document as
 * markup. Replacing every `<` with the JSON escape `<` prevents that
 * sequence from ever appearing literally, while staying valid JSON that
 * `JSON.parse` restores byte-for-byte (`\uXXXX` is a standard JSON string
 * escape) — this is the one implementation detail the brief's own tests pin
 * exactly, not a stylistic choice.
 */
function payloadScript(snapshot) {
    const json = JSON.stringify(snapshot).replace(/</g, '\\u003c');
    return `<script type="application/json" id="guardian-data">${json}</script>`;
}
// ---------------------------------------------------------------------------
// The interaction script — inline vanilla JS, no dependencies, no network.
//
// Deliberately does NOT build the table from the JSON payload (see this
// file's header comment for why: the table is already server-rendered and
// escaped). It reads the payload only to look up a finding's message/snippet
// for the click-to-expand detail view, and always writes that text via
// `textContent`/`createElement`, never `innerHTML` — the client-side mirror
// of the escaping this file applies server-side, for the one piece of text
// that only ever reaches the page through this script.
//
// Wrapped in one outer try/catch: any failure here — a browser quirk this
// file did not anticipate, a future edit that breaks an assumption — leaves
// the static, already-correct table exactly as server-rendered, filters and
// sort simply inert. It never results in an empty table.
// ---------------------------------------------------------------------------
function interactionScript() {
    return `<script id="guardian-interactions">
(function () {
  try {
    var tbody = document.getElementById('pdk-findings-body');
    if (!tbody) { return; }
    var dataEl = document.getElementById('guardian-data');
    var payload = dataEl ? JSON.parse(dataEl.textContent) : null;
    var items = (payload && payload.findings && payload.findings.items) || [];
    var byFp = {};
    for (var i = 0; i < items.length; i++) {
      if (items[i] && items[i].fingerprint) { byFp[items[i].fingerprint] = items[i]; }
    }

    var sevSel = document.getElementById('pdk-filter-severity');
    var toolSel = document.getElementById('pdk-filter-tool');
    var catSel = document.getElementById('pdk-filter-category');
    var fileInput = document.getElementById('pdk-filter-file');
    var countEl = document.getElementById('pdk-findings-count');
    var emptyEl = document.getElementById('pdk-findings-empty');
    var total = tbody.children.length;

    function applyFilter() {
      var sev = sevSel ? sevSel.value : '';
      var tool = toolSel ? toolSel.value : '';
      var cat = catSel ? catSel.value : '';
      var fileQ = fileInput ? fileInput.value.toLowerCase() : '';
      var shown = 0;
      var rows = tbody.children;
      for (var i = 0; i < rows.length; i++) {
        var r = rows[i];
        var ok = true;
        if (sev && r.getAttribute('data-severity') !== sev) { ok = false; }
        if (ok && tool && r.getAttribute('data-tool') !== tool) { ok = false; }
        if (ok && cat && r.getAttribute('data-category') !== cat) { ok = false; }
        if (ok && fileQ && (r.getAttribute('data-file') || '').indexOf(fileQ) === -1) { ok = false; }
        r.style.display = ok ? '' : 'none';
        if (ok) { shown++; }
      }
      if (countEl) { countEl.textContent = shown + ' of ' + total + ' shown'; }
      if (emptyEl) { emptyEl.style.display = shown === 0 ? '' : 'none'; }
    }

    var sortKey = 'sevrank';
    var sortDir = -1;

    function sortValue(row) {
      var v = row.getAttribute('data-' + sortKey);
      if (sortKey === 'sevrank') { return Number(v || 0); }
      return v === null ? '' : v;
    }

    function applySort() {
      var rows = Array.prototype.slice.call(tbody.children);
      rows.sort(function (a, b) {
        var av = sortValue(a);
        var bv = sortValue(b);
        if (av < bv) { return -1 * sortDir; }
        if (av > bv) { return 1 * sortDir; }
        return 0;
      });
      for (var i = 0; i < rows.length; i++) { tbody.appendChild(rows[i]); }
    }

    function bindSort(id, key) {
      var th = document.getElementById(id);
      if (!th) { return; }
      th.addEventListener('click', function () {
        if (sortKey === key) { sortDir = -sortDir; } else { sortKey = key; sortDir = 1; }
        applySort();
      });
    }

    [sevSel, toolSel, catSel].forEach(function (el) {
      if (el) { el.addEventListener('change', applyFilter); }
    });
    if (fileInput) { fileInput.addEventListener('input', applyFilter); }

    bindSort('pdk-th-severity', 'sevrank');
    bindSort('pdk-th-tool', 'tool');
    bindSort('pdk-th-rule', 'rule');
    bindSort('pdk-th-title', 'title');
    bindSort('pdk-th-file', 'file');

    var rows = tbody.children;
    var wireExpand = function (row) {
      var detailBox = null;
      row.addEventListener('click', function () {
        if (detailBox) {
          detailBox.style.display = detailBox.style.display === 'none' ? '' : 'none';
          return;
        }
        var fp = row.getAttribute('data-fp');
        var finding = fp ? byFp[fp] : null;
        if (!finding) { return; }
        var cell = row.children[3];
        if (!cell) { return; }
        detailBox = document.createElement('div');
        detailBox.className = 'pdk-detail';
        var msg = document.createElement('div');
        msg.textContent = finding.message ? finding.message : '(no message)';
        detailBox.appendChild(msg);
        if (finding.snippet) {
          var pre = document.createElement('pre');
          pre.textContent = finding.snippet;
          detailBox.appendChild(pre);
        }
        cell.appendChild(detailBox);
      });
    };
    for (var ri = 0; ri < rows.length; ri++) { wireExpand(rows[ri]); }

    applyFilter();
  } catch (e) {
    // Progressive enhancement only: the table above is already fully
    // rendered and correctly escaped by the server. A failure here leaves a
    // complete, static, non-interactive table — never an empty one.
  }
})();
</script>`;
}
//# sourceMappingURL=renderHtml.js.map