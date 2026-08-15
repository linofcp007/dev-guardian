import { describe, expect, it } from 'vitest';
import { renderDashboard } from '../../../src/dashboard/renderHtml.js';
import { snap } from './snapshotFixture.js';

/** Pull the inlined payload back out the way a browser would. */
function inlinedData(html: string): unknown {
  const m = html.match(
    /<script type="application\/json" id="guardian-data">([\s\S]*?)<\/script>/,
  );
  if (!m || m[1] === undefined) throw new Error('no inlined data block');
  return JSON.parse(m[1]);
}

/**
 * Every way this page could reach outside itself. Named and shared between
 * the main "reaches for nothing outside the file" test below (checked
 * against the real, unmodified page) and the injection tests further down
 * (each pattern individually proven to catch a synthetic example of the
 * thing it names) — one list, not two copies that could silently drift.
 *
 * Fix round 1 (Important finding): the original four checks caught
 * `<script src>`/`<link href>` regardless of URL form, and a scheme'd
 * (`https?://`) asset URL or `@import url(...)` — but missed a
 * PROTOCOL-RELATIVE reference (`src="//host/x.js"`, no scheme at all) in
 * ANY position, including tags never checked at all (`<img>` and its
 * auto-loading siblings), and the bare-string form of `@import`
 * (`@import "//host/x.css"`, no `url(...)` wrapper). Both reach the network
 * exactly like their scheme'd/wrapped siblings. Widened to close both, and
 * to the auto-loading tags most likely to gain a `src`/`data` attribute
 * before anyone thinks to add `<img>` here specifically.
 *
 * Deliberately does NOT flag a plain `<a href="https://...">` — the one
 * legitimate outbound reference this page has (a CVE's NVD link) is exactly
 * that: a user has to click it, it is never auto-loaded, and `<a>` is not in
 * this list. See "still allows the one legitimate outbound link" below.
 */
const OFFLINE_GUARD = {
  scriptSrc: /<script[^>]+\bsrc=/i,
  linkHref: /<link[^>]+\bhref=/i,
  autoLoadingTag: /<(?:img|iframe|video|audio|source|embed|object|track)[^>]+\b(?:src|data)=/i,
  schemedAssetUrl: /https?:\/\/[^"'\s]+\.(?:js|css|woff2?|png|svg)/i,
  protocolRelativeRef: /\b(?:src|href)=["']\/\/[^"'\s]+/i,
  // Either CSS @import form — `@import url(...)` or the bare quoted-string
  // form — targeting anything off-disk, scheme'd or protocol-relative.
  importOffDisk: /@import\s+(?:url\(\s*)?["']?(?:https?:)?\/\//i,
} as const;

describe('renderDashboard', () => {
  it('inlines data that is valid JSON and round-trips the findings', () => {
    const html = renderDashboard(snap({
      findings: { total: 1,
        by_severity: { critical: 0, high: 1, medium: 0, low: 0, info: 0 },
        by_category: { security: 1 }, by_tool: { semgrep: 1 }, hotspots: [],
        items: [{ fingerprint: 'a', severity: 'high', title: 'Injection',
          file_path: 'src/a.ts', tool: 'semgrep', rule_id: 'r',
          message: 'm', line_start: 3 } as never] },
    }));
    const data = inlinedData(html) as { findings: { items: { title: string }[] } };
    expect(data.findings.items[0]?.title).toBe('Injection');
  });

  it('reaches for nothing outside the file', () => {
    // The offline guarantee. A CDN <script src> added later would render
    // perfectly in a browser with network and break silently without one, and
    // no visual check would catch it. See OFFLINE_GUARD's own comment for
    // what fix round 1 widened this to, and why.
    const html = renderDashboard(snap());
    expect(html).not.toMatch(OFFLINE_GUARD.scriptSrc);
    expect(html).not.toMatch(OFFLINE_GUARD.linkHref);
    expect(html).not.toMatch(OFFLINE_GUARD.autoLoadingTag);
    expect(html).not.toMatch(OFFLINE_GUARD.schemedAssetUrl);
    expect(html).not.toMatch(OFFLINE_GUARD.protocolRelativeRef);
    expect(html).not.toMatch(OFFLINE_GUARD.importOffDisk);
  });

  it('carries a coverage banner, not a footnote, when coverage is partial', () => {
    // Fix round 1: this test originally asserted against the UN-STRIPPED
    // html string. `missing_tools`/`omitted_categories` are always present
    // verbatim in the inlined JSON payload regardless of what the banner
    // itself renders, so 'gitleaks' and 'secrets' were always found —
    // reviewer-confirmed hollow by mutation (a [0]-only banner still left
    // this green). Stripped, matching every other content-bearing test in
    // this file — see the brief's own "escapes finding text" test, which
    // already does this and was the model this test should have followed.
    const html = renderDashboard(snap({
      coverage: { level: 'partial', tools_run: ['semgrep'],
        missing_tools: ['gitleaks'], omitted_categories: ['secrets'] },
    }));
    const visible = html.replace(/<script type="application\/json"[\s\S]*?<\/script>/g, '');
    expect(visible).toMatch(/guardian-coverage-banner/);
    expect(visible).toMatch(/gitleaks/);
    expect(visible).toMatch(/secrets/);
  });

  it('has no coverage banner when coverage is full', () => {
    // Stripped for the same reason and to match the pair above, though this
    // specific assertion was never hollow: 'guardian-coverage-banner' is a
    // CSS class name, never a snapshot field name or value, so it cannot
    // appear in the JSON payload regardless of stripping.
    const html = renderDashboard(snap());
    const visible = html.replace(/<script type="application\/json"[\s\S]*?<\/script>/g, '');
    expect(visible).not.toMatch(/guardian-coverage-banner/);
  });

  it('states what it cut, in the visible document and not only in the data', () => {
    const html = renderDashboard(snap({
      truncation: [{ what: 'findings', shown: 2000, total: 5310, reason: 'cap of 2000' }],
    }));
    const visible = html.replace(
      /<script type="application\/json"[\s\S]*?<\/script>/g, '');
    expect(visible).toMatch(/2000/);
    expect(visible).toMatch(/5310/);
  });

  it('escapes finding text rather than letting it become markup', () => {
    // A finding's message comes from a scanner, which read it from the user's
    // source. It is untrusted text in this document.
    const html = renderDashboard(snap({
      findings: { total: 1,
        by_severity: { critical: 0, high: 1, medium: 0, low: 0, info: 0 },
        by_category: {}, by_tool: {}, hotspots: [],
        items: [{ fingerprint: 'a', severity: 'high',
          title: '<img src=x onerror=alert(1)>', file_path: 'a.ts',
          tool: 'semgrep', rule_id: 'r', message: 'm', line_start: 1 } as never] },
    }));
    const visible = html.replace(
      /<script type="application\/json"[\s\S]*?<\/script>/g, '');
    expect(visible).not.toMatch(/<img src=x/);
    expect(visible).toMatch(/&lt;img/);
  });

  it('closes the JSON block safely when a finding contains the closing tag', () => {
    // `</script>` inside the payload would end the block early and spill the
    // rest of the JSON into the document as markup.
    const html = renderDashboard(snap({
      findings: { total: 1,
        by_severity: { critical: 0, high: 1, medium: 0, low: 0, info: 0 },
        by_category: {}, by_tool: {}, hotspots: [],
        items: [{ fingerprint: 'a', severity: 'high', title: 'x</script><b>y',
          file_path: 'a.ts', tool: 'semgrep', rule_id: 'r', message: 'm',
          line_start: 1 } as never] },
    }));
    const data = inlinedData(html) as { findings: { items: { title: string }[] } };
    expect(data.findings.items[0]?.title).toBe('x</script><b>y');
  });

  it('renders a scanned-nothing project without undefined or NaN', () => {
    const html = renderDashboard(snap({
      scan: null,
      coverage: { level: 'none', tools_run: [], missing_tools: [], omitted_categories: [] },
    }));
    const visible = html.replace(
      /<script type="application\/json"[\s\S]*?<\/script>/g, '');
    expect(visible).not.toMatch(/undefined|NaN/);
    expect(visible).toMatch(/dev-guardian scan/);
  });
});

// ---------------------------------------------------------------------------
// Beyond the brief: escaping breadth. The brief's own test pins ONE field
// (a finding's title). Untrusted text reaches this document from several
// other scanner/user-supplied fields too — each gets its own discriminating
// check, guarding against an implementation that escapes the field the brief
// happened to test and nothing else.
// ---------------------------------------------------------------------------
describe('renderDashboard — escaping breadth beyond the brief', () => {
  function visibleOf(html: string): string {
    return html.replace(/<script type="application\/json"[\s\S]*?<\/script>/g, '');
  }

  it('escapes a finding message, not only its title', () => {
    const html = renderDashboard(snap({
      findings: { total: 1,
        by_severity: { critical: 0, high: 1, medium: 0, low: 0, info: 0 },
        by_category: {}, by_tool: {}, hotspots: [],
        items: [{ fingerprint: 'a', severity: 'high', title: 't',
          file_path: 'a.ts', tool: 'semgrep', rule_id: 'r',
          message: '<svg onload=alert(2)>', line_start: 1 } as never] },
    }));
    const visible = visibleOf(html);
    expect(visible).not.toMatch(/<svg onload=/);
    expect(visible).toMatch(/&lt;svg/);
  });

  it('escapes a finding file_path', () => {
    const html = renderDashboard(snap({
      findings: { total: 1,
        by_severity: { critical: 0, high: 1, medium: 0, low: 0, info: 0 },
        by_category: {}, by_tool: {}, hotspots: [],
        items: [{ fingerprint: 'a', severity: 'high', title: 't',
          file_path: '"><script>alert(3)</script>', tool: 'semgrep',
          rule_id: 'r', message: 'm', line_start: 1 } as never] },
    }));
    const visible = visibleOf(html);
    expect(visible).not.toMatch(/"><script>alert\(3\)/);
    expect(visible).toMatch(/&quot;&gt;/);
  });

  it('escapes a hotspot file_path', () => {
    const html = renderDashboard(snap({
      findings: { total: 1,
        by_severity: { critical: 0, high: 0, medium: 0, low: 1, info: 0 },
        by_category: {}, by_tool: {},
        hotspots: [{ file_path: '<b>hot</b>.ts', count: 4 }],
        items: [] },
    }));
    const visible = visibleOf(html);
    expect(visible).not.toMatch(/<b>hot<\/b>/);
    expect(visible).toMatch(/&lt;b&gt;hot/);
  });

  it('escapes a CVE package name', () => {
    const html = renderDashboard(snap({
      cves: { total: 1, by_severity: { critical: 1, high: 0, medium: 0, low: 0, info: 0 },
        items: [{ cve_id: 'CVE-2026-0001', package_name: '<i>pwn</i>',
          installed_version: '1.0.0', fixed_version: '1.0.1', severity: 'critical',
          first_seen_scan_id: 's1', last_seen_scan_id: 's1' }] },
    }));
    const visible = visibleOf(html);
    expect(visible).not.toMatch(/<i>pwn<\/i>/);
    expect(visible).toMatch(/&lt;i&gt;pwn/);
  });

  it('renders a CVE missing fields the type marks required, without crashing', () => {
    // Minor from fix round 1's review: cveRow's `?? fallback` branches
    // (mirroring findingRow's own, tested via the brief's `as never`
    // fixtures) had no test of their own. Cheap to close while already in
    // this file: a Cve object missing severity/cve_id, the same landmine
    // shape as the brief's own finding fixtures.
    const html = renderDashboard(snap({
      cves: { total: 1, by_severity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
        items: [{ package_name: 'p', installed_version: '1', fixed_version: '2',
          first_seen_scan_id: 's1', last_seen_scan_id: 's1' } as never] },
    }));
    const visible = visibleOf(html);
    expect(visible).not.toMatch(/undefined|NaN/);
    expect(visible).toMatch(/\bp\b/); // package_name still renders
  });

  it('escapes an expiring suppression reason', () => {
    const html = renderDashboard(snap({
      suppressions: { active_count: 1,
        expiring_soon: [{ fingerprint: 'f1', reason: '<u>why</u>',
          expires_at: '2026-08-18T00:00:00.000Z' }] },
    }));
    const visible = visibleOf(html);
    expect(visible).not.toMatch(/<u>why<\/u>/);
    expect(visible).toMatch(/&lt;u&gt;why/);
  });

  it('escapes an active baseline note', () => {
    const html = renderDashboard(snap({
      baseline: { active: { baseline_id: 1, scan_id: 'z',
        set_at: '2026-07-12T00:00:00.000Z', note: '<mark>note</mark>' },
        age_days: 34 },
    }));
    const visible = visibleOf(html);
    expect(visible).not.toMatch(/<mark>note<\/mark>/);
    expect(visible).toMatch(/&lt;mark&gt;note/);
  });

  it('escapes the project_path in the scan-metadata section', () => {
    const html = renderDashboard(snap({ project_path: '<i>/proj</i>' }));
    const visible = visibleOf(html);
    expect(visible).not.toMatch(/<i>\/proj<\/i>/);
    expect(visible).toMatch(/&lt;i&gt;\/proj/);
  });
});

// ---------------------------------------------------------------------------
// Beyond the brief: the coverage banner must name EVERY missing tool and
// EVERY omitted category, not just the first — the brief's own test uses a
// single-element array for each, which a `[0]`-only implementation would
// also pass.
// ---------------------------------------------------------------------------
describe('renderDashboard — coverage banner completeness', () => {
  it('names every missing tool and every omitted category, not only the first', () => {
    // Fix round 1 (Important finding): this test checked UN-STRIPPED html.
    // missing_tools/omitted_categories are always present verbatim in the
    // inlined JSON regardless of what the banner renders, so this test
    // passed unconditionally — reviewer-confirmed by mutation: restricting
    // the banner to [0] left the full suite green. Stripped.
    const html = renderDashboard(snap({
      coverage: { level: 'partial', tools_run: ['semgrep'],
        missing_tools: ['gitleaks', 'trivy'],
        omitted_categories: ['secrets', 'container and dependency'] },
    }));
    const visible = html.replace(/<script type="application\/json"[\s\S]*?<\/script>/g, '');
    expect(visible).toMatch(/gitleaks/);
    expect(visible).toMatch(/trivy/);
    expect(visible).toMatch(/secrets/);
    expect(visible).toMatch(/container and dependency/);
  });

  it("shows the risk section's own coverage caveat, isolated from the banner elsewhere on the page", () => {
    // Design §2's corollary. Fix round 1 (Important finding): the ORIGINAL
    // version of this test stripped the JSON (already correct) but set
    // coverage.level: 'partial' — which also renders the coverage banner,
    // whose own text is "Partial coverage.". `expect(visible).toMatch(/partial/i)`
    // was therefore satisfied by the BANNER even with the risk section's own
    // caveat paragraph removed entirely — reviewer-confirmed by mutation:
    // disabling the caveat left the full suite green.
    //
    // Fixed by isolating the two: coverage FULL (banner genuinely absent,
    // checked directly below) but risk.coverage_caveat TRUE regardless — an
    // inconsistent combination `buildSnapshot` never actually produces
    // (real snapshots derive both from the same underlying condition), used
    // here deliberately so this assertion can only be satisfied by
    // `riskSection`'s own rendering, matching the design comment in
    // `renderHtml.ts` that these two fields are read independently by
    // construction. Also matches on the caveat's own CSS marker
    // (`pdk-risk-caveat`), the same technique the brief's own banner test
    // uses for the banner.
    const html = renderDashboard(snap({
      coverage: { level: 'full', tools_run: ['semgrep'], missing_tools: [], omitted_categories: [] },
      risk: { score: 62, band: 'high',
        components: { findings: { score: 40, open_findings: 104 },
          cves: { score: 14, active_cves: 5 },
          compliance: { score: 0, policies_missing: 0 },
          baseline: { score: 8, has_active_baseline: true } },
        next_action: 'Fix the 3 critical findings first.', coverage_caveat: true },
    }));
    const visible = html.replace(/<script type="application\/json"[\s\S]*?<\/script>/g, '');
    expect(visible).not.toMatch(/guardian-coverage-banner/); // sanity: banner truly absent here
    expect(visible).toMatch(/pdk-risk-caveat/);
    expect(visible).toMatch(/62/);
  });
});

// ---------------------------------------------------------------------------
// Fix round 1 (Important finding): the original "reaches for nothing
// outside the file" test caught a scheme'd absolute URL and the
// `url(...)`-wrapped form of @import, but missed two forms that reach the
// network exactly the same way: a PROTOCOL-RELATIVE reference
// (`src="//host/x"`, no `http(s):` at all) in any position — including
// `<img>` and its auto-loading siblings, none of which the original test
// checked at all — and the bare-string form of @import
// (`@import "//host/x.css"`, no `url()` wrapper).
//
// No such reference exists in the page today; these tests do not call
// renderDashboard with attacker-controlled data. They inject each missed
// form directly into a real rendered page and prove OFFLINE_GUARD's new
// patterns catch it — the guard's whole job is to catch what a FUTURE edit
// adds, and a wide-looking regex that quietly doesn't match the thing it
// claims to is exactly as useless as the original narrower one. Each
// injection targets one pattern; a passing "sanity" test first confirms the
// unmodified page trips none of them, so a failing injection test really
// means "this specific form is caught," not "everything always fails."
// ---------------------------------------------------------------------------
describe('renderDashboard — the offline guard catches forms the original four checks missed', () => {
  function anyGuardMatch(html: string): string[] {
    return Object.entries(OFFLINE_GUARD)
      .filter(([, pattern]) => pattern.test(html))
      .map(([name]) => name);
  }

  it('sanity: the real, unmodified page trips none of the guard patterns', () => {
    expect(anyGuardMatch(renderDashboard(snap()))).toEqual([]);
  });

  it('still allows the one legitimate outbound link — a user-clicked, fully-qualified CVE href', () => {
    // The guard must not be so broad it flags tools/reportExport.ts's own
    // established convention, reused here for CVE rows: <a href="https://
    // nvd.nist.gov/…">, a link the user has to click, never auto-loaded.
    const html = renderDashboard(snap({
      cves: { total: 1, by_severity: { critical: 1, high: 0, medium: 0, low: 0, info: 0 },
        items: [{ cve_id: 'CVE-2026-0001', package_name: 'p', installed_version: '1',
          fixed_version: '2', severity: 'critical', first_seen_scan_id: 's1', last_seen_scan_id: 's1' }] },
    }));
    expect(html).toMatch(/nvd\.nist\.gov/); // sanity: the link is really there
    expect(anyGuardMatch(html)).toEqual([]);
  });

  it('catches an <img src> with a protocol-relative URL — a tag the original test never checked', () => {
    const injected = renderDashboard(snap()).replace(
      '<body>', '<body><img src="//cdn.example/track.png">',
    );
    expect(OFFLINE_GUARD.autoLoadingTag.test(injected)).toBe(true);
    expect(OFFLINE_GUARD.protocolRelativeRef.test(injected)).toBe(true);
  });

  it('catches a protocol-relative <script src>, with no scheme at all', () => {
    const injected = renderDashboard(snap()).replace(
      '<body>', '<body><script src="//cdn.example/x.js"></script>',
    );
    expect(OFFLINE_GUARD.scriptSrc.test(injected)).toBe(true);
    expect(OFFLINE_GUARD.protocolRelativeRef.test(injected)).toBe(true);
  });

  it('catches a bare-string @import with a protocol-relative URL — no url() wrapper', () => {
    const injected = renderDashboard(snap()).replace(
      '</style>', '@import "//cdn.example/x.css";\n</style>',
    );
    expect(OFFLINE_GUARD.importOffDisk.test(injected)).toBe(true);
  });

  it('catches a bare-string @import with a fully-qualified https URL', () => {
    const injected = renderDashboard(snap()).replace(
      '</style>', '@import "https://cdn.example/x.css";\n</style>',
    );
    expect(OFFLINE_GUARD.importOffDisk.test(injected)).toBe(true);
  });

  it('still catches the original url()-wrapped @import form — the widening did not narrow it', () => {
    const injected = renderDashboard(snap()).replace(
      '</style>', '@import url(https://cdn.example/x.css);\n</style>',
    );
    expect(OFFLINE_GUARD.importOffDisk.test(injected)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Beyond the brief: numeric edge shapes that a naive template could turn
// into NaN/undefined even while the "scanned nothing" case (the brief's own
// adversarial test) stays clean — a fully-populated snapshot exercises
// different template branches than an empty one.
// ---------------------------------------------------------------------------
describe('renderDashboard — numeric edges on a populated snapshot', () => {
  it('never renders undefined or NaN for a large, fully-populated snapshot', () => {
    const html = renderDashboard(snap({
      findings: { total: 999_999,
        by_severity: { critical: 999_999, high: 0, medium: 0, low: 0, info: 0 },
        by_category: {}, by_tool: {}, hotspots: [], items: [] },
      deltas: {
        since_previous: { from_scan_id: 'a', to_scan_id: 'b', new_count: 0,
          resolved_count: 0, unchanged_count: 0, new_findings: [] },
        since_baseline: { from_scan_id: 'z', to_scan_id: 'b', new_count: 0,
          resolved_count: 0, unchanged_count: 0, new_findings: [] },
      },
    }));
    const visible = html.replace(/<script type="application\/json"[\s\S]*?<\/script>/g, '');
    expect(visible).not.toMatch(/undefined|NaN/);
    expect(visible).toMatch(/999999|999,999/);
  });

  it('renders a real (non-null) delta whose counts are all zero as zeros, never as an absence', () => {
    // The mirror image of the "absent delta" rule (design §7): a delta that
    // EXISTS and found no change must say 0, not disappear or say "no
    // baseline set" — that sentence is reserved for a genuinely null delta.
    const html = renderDashboard(snap({
      deltas: {
        since_previous: { from_scan_id: 'a', to_scan_id: 'b', new_count: 0,
          resolved_count: 0, unchanged_count: 40, new_findings: [] },
        since_baseline: null,
      },
    }));
    const visible = html.replace(/<script type="application\/json"[\s\S]*?<\/script>/g, '');
    expect(visible).not.toMatch(/undefined|NaN/);
    expect(visible).toMatch(/no baseline set/i);
  });

  it('says so, plainly, for a clean scan (zero findings, not a missing one)', () => {
    // scan !== null but findings.total === 0 — a real, common state (the
    // project WAS scanned and nothing is open) that is different from
    // "never scanned" (which short-circuits to renderNoScan entirely,
    // before this section is ever reached). Coverage flagged this branch
    // as untested: every other test in this file uses a nonzero total.
    const html = renderDashboard(snap({
      findings: { total: 0,
        by_severity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
        by_category: {}, by_tool: {}, hotspots: [], items: [] },
    }));
    const visible = html.replace(/<script type="application\/json"[\s\S]*?<\/script>/g, '');
    expect(visible).not.toMatch(/undefined|NaN/);
    expect(visible).toMatch(/No open findings/);
  });

  it('renders a populated delta findings table, escaping each row exactly like the main table', () => {
    // Every delta test elsewhere in this file uses new_findings: [] — the
    // branch that actually builds a table row from a delta's own findings
    // (deltaRow) had ZERO coverage, including its own escapeHtml calls.
    // A regression here (e.g. deltaRow forgetting to escape title) would
    // have passed the whole suite silently.
    const html = renderDashboard(snap({
      deltas: {
        since_previous: { from_scan_id: 'a', to_scan_id: 'b', new_count: 1,
          resolved_count: 0, unchanged_count: 0,
          new_findings: [{ fingerprint: 'nd1', severity: 'critical',
            title: '<b>new</b> injection', tool: 'semgrep', rule_id: 'r',
            category: 'security', file_path: 'new.ts', line_start: 9 } as never] },
        since_baseline: null,
      },
    }));
    const visible = html.replace(/<script type="application\/json"[\s\S]*?<\/script>/g, '');
    expect(visible).not.toMatch(/<b>new<\/b>/);
    expect(visible).toMatch(/&lt;b&gt;new/);
    expect(visible).toMatch(/new\.ts:9/);
  });

  it('renders a delta finding missing fields the type marks required, without crashing', () => {
    // Minor from fix round 1's review: deltaRow's `?? fallback` branches
    // had no test of their own, unlike findingRow's identical-shaped ones
    // (exercised by the brief's own `as never` fixtures). Cheap to close
    // while already in this file.
    const html = renderDashboard(snap({
      deltas: {
        since_previous: { from_scan_id: 'a', to_scan_id: 'b', new_count: 1,
          resolved_count: 0, unchanged_count: 0,
          new_findings: [{ fingerprint: 'nd2', tool: 'semgrep', rule_id: 'r',
            category: 'security' } as never] },
        since_baseline: null,
      },
    }));
    const visible = html.replace(/<script type="application\/json"[\s\S]*?<\/script>/g, '');
    expect(visible).not.toMatch(/undefined|NaN/);
  });

  it('shows active suppressions with none currently expiring soon, without an empty expiring-soon table', () => {
    // active_count counts ALL active suppressions; expiring_soon is the
    // subset due within 7 days — active_count > 0 with expiring_soon: []
    // is a normal, common state, untested elsewhere in this file (the
    // dedicated suppression-reason test always populates expiring_soon).
    const html = renderDashboard(snap({
      suppressions: { active_count: 5, expiring_soon: [] },
    }));
    const visible = html.replace(/<script type="application\/json"[\s\S]*?<\/script>/g, '');
    expect(visible).not.toMatch(/undefined|NaN/);
    expect(visible).toMatch(/5 active/);
    expect(visible).not.toMatch(/Expiring within 7 days/);
  });
});

// ---------------------------------------------------------------------------
// Beyond the brief: exercise the interaction script itself.
//
// Every test above operates on the STRING renderDashboard returns — none of
// them execute a single line of the inline script. Filtering and sorting are
// the reason this is a page and not a text dump, and a script that throws on
// load leaves the user the empty shell of a table with no error anywhere —
// silent breakage the brief's string-matching tests cannot see, because they
// never run the code.
//
// No new dependency (no jsdom): a small hand-rolled DOM shim, sized to
// exactly the surface the script uses (getElementById/createElement,
// appendChild, addEventListener, textContent, value, style.display,
// getAttribute). Row elements are NOT hand-built from scratch — their
// data-* attributes are extracted from renderDashboard's ACTUAL output via
// a small regex reader, so a change to the real row markup that stops
// emitting an attribute the script depends on shows up here too, not just a
// hand-maintained fixture drifting from reality.
// ---------------------------------------------------------------------------
describe('renderDashboard — the interaction script itself', () => {
  class FakeElement {
    tagName: string;
    children: FakeElement[] = [];
    parentNode: FakeElement | null = null;
    value = '';
    style: { display: string } = { display: '' };
    className = '';
    private text = '';
    private attrs = new Map<string, string>();
    private listeners = new Map<string, Array<() => void>>();

    constructor(tag: string) {
      this.tagName = tag.toUpperCase();
    }

    get textContent(): string {
      return this.text;
    }

    set textContent(v: string) {
      this.text = v;
    }

    /** No HTML parser in this shim, deliberately: assigning innerHTML throws
     *  rather than silently no-opping. The plausible-wrong implementation of
     *  the expand-detail feature is `cell.innerHTML = template + f.message`
     *  — the exact client-side mirror of the server escaping hazard. If it
     *  used innerHTML, this throws from inside the click handler and the
     *  "does not throw" assertion in the expand-detail test below fails;
     *  silently ignoring the assignment (e.g. a no-op setter, or no setter
     *  at all so JS just stores a dead plain property) would let that wrong
     *  implementation pass by accident. */
    set innerHTML(_v: string) {
      throw new Error('FakeElement has no HTML parser — use createElement/textContent');
    }

    /** Mirrors the real DOM's re-parenting behaviour: appending a node that
     *  is already attached elsewhere MOVES it (removes it from its current
     *  parent first) rather than duplicating it. This matters specifically
     *  for the sort test below: the production script re-sorts by calling
     *  tbody.appendChild(row) on already-attached rows in the new order —
     *  without this, a naive push-only shim would leave every row
     *  duplicated after the first sort. */
    appendChild(child: FakeElement): FakeElement {
      if (child.parentNode) {
        const i = child.parentNode.children.indexOf(child);
        if (i !== -1) child.parentNode.children.splice(i, 1);
      }
      child.parentNode = this;
      this.children.push(child);
      return child;
    }

    setAttribute(name: string, value: string): void {
      this.attrs.set(name, value);
    }

    getAttribute(name: string): string | null {
      return this.attrs.get(name) ?? null;
    }

    addEventListener(type: string, fn: () => void): void {
      const list = this.listeners.get(type) ?? [];
      list.push(fn);
      this.listeners.set(type, list);
    }

    fire(type: string): void {
      for (const fn of this.listeners.get(type) ?? []) fn();
    }
  }

  class FakeDocument {
    private byId = new Map<string, FakeElement>();

    register(id: string, el: FakeElement): FakeElement {
      this.byId.set(id, el);
      return el;
    }

    getElementById(id: string): FakeElement | null {
      return this.byId.get(id) ?? null;
    }

    createElement(tag: string): FakeElement {
      return new FakeElement(tag);
    }
  }

  /** Extracts each rendered <tr>'s data-* attributes straight out of the
   *  REAL html string (not a hand-maintained parallel fixture), and wraps
   *  them in FakeElements with 5 empty <td> children — matching the real
   *  row's column count — so the detail-expand code under test has a title
   *  cell (index 3) to append into. */
  function extractRows(html: string): FakeElement[] {
    const tbodyMatch = html.match(/<tbody id="pdk-findings-body">([\s\S]*?)<\/tbody>/);
    const body = tbodyMatch?.[1] ?? '';
    const rows: FakeElement[] = [];
    for (const rowMatch of body.matchAll(/<tr([^>]*)>/g)) {
      const attrText = rowMatch[1] ?? '';
      const el = new FakeElement('tr');
      for (const attrMatch of attrText.matchAll(/(data-[a-z-]+)="([^"]*)"/g)) {
        const name = attrMatch[1];
        const value = attrMatch[2];
        if (name !== undefined && value !== undefined) el.setAttribute(name, value);
      }
      for (let i = 0; i < 5; i++) el.appendChild(new FakeElement('td'));
      rows.push(el);
    }
    return rows;
  }

  function extractScript(html: string, id: string): string {
    const m = html.match(new RegExp(`<script id="${id}">([\\s\\S]*?)</script>`));
    if (!m || m[1] === undefined) throw new Error(`no <script id="${id}"> found`);
    return m[1];
  }

  /** Wires a rendered dashboard's findings table + filters + the extracted
   *  interaction script together against the FakeDocument shim, and runs it
   *  — exactly what a browser does on page load, minus the browser. */
  function mount(html: string): { doc: FakeDocument; tbody: FakeElement;
    severitySelect: FakeElement; titleHeader: FakeElement } {
    const doc = new FakeDocument();
    const tbody = new FakeElement('tbody');
    for (const row of extractRows(html)) tbody.appendChild(row);
    doc.register('pdk-findings-body', tbody);

    const dataMatch = html.match(
      /<script type="application\/json" id="guardian-data">([\s\S]*?)<\/script>/,
    );
    const dataEl = new FakeElement('script');
    dataEl.textContent = dataMatch?.[1] ?? '{}';
    doc.register('guardian-data', dataEl);

    const severitySelect = new FakeElement('select');
    doc.register('pdk-filter-severity', severitySelect);
    doc.register('pdk-filter-tool', new FakeElement('select'));
    doc.register('pdk-filter-category', new FakeElement('select'));
    doc.register('pdk-filter-file', new FakeElement('input'));
    doc.register('pdk-findings-count', new FakeElement('span'));
    doc.register('pdk-findings-empty', new FakeElement('p'));
    const titleHeader = new FakeElement('th');
    doc.register('pdk-th-title', titleHeader);
    doc.register('pdk-th-severity', new FakeElement('th'));
    doc.register('pdk-th-tool', new FakeElement('th'));
    doc.register('pdk-th-file', new FakeElement('th'));

    const script = extractScript(html, 'guardian-interactions');
    // eslint-disable-next-line @typescript-eslint/no-implied-eval -- test-only sandbox execution
    const run = new Function('document', script) as (d: FakeDocument) => void;
    run(doc);

    return { doc, tbody, severitySelect, titleHeader };
  }

  function fixtureHtml(): string {
    return renderDashboard(snap({
      findings: {
        total: 3,
        by_severity: { critical: 2, high: 0, medium: 0, low: 1, info: 0 },
        by_category: { security: 3 },
        by_tool: { semgrep: 2, trivy: 1 },
        hotspots: [],
        items: [
          { fingerprint: 'f1', severity: 'critical', title: 'Zeta issue',
            tool: 'semgrep', rule_id: 'r1', category: 'security',
            file_path: 'z.ts', message: 'm1', line_start: 10 } as never,
          { fingerprint: 'f2', severity: 'low', title: 'Alpha issue',
            tool: 'trivy', rule_id: 'r2', category: 'security',
            file_path: 'a.ts', message: '<img src=x onerror=alert(9)>',
            line_start: 2 } as never,
          { fingerprint: 'f3', severity: 'critical', title: 'Mid issue',
            tool: 'semgrep', rule_id: 'r3', category: 'security',
            file_path: 'm.ts', message: 'm3', line_start: 5 } as never,
        ],
      },
    }));
  }

  it('the extracted script has no syntax error and executes without throwing', () => {
    const html = fixtureHtml();
    expect(() => mount(html)).not.toThrow();
  });

  it('never builds row content via innerHTML — the exact client-side version of the server escaping hazard', () => {
    // The plausible-wrong implementation: `cell.innerHTML = template + f.title`,
    // mirroring the server-side hazard the brief's own escaping test guards
    // against, but on the client. A DOM built through createElement/textContent
    // cannot parse a string as markup, no matter what the string contains;
    // one built through innerHTML string-concatenation can, and typically does
    // by accident.
    const script = extractScript(fixtureHtml(), 'guardian-interactions');
    expect(script).not.toMatch(/\.innerHTML/);
  });

  it('an empty document (no findings table on the page) does not make the script throw', () => {
    // scan: null renders no findings table at all (see the "scanned nothing"
    // test) — getElementById('pdk-findings-body') returns null in a real
    // browser too. A script that assumes the table always exists throws here.
    const html = renderDashboard(snap({
      scan: null,
      coverage: { level: 'none', tools_run: [], missing_tools: [], omitted_categories: [] },
    }));
    const doc = new FakeDocument();
    const dataMatch = html.match(
      /<script type="application\/json" id="guardian-data">([\s\S]*?)<\/script>/,
    );
    const dataEl = new FakeElement('script');
    dataEl.textContent = dataMatch?.[1] ?? '{}';
    doc.register('guardian-data', dataEl);
    const script = extractScript(html, 'guardian-interactions');
    const run = new Function('document', script) as (d: FakeDocument) => void;
    expect(() => run(doc)).not.toThrow();
  });

  it('a corrupted data payload does not throw, and the already-rendered rows are untouched', () => {
    // The more realistic failure than a missing table: the table renders
    // fine, but JSON.parse on the payload throws (a future edit breaks the
    // payload's shape, a browser extension mangles the page, anything). This
    // is the direct test of the self-review's central claim: on ANY failure
    // in this script, the user sees the already-rendered DATA, not an empty
    // table — because the table was never the script's to build in the
    // first place. Snapshot BEFORE running the script and compare after: if
    // the rows were ever cleared or rebuilt, this would catch it even though
    // "does not throw" alone would not.
    const html = fixtureHtml();
    const rowsBefore = extractRows(html).map((r) => ({
      fp: r.getAttribute('data-fp'),
      severity: r.getAttribute('data-severity'),
    }));

    const doc = new FakeDocument();
    const tbody = new FakeElement('tbody');
    for (const row of extractRows(html)) tbody.appendChild(row);
    doc.register('pdk-findings-body', tbody);
    const dataEl = new FakeElement('script');
    dataEl.textContent = '{not valid json'; // JSON.parse throws on this
    doc.register('guardian-data', dataEl);
    const script = extractScript(html, 'guardian-interactions');
    const run = new Function('document', script) as (d: FakeDocument) => void;

    expect(() => run(doc)).not.toThrow();

    const rowsAfter = tbody.children.map((r) => ({
      fp: r.getAttribute('data-fp'),
      severity: r.getAttribute('data-severity'),
    }));
    expect(rowsAfter).toEqual(rowsBefore);
  });

  it('filtering by severity hides non-matching rows and updates the visible count', () => {
    const { doc, tbody, severitySelect } = mount(fixtureHtml());
    expect(tbody.children).toHaveLength(3);

    severitySelect.value = 'critical';
    severitySelect.fire('change');

    const visible = tbody.children.filter((r) => r.style.display !== 'none');
    expect(visible).toHaveLength(2);
    expect(visible.map((r) => r.getAttribute('data-fp')).sort()).toEqual(['f1', 'f3']);
    const hidden = tbody.children.filter((r) => r.style.display === 'none');
    expect(hidden.map((r) => r.getAttribute('data-fp'))).toEqual(['f2']);

    // The live counter must track the FILTERED count, not just exist —
    // a counter that never updates would still pass every assertion above.
    const countEl = doc.getElementById('pdk-findings-count');
    expect(countEl).not.toBeNull();
    expect(countEl?.textContent).toMatch(/2/);
  });

  it('sorting by title reorders the existing rows into alphabetical order', () => {
    const { tbody, titleHeader } = mount(fixtureHtml());
    const before = tbody.children.map((r) => r.getAttribute('data-fp'));
    expect(before).toEqual(['f1', 'f2', 'f3']); // server order: as given, unsorted by title

    titleHeader.fire('click');

    const after = tbody.children.map((r) => r.getAttribute('data-fp'));
    // Alpha issue (f2) < Mid issue (f3) < Zeta issue (f1)
    expect(after).toEqual(['f2', 'f3', 'f1']);
  });

  it('clicking a sorted column a second time reverses the order', () => {
    const { tbody, titleHeader } = mount(fixtureHtml());
    titleHeader.fire('click');
    const ascending = tbody.children.map((r) => r.getAttribute('data-fp'));
    titleHeader.fire('click');
    const descending = tbody.children.map((r) => r.getAttribute('data-fp'));
    expect(descending).toEqual([...ascending].reverse());
  });

  it('expanding a row with a malicious message renders it as inert text, never as markup', () => {
    // The dynamic counterpart of the brief's static escaping test. f2's
    // message ALSO reaches the static document (as an escaped `title`
    // attribute — a native hover tooltip, see findingRow's `titleAttr`), so
    // that path is already covered by the static escaping tests above. This
    // test is about the SEPARATE path: the click-to-expand detail box, built
    // entirely by this script from the JSON payload, which the brief's own
    // string-matching tests never execute at all.
    //
    // The plausible-wrong implementation is `cell.innerHTML = template +
    // f.message`, the client-side mirror of the server hazard. FakeElement's
    // `innerHTML` setter throws (see its definition above) precisely so that
    // implementation fails HERE, not silently: the two assertions below both
    // fail against it — the click throws instead of completing, and even if
    // the throw were swallowed, no text would ever have reached textContent.
    const { tbody } = mount(fixtureHtml());
    const row = tbody.children.find((r) => r.getAttribute('data-fp') === 'f2');
    expect(row).toBeDefined();
    if (row === undefined) throw new Error('row f2 not found');

    expect(() => row.fire('click')).not.toThrow(); // expand

    const titleCell = row.children[3];
    expect(titleCell).toBeDefined();
    if (titleCell === undefined) throw new Error('title cell missing');
    // The detail box was appended as a child; find text containing the
    // raw (unescaped) malicious string somewhere in the cell's subtree —
    // proving the message reached the page as DATA, not as an unwrapped
    // string dropped straight into markup.
    const texts = collectText(titleCell);
    expect(texts.some((t) => t.includes('<img src=x onerror=alert(9)>'))).toBe(true);
  });

  it('expanding a row with a malicious snippet also renders it as inert text', () => {
    // The same hazard, the other optional detail field. message and snippet
    // are two separate createElement/textContent calls in the production
    // script's wireExpand — a bug in just one of them (e.g. someone
    // "optimising" only the snippet branch into a string concatenation
    // later) would not be caught by the message-only test above.
    const html = renderDashboard(snap({
      findings: {
        total: 1,
        by_severity: { critical: 0, high: 1, medium: 0, low: 0, info: 0 },
        by_category: { security: 1 }, by_tool: { semgrep: 1 }, hotspots: [],
        items: [{ fingerprint: 'f9', severity: 'high', title: 'Snippet finding',
          tool: 'semgrep', rule_id: 'r9', category: 'security', file_path: 's.ts',
          message: 'm9', snippet: '<script>alert(7)</script>', line_start: 1 } as never],
      },
    }));
    const { tbody } = mount(html);
    const row = tbody.children.find((r) => r.getAttribute('data-fp') === 'f9');
    expect(row).toBeDefined();
    if (row === undefined) throw new Error('row f9 not found');

    expect(() => row.fire('click')).not.toThrow();

    const titleCell = row.children[3];
    expect(titleCell).toBeDefined();
    if (titleCell === undefined) throw new Error('title cell missing');
    const texts = collectText(titleCell);
    expect(texts.some((t) => t.includes('<script>alert(7)</script>'))).toBe(true);
  });

  function collectText(el: FakeElement): string[] {
    const own = el.textContent;
    const fromChildren = el.children.flatMap((c) => collectText(c));
    return own.length > 0 ? [own, ...fromChildren] : fromChildren;
  }
});
