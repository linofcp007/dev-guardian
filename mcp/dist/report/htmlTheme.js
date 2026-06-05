/**
 * Shared branded HTML shell for dev-guardian reports — Pro Digital Key identity.
 *
 * One shell, two consumers (the scan `report_export` HTML and the stakeholder
 * `/guardian-report` narrative) so every report looks identical. Self-contained:
 * inline CSS + a ~15-line inline theme toggle, NO external assets (no web fonts,
 * no <link>, no network) so it honours the "local · no telemetry" promise and
 * opens offline in any browser.
 *
 * Theming mirrors the website (src/assets/css/styles.css): dark-first with a
 * `[data-theme]` override. Default follows the OS via prefers-color-scheme;
 * the toggle persists an explicit choice in localStorage.
 */
const SHARED = { '--accent': '#00AAFF', '--brand-blue': '#11689B' };
const DARK = {
    '--bg-primary': '#040405',
    '--bg-secondary': '#0A0A0C',
    '--bg-tertiary': '#121216',
    '--text-main': '#FFFFFF',
    '--text-muted': '#8A91A5',
    '--border': 'rgba(74,144,226,0.15)',
    ...SHARED,
};
const LIGHT = {
    '--bg-primary': '#F8F9FA',
    '--bg-secondary': '#FFFFFF',
    '--bg-tertiary': '#E9ECEF',
    '--text-main': '#1A1D20',
    '--text-muted': '#6C757D',
    '--border': 'rgba(74,144,226,0.25)',
    ...SHARED,
};
/** Severity → solid chip colours (background-independent, legible on both themes). */
export const SEVERITY_COLORS = {
    critical: { bg: '#B3001B', fg: '#FFFFFF' },
    high: { bg: '#FF6B6B', fg: '#1A0000' },
    medium: { bg: '#FFD700', fg: '#1A1D20' },
    low: { bg: '#00AAFF', fg: '#00121F' },
    info: { bg: '#8A91A5', fg: '#0A0A0C' },
};
function chipColor(sev) {
    return SEVERITY_COLORS[sev] ?? SEVERITY_COLORS.info;
}
export function escapeHtml(s) {
    return s
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}
/** A coloured severity chip (`<span>`), used for finding rows. */
export function severityChip(sev, label) {
    const c = chipColor(sev);
    return `<span class="pdk-chip" style="background:${c.bg};color:${c.fg};">${escapeHtml(label ?? sev)}</span>`;
}
/** A horizontal severity-distribution bar sized by counts. */
export function severityBar(counts) {
    const parts = ['critical', 'high', 'medium', 'low', 'info']
        .map((s) => {
        const n = counts[s] ?? 0;
        if (n === 0)
            return '';
        const c = chipColor(s);
        return `<div style="flex:${n};background:${c.bg};color:${c.fg};display:flex;align-items:center;justify-content:center;font-size:12px;font-weight:600;padding:4px 6px;">${s}: ${n}</div>`;
    })
        .join('');
    return `<div class="pdk-bar">${parts}</div>`;
}
function cssVars(obj) {
    return Object.entries(obj)
        .map(([k, v]) => `  ${k}: ${v};`)
        .join('\n');
}
function baseCss() {
    return `
* { box-sizing: border-box; }
:root {
  color-scheme: dark light;
${cssVars(DARK)}
}
@media (prefers-color-scheme: light) {
  :root:not([data-theme="dark"]) {
${cssVars(LIGHT)}
  }
}
:root[data-theme="light"] {
${cssVars(LIGHT)}
}
:root[data-theme="dark"] {
${cssVars(DARK)}
}
body { margin: 0; background: var(--bg-primary); color: var(--text-main);
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Inter, Helvetica, Arial, sans-serif;
  line-height: 1.55; transition: background-color .2s, color .2s; }
.pdk-header { display: flex; align-items: center; justify-content: space-between;
  padding: 14px 24px; background: var(--bg-secondary); border-bottom: 1px solid var(--border);
  position: sticky; top: 0; z-index: 10; }
.pdk-brand { font-weight: 700; letter-spacing: .2px; color: var(--brand-blue);
  display: flex; align-items: center; gap: 8px; }
.pdk-dot { width: 10px; height: 10px; border-radius: 50%; background: var(--accent);
  box-shadow: 0 0 10px var(--accent); }
.pdk-toggle { cursor: pointer; border: 1px solid var(--border); background: var(--bg-tertiary);
  color: var(--text-main); border-radius: 8px; padding: 4px 11px; font-size: 15px; line-height: 1; }
.pdk-main { max-width: 1080px; margin: 0 auto; padding: 28px 24px 56px; }
.pdk-title { margin: .2em 0 .1em; font-size: 1.7rem; }
.pdk-subtitle { color: var(--text-muted); margin: 0 0 1.4em; }
.pdk-meta { color: var(--text-muted); font-size: 14px; margin-bottom: 1.5em; }
.pdk-meta strong { color: var(--text-main); }
h2 { margin: 1.8em 0 .6em; font-size: 1.15rem; border-bottom: 1px solid var(--border); padding-bottom: .3em; }
h3 { margin: 1.3em 0 .4em; font-size: 1rem; }
a { color: var(--accent); }
code { background: var(--bg-tertiary); padding: 2px 5px; border-radius: 4px;
  font-family: ui-monospace, SFMono-Regular, Consolas, monospace; font-size: .86em; }
pre { background: var(--bg-tertiary); padding: 14px 16px; border-radius: 8px; overflow: auto;
  border: 1px solid var(--border); }
pre code { background: none; padding: 0; }
table { width: 100%; border-collapse: collapse; margin: 1em 0 1.6em; font-size: .92rem; }
th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid var(--border); vertical-align: top; }
th { background: var(--bg-tertiary); font-weight: 600; }
tbody tr:hover { background: var(--bg-secondary); }
blockquote { margin: 1em 0; padding: .4em 1em; border-left: 3px solid var(--accent);
  color: var(--text-muted); background: var(--bg-secondary); border-radius: 0 6px 6px 0; }
hr { border: none; border-top: 1px solid var(--border); margin: 2em 0; }
.pdk-bar { display: flex; border-radius: 8px; overflow: hidden; margin: 1em 0 1.6em;
  min-height: 30px; border: 1px solid var(--border); }
.pdk-chip { padding: 2px 9px; border-radius: 999px; font-size: 11px; font-weight: 600; white-space: nowrap; }
.pdk-empty { color: var(--text-muted); font-style: italic; }
.pdk-footer { max-width: 1080px; margin: 0 auto; padding: 18px 24px; color: var(--text-muted);
  font-size: 12px; border-top: 1px solid var(--border); }
@media print {
  :root, :root[data-theme="dark"], :root[data-theme="light"] {
    color-scheme: light;
${cssVars(LIGHT)}
  }
  body { background: #fff; color: #000; }
  .pdk-header { position: static; }
  .pdk-toggle { display: none; }
  a { color: #000; text-decoration: underline; }
  table, tr, pre, blockquote, .pdk-bar { break-inside: avoid; }
}
`.trim();
}
function toggleScript() {
    // Inline, dependency-free. Reads an explicit choice from localStorage; otherwise
    // CSS falls back to prefers-color-scheme. The button shows the target theme's icon.
    return `<script>
(function(){
  var KEY='pdk-report-theme', root=document.documentElement, btn=document.getElementById('pdk-theme-toggle');
  try{ var saved=localStorage.getItem(KEY); if(saved){ root.setAttribute('data-theme', saved); } }catch(e){}
  function current(){
    var a=root.getAttribute('data-theme');
    if(a){ return a; }
    return (window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches) ? 'light' : 'dark';
  }
  function paint(){ if(btn){ btn.textContent = current()==='light' ? '\\u263e' : '\\u2600'; } }
  paint();
  if(btn){ btn.addEventListener('click', function(){
    var next = current()==='light' ? 'dark' : 'light';
    root.setAttribute('data-theme', next);
    try{ localStorage.setItem(KEY, next); }catch(e){}
    paint();
  }); }
})();
</script>`;
}
const FOOTER = {
    en: 'generated locally &middot; no telemetry',
    pt: 'gerado localmente &middot; sem telemetria',
    es: 'generado localmente &middot; sin telemetría',
};
/** Wrap pre-rendered section HTML in the branded, self-contained shell. */
export function renderHtmlDocument(doc) {
    const lang = doc.lang ?? 'en';
    const subtitle = doc.subtitle ? `<p class="pdk-subtitle">${escapeHtml(doc.subtitle)}</p>` : '';
    return `<!DOCTYPE html>
<html lang="${lang}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(doc.title)}</title>
<script>(function(){try{var t=localStorage.getItem('pdk-report-theme');if(t){document.documentElement.setAttribute('data-theme',t);}}catch(e){}})();</script>
<style>
${baseCss()}
</style>
</head>
<body>
<header class="pdk-header">
  <div class="pdk-brand"><span class="pdk-dot"></span>Pro Digital Key</div>
  <button id="pdk-theme-toggle" class="pdk-toggle" type="button" aria-label="Toggle dark / light theme">☀</button>
</header>
<main class="pdk-main">
  <h1 class="pdk-title">${escapeHtml(doc.title)}</h1>
  ${subtitle}
  ${doc.sections.join('\n  ')}
</main>
<footer class="pdk-footer">Pro Digital Key &middot; ${FOOTER[lang]}</footer>
${toggleScript()}
</body>
</html>`;
}
/* ------------------------------------------------------------------ */
/* Minimal, dependency-free Markdown → safe HTML (stakeholder reports) */
/* ------------------------------------------------------------------ */
function sanitizeUrl(u) {
    const t = u.trim();
    if (/^(https?:|mailto:|#|\/|\.\/|\.\.\/)/i.test(t))
        return t.replace(/"/g, '%22');
    if (/^[\w./#?=&%-]+$/.test(t))
        return t; // bare relative path
    return null;
}
/** Inline spans: escape first, then code / links / bold / italic.
 *  Code spans are stashed behind an ASCII token so later passes can't touch them. */
function inline(raw) {
    let s = escapeHtml(raw);
    const codes = [];
    s = s.replace(/`([^`]+)`/g, (_m, c) => {
        codes.push(`<code>${c}</code>`);
        return `[[[CODE_${codes.length - 1}]]]`;
    });
    s = s.replace(/\[([^\]]+)\]\(([^)\s]+)\)/g, (_m, text, url) => {
        const safe = sanitizeUrl(url);
        return safe ? `<a href="${safe}">${text}</a>` : text;
    });
    s = s.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
    s = s.replace(/\*([^*]+)\*/g, '<em>$1</em>');
    s = s.replace(/\[\[\[CODE_(\d+)\]\]\]/g, (_m, i) => codes[Number(i)] ?? '');
    return s;
}
const TABLE_SEP = /^\s*\|?\s*:?-{1,}:?\s*(\|\s*:?-{1,}:?\s*)+\|?\s*$/;
const HR = /^(\*\s*){3,}$|^(-\s*){3,}$|^(_\s*){3,}$/;
function splitRow(line) {
    let l = line.trim();
    if (l.startsWith('|'))
        l = l.slice(1);
    if (l.endsWith('|'))
        l = l.slice(0, -1);
    return l.split('|').map((c) => c.trim());
}
function renderTable(header, rows) {
    const th = header.map((c) => `<th>${inline(c)}</th>`).join('');
    const trs = rows
        .map((r) => `<tr>${r.map((c) => `<td>${inline(c)}</td>`).join('')}</tr>`)
        .join('');
    return `<table><thead><tr>${th}</tr></thead><tbody>${trs}</tbody></table>`;
}
function isBlockStart(line, next) {
    return (/^```/.test(line.trim()) ||
        /^#{1,6}\s/.test(line) ||
        /^>\s?/.test(line) ||
        /^\s*[-*+]\s+/.test(line) ||
        /^\s*\d+\.\s+/.test(line) ||
        HR.test(line.trim()) ||
        (line.includes('|') && TABLE_SEP.test(next)));
}
/** Convert a Markdown subset to safe HTML. Unsupported syntax degrades to text. */
export function markdownToSafeHtml(md) {
    const lines = md.replace(/\r\n?/g, '\n').split('\n');
    const at = (n) => lines[n] ?? '';
    const out = [];
    let i = 0;
    while (i < lines.length) {
        const line = at(i);
        if (line.trim() === '') {
            i++;
            continue;
        }
        if (/^```/.test(line.trim())) {
            const buf = [];
            i++;
            while (i < lines.length && !/^```/.test(at(i).trim())) {
                buf.push(at(i));
                i++;
            }
            i++; // closing fence
            out.push(`<pre><code>${escapeHtml(buf.join('\n'))}</code></pre>`);
            continue;
        }
        const heading = /^(#{1,6})\s+(.*)$/.exec(line);
        if (heading) {
            const level = Math.min(heading[1]?.length ?? 1, 6);
            out.push(`<h${level}>${inline((heading[2] ?? '').trim())}</h${level}>`);
            i++;
            continue;
        }
        if (HR.test(line.trim())) {
            out.push('<hr>');
            i++;
            continue;
        }
        if (line.includes('|') && TABLE_SEP.test(at(i + 1))) {
            const header = splitRow(line);
            i += 2;
            const rows = [];
            while (i < lines.length && at(i).includes('|') && at(i).trim() !== '') {
                rows.push(splitRow(at(i)));
                i++;
            }
            out.push(renderTable(header, rows));
            continue;
        }
        if (/^>\s?/.test(line)) {
            const buf = [];
            while (i < lines.length && /^>\s?/.test(at(i))) {
                buf.push(at(i).replace(/^>\s?/, ''));
                i++;
            }
            out.push(`<blockquote>${inline(buf.join(' '))}</blockquote>`);
            continue;
        }
        if (/^\s*[-*+]\s+/.test(line)) {
            const items = [];
            while (i < lines.length && /^\s*[-*+]\s+/.test(at(i))) {
                items.push(inline(at(i).replace(/^\s*[-*+]\s+/, '')));
                i++;
            }
            out.push(`<ul>${items.map((x) => `<li>${x}</li>`).join('')}</ul>`);
            continue;
        }
        if (/^\s*\d+\.\s+/.test(line)) {
            const items = [];
            while (i < lines.length && /^\s*\d+\.\s+/.test(at(i))) {
                items.push(inline(at(i).replace(/^\s*\d+\.\s+/, '')));
                i++;
            }
            out.push(`<ol>${items.map((x) => `<li>${x}</li>`).join('')}</ol>`);
            continue;
        }
        const para = [];
        while (i < lines.length && at(i).trim() !== '' && !isBlockStart(at(i), at(i + 1))) {
            para.push(at(i));
            i++;
        }
        out.push(`<p>${inline(para.join(' '))}</p>`);
    }
    return out.join('\n');
}
//# sourceMappingURL=htmlTheme.js.map