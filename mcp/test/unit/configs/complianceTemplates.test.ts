/**
 * The RGPD templates `guardian-compliance` points people at:
 * `configs/compliance/cookie-banner/` and
 * `configs/compliance/privacy-policy-template.md`.
 *
 * The banner's compliance-relevant behaviour lives in pure helpers the script
 * exports under CommonJS (it runs as a plain browser script otherwise), so it
 * is exercised here in a bare `vm` context — no DOM, no dependency:
 *
 *   - what Google Consent Mode v2 receives for each choice (default denied;
 *     analytics and marketing map to different storage keys);
 *   - that a stored choice expires and is re-asked when the policy version
 *     changes, and that anything but a literal `true` reads as a refusal;
 *   - that the pt-PT and English string tables have the same keys, so a
 *     missing translation cannot leave a button without a label.
 *
 * The rest is a static contract over the files: the demo page declares the
 * denied defaults before any other script and loads every tracker blocked,
 * and the privacy policy carries what RGPD arts. 13 and 14 require, with its
 * placeholders in one greppable syntax. That the demo page also passes the
 * RGPD Semgrep pack is asserted in `test/integration/rgpdRules.test.ts`.
 */

import { existsSync, readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { runInNewContext } from 'node:vm';
import { describe, expect, it } from 'vitest';

const here = dirname(fileURLToPath(import.meta.url));
/** configs -> unit -> test -> mcp -> repo root. */
const REPO_ROOT = resolve(here, '..', '..', '..', '..');
const BANNER_DIR = resolve(REPO_ROOT, 'configs', 'compliance', 'cookie-banner');
const POLICY = resolve(REPO_ROOT, 'configs', 'compliance', 'privacy-policy-template.md');

type Choice = Record<string, unknown>;

interface BannerApi {
  CATEGORIES: string[];
  STRINGS: Record<string, Record<string, string>>;
  resolveLang(requested: unknown, documentLang: unknown): string;
  stringsFor(lang: string, overrides?: unknown): Record<string, string>;
  consentModeState(choice: Choice | null): Record<string, string>;
  readRecord(raw: unknown, version: number, maxAgeDays: number, now: number): Record<string, boolean> | null;
  makeRecord(choice: Choice, version: number, now: number): string;
  safeUrl(url: unknown): string | null;
}

function loadBanner(): BannerApi {
  const sandbox: { module: { exports: unknown } } = { module: { exports: {} } };
  runInNewContext(readFileSync(resolve(BANNER_DIR, 'cookie-banner.js'), 'utf8'), sandbox);
  return sandbox.module.exports as BannerApi;
}

const banner = loadBanner();
const DAY = 86_400_000;
const NOW = Date.parse('2026-09-25T12:00:00Z');

describe('cookie banner: Google Consent Mode v2 state', () => {
  it('denies everything when there is no choice, or an empty one', () => {
    const denied = { analytics_storage: 'denied', ad_storage: 'denied', ad_user_data: 'denied', ad_personalization: 'denied' };
    expect({ ...banner.consentModeState(null) }).toEqual(denied);
    expect({ ...banner.consentModeState({}) }).toEqual(denied);
  });

  it('grants analytics storage for analytics only, and nothing for ads', () => {
    expect({ ...banner.consentModeState({ analytics: true }) }).toEqual({
      analytics_storage: 'granted', ad_storage: 'denied', ad_user_data: 'denied', ad_personalization: 'denied',
    });
  });

  it('grants the three v2 ad signals for marketing only, and not analytics', () => {
    expect({ ...banner.consentModeState({ marketing: true }) }).toEqual({
      analytics_storage: 'denied', ad_storage: 'granted', ad_user_data: 'granted', ad_personalization: 'granted',
    });
  });
});

describe('cookie banner: the stored choice', () => {
  it('round-trips a choice', () => {
    const raw = banner.makeRecord({ analytics: true, marketing: false }, 1, NOW);
    expect({ ...banner.readRecord(raw, 1, 180, NOW + DAY) }).toEqual({ analytics: true, marketing: false });
  });

  it('asks again once the record is older than maxAgeDays', () => {
    const raw = banner.makeRecord({ analytics: true, marketing: true }, 1, NOW);
    expect(banner.readRecord(raw, 1, 180, NOW + 181 * DAY)).toBeNull();
  });

  it('asks again when the policy version changed', () => {
    const raw = banner.makeRecord({ analytics: true, marketing: true }, 1, NOW);
    expect(banner.readRecord(raw, 2, 180, NOW)).toBeNull();
  });

  it('treats anything but a literal true as a refusal, and garbage as no record', () => {
    const tampered = JSON.stringify({ version: 1, date: new Date(NOW).toISOString(), choice: { analytics: 'true', marketing: 1 } });
    expect({ ...banner.readRecord(tampered, 1, 180, NOW) }).toEqual({ analytics: false, marketing: false });
    expect(banner.readRecord('{not json', 1, 180, NOW)).toBeNull();
    expect(banner.readRecord(null, 1, 180, NOW)).toBeNull();
    // A record dated in the future is not trusted either.
    expect(banner.readRecord(banner.makeRecord({ analytics: true }, 1, NOW + 10 * DAY), 1, 180, NOW)).toBeNull();
  });
});

describe('cookie banner: strings and links', () => {
  it('serves pt-PT for any Portuguese tag and English otherwise', () => {
    expect(banner.resolveLang(undefined, 'pt-PT')).toBe('pt-PT');
    expect(banner.resolveLang('pt', 'en')).toBe('pt-PT');
    expect(banner.resolveLang(undefined, 'en-GB')).toBe('en');
    expect(banner.resolveLang(undefined, undefined)).toBe('en');
    expect(banner.resolveLang(undefined, 'es')).toBe('en');
  });

  it('has the same keys in pt-PT and English, none empty', () => {
    const pt = banner.STRINGS['pt-PT'] ?? {};
    const en = banner.STRINGS['en'] ?? {};
    expect(Object.keys(pt).sort()).toEqual(Object.keys(en).sort());
    for (const table of [pt, en]) {
      for (const [key, value] of Object.entries(table)) expect([key, value.trim().length > 0]).toEqual([key, true]);
    }
    // Rejecting is offered on the first layer, in both languages.
    expect(pt['rejectAll']).toBe('Rejeitar todos');
    expect(en['rejectAll']).toBe('Reject all');
  });

  it("applies the site's overrides over the built-in strings", () => {
    const t = banner.stringsFor('en', { en: { title: 'Cookies at ACME' } });
    expect(t['title']).toBe('Cookies at ACME');
    expect(t['acceptAll']).toBe('Accept all');
  });

  it('only turns http(s) or site-relative URLs into the policy link', () => {
    expect(banner.safeUrl('/politica-de-privacidade')).toBe('/politica-de-privacidade');
    expect(banner.safeUrl('https://exemplo.pt/privacidade')).toBe('https://exemplo.pt/privacidade');
    expect(banner.safeUrl('javascript:alert(1)')).toBeNull();
    expect(banner.safeUrl('//evil.example/x')).toBeNull();
    expect(banner.safeUrl('')).toBeNull();
  });
});

describe('cookie banner: the demo page', () => {
  const html = readFileSync(resolve(BANNER_DIR, 'banner.html'), 'utf8');
  // Comments explain the integration and quote tags; the contract is about
  // the markup that runs.
  const markup = html.replace(/<!--[\s\S]*?-->/g, '');

  it('declares the Consent Mode v2 defaults, denied, in the FIRST script of the page', () => {
    const first = /<script\b[^>]*>([\s\S]*?)<\/script>/.exec(markup);
    expect(first?.[1]).toMatch(/gtag\('consent', 'default'/);
    for (const key of ['ad_storage', 'ad_user_data', 'ad_personalization', 'analytics_storage']) {
      expect(first?.[1]).toMatch(new RegExp(`'${key}': 'denied'`));
    }
  });

  it('loads every tracker blocked: text/plain scripts, iframes without a src', () => {
    const trackers = [...markup.matchAll(/<(script|iframe)\b[^>]*>(?:[\s\S]*?<\/\1>)?/g)]
      .map((m) => m[0])
      .filter((tag) => /googletagmanager|gtag\('(?:js|config)'|fbq\(|facebook\.net|youtube|hotjar/.test(tag));
    expect(trackers.length).toBeGreaterThanOrEqual(4);
    for (const tag of trackers) {
      expect(tag).toMatch(/data-consent-category="(analytics|marketing)"/);
      expect(tag).not.toMatch(/\ssrc=/);
      if (tag.startsWith('<script')) expect(tag).toMatch(/type="text\/plain"/);
    }
  });

  it('embeds video from the privacy-enhanced domain', () => {
    expect(markup).not.toMatch(/youtube\.com\/embed/);
    expect(markup).toMatch(/youtube-nocookie\.com\/embed/);
  });

  it('offers a way back to the choice, and ships the files it links', () => {
    expect(markup).toMatch(/data-cookie-preferences/);
    for (const [, file] of markup.matchAll(/(?:href|src)="(cookie-banner\.(?:css|js))"/g)) {
      expect(existsSync(resolve(BANNER_DIR, file ?? ''))).toBe(true);
    }
  });
});

describe('privacy policy template (pt-PT, RGPD arts. 13 and 14)', () => {
  const text = readFileSync(POLICY, 'utf8');

  it.each([
    ['controller identity and contacts (art. 13(1)(a))', /respons[aá]vel pelo tratamento/i],
    ['DPO contacts (art. 13(1)(b))', /encarregado da prote[cç][aã]o de dados/i],
    ['purposes and legal basis (art. 13(1)(c))', /fundamento \(art\. 6\.º/i],
    ['legitimate interests (art. 13(1)(d))', /interesses leg[ií]timos/i],
    ['recipients (art. 13(1)(e))', /com quem partilhamos/i],
    ['third-country transfers (art. 13(1)(f))', /fora do Espa[cç]o Econ[oó]mico Europeu/i],
    ['retention (art. 13(2)(a))', /prazo de conserva[cç][aã]o/i],
    ['access, rectification, erasure, restriction, portability, objection (art. 13(2)(b))', /Portabilidade[\s\S]*Oposi[cç][aã]o/],
    ['withdrawing consent (art. 13(2)(c))', /retirar o consentimento/i],
    ['complaint to the CNPD (art. 13(2)(d))', /Comiss[aã]o Nacional de Prote[cç][aã]o de Dados \(CNPD\)[\s\S]*www\.cnpd\.pt/],
    ['statutory or contractual requirement (art. 13(2)(e))', /Dados obrigat[oó]rios/],
    ['automated decision-making (art. 13(2)(f))', /decis[oõ]es automatizadas/i],
    ['categories of data (art. 14(1)(d))', /Que dados tratamos/],
    ['source of the data (art. 14(2)(f))', /de onde v[eê]m/],
    ['the Portuguese execution law', /Lei n\.º 58\/2019/],
  ])('covers %s', (_what, pattern) => {
    expect(text).toMatch(pattern);
  });

  it('marks every placeholder one greppable way, and leaves no other kind', () => {
    const placeholders = text.match(/\[\[(?:PREENCHER|REMOVER SE N[AÃ]O SE APLICAR)[^\]]*\]\]/g) ?? [];
    expect(placeholders.length).toBeGreaterThan(20);
    // Every `[[` opens one of the two marked forms.
    expect((text.match(/\[\[/g) ?? []).length).toBe(placeholders.length);
    expect(text).not.toMatch(/\bTODO\b|\bXXX\b|\bLorem\b/);
  });
});
