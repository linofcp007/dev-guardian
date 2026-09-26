/*!
 * dev-guardian cookie banner — vanilla JS, no dependencies, no network calls.
 *
 * What it guarantees:
 *   - NOTHING non-essential runs before a choice. Trackers are written in the
 *     page as <script type="text/plain" data-consent-category="analytics"> (or
 *     "marketing"), which the browser neither fetches nor executes, and as
 *     <iframe data-consent-category="marketing" data-src="...">. This script
 *     activates them only for the categories the visitor accepted.
 *   - Google Consent Mode v2: the page declares
 *     gtag('consent', 'default', { ... 'denied' ... }) BEFORE any tag (see
 *     banner.html); this script sends gtag('consent', 'update', ...) with the
 *     visitor's choice, and again on every later visit.
 *   - Rejecting is exactly as easy as accepting: both buttons on the first
 *     layer, same size, same style. No pre-ticked boxes.
 *   - Withdrawing is as easy as giving: any element with
 *     data-cookie-preferences reopens the choice (RGPD art. 7(3)).
 *   - The choice is stored in localStorage (the consent record itself is
 *     strictly necessary) and asked again after `maxAgeDays` or when
 *     `version` changes.
 *   - pt-PT and English strings; keyboard operable, focus managed, labelled
 *     for screen readers.
 *
 * Configure BEFORE this script loads (every key optional):
 *   window.dgCookieBanner = {
 *     lang: 'pt-PT' | 'en',          // default: <html lang>, else 'en'
 *     policyUrl: '/politica-de-privacidade',
 *     version: 1,                     // bump to ask everyone again
 *     maxAgeDays: 180,
 *     storageKey: 'dg-cookie-consent',
 *     strings: { 'pt-PT': { ... }, en: { ... } }   // override any text
 *   };
 *
 * Other code can wait for consent:
 *   document.addEventListener('dg:consent', function (event) {
 *     if (event.detail.analytics) { ... }
 *   });
 */
(function (root, factory) {
  var api = factory();
  if (typeof module === 'object' && module.exports) {
    module.exports = api; // pure helpers, for tests
  } else if (typeof document !== 'undefined') {
    api.start(root);
  }
})(typeof window !== 'undefined' ? window : this, function () {
  'use strict';

  var CATEGORIES = ['analytics', 'marketing'];

  var STRINGS = {
    'pt-PT': {
      title: 'Cookies neste site',
      description:
        'Usamos cookies estritamente necessários para o site funcionar. Com a sua autorização, ' +
        'usamos também cookies de análise (para medir visitas) e de marketing (para anúncios e ' +
        'vídeos incorporados). Pode aceitar, rejeitar ou escolher, e mudar de ideias a qualquer momento.',
      policy: 'Política de privacidade',
      acceptAll: 'Aceitar todos',
      rejectAll: 'Rejeitar todos',
      customize: 'Personalizar',
      preferencesTitle: 'Preferências de cookies',
      save: 'Guardar preferências',
      close: 'Fechar',
      necessaryLabel: 'Estritamente necessários',
      necessaryDescription: 'Sessão, segurança e o registo desta escolha. Sempre ativos.',
      analyticsLabel: 'Análise',
      analyticsDescription: 'Estatísticas de utilização (por exemplo, Google Analytics).',
      marketingLabel: 'Marketing',
      marketingDescription: 'Anúncios, pixels de conversão e vídeos de terceiros (por exemplo, Meta, YouTube).',
      placeholder: 'Este conteúdo usa cookies de marketing.',
      placeholderButton: 'Permitir e mostrar'
    },
    en: {
      title: 'Cookies on this site',
      description:
        'We use strictly necessary cookies to make the site work. With your permission, we also use ' +
        'analytics cookies (to measure visits) and marketing cookies (for ads and embedded videos). ' +
        'You can accept, reject or choose, and change your mind at any time.',
      policy: 'Privacy policy',
      acceptAll: 'Accept all',
      rejectAll: 'Reject all',
      customize: 'Customise',
      preferencesTitle: 'Cookie preferences',
      save: 'Save preferences',
      close: 'Close',
      necessaryLabel: 'Strictly necessary',
      necessaryDescription: 'Session, security and the record of this choice. Always on.',
      analyticsLabel: 'Analytics',
      analyticsDescription: 'Usage statistics (for example, Google Analytics).',
      marketingLabel: 'Marketing',
      marketingDescription: 'Ads, conversion pixels and third-party videos (for example, Meta, YouTube).',
      placeholder: 'This content uses marketing cookies.',
      placeholderButton: 'Allow and show'
    }
  };

  /** Cookie name prefixes each category's trackers set, removed when consent is withdrawn. */
  var COOKIE_PREFIXES = {
    analytics: ['_ga', '_gid', '_gat', '_hj'],
    marketing: ['_fbp', '_fbc', '_gcl', 'IDE', 'VISITOR_INFO1_LIVE', 'YSC']
  };

  /** 'pt-PT' for any Portuguese tag, 'en' otherwise. */
  function resolveLang(requested, documentLang) {
    var tag = String(requested || documentLang || 'en').toLowerCase();
    return tag.indexOf('pt') === 0 ? 'pt-PT' : 'en';
  }

  /** The string table for a language, with the site's overrides on top. */
  function stringsFor(lang, overrides) {
    var base = STRINGS[lang] || STRINGS.en;
    var extra = (overrides && overrides[lang]) || {};
    var out = {};
    var key;
    for (key in base) if (Object.prototype.hasOwnProperty.call(base, key)) out[key] = base[key];
    for (key in extra) if (Object.prototype.hasOwnProperty.call(extra, key)) out[key] = String(extra[key]);
    return out;
  }

  /** Google Consent Mode v2 state for a choice. Unknown categories are denied. */
  function consentModeState(choice) {
    var analytics = !!(choice && choice.analytics);
    var marketing = !!(choice && choice.marketing);
    return {
      analytics_storage: analytics ? 'granted' : 'denied',
      ad_storage: marketing ? 'granted' : 'denied',
      ad_user_data: marketing ? 'granted' : 'denied',
      ad_personalization: marketing ? 'granted' : 'denied'
    };
  }

  /** A stored record, or null when there is none, it is stale, or it is from another version. */
  function readRecord(raw, version, maxAgeDays, now) {
    if (typeof raw !== 'string' || raw === '') return null;
    var record;
    try {
      record = JSON.parse(raw);
    } catch (e) {
      return null;
    }
    if (!record || record.version !== version || typeof record.date !== 'string') return null;
    var age = (now - Date.parse(record.date)) / 86400000;
    if (!(age >= 0) || age > maxAgeDays) return null;
    var choice = {};
    for (var i = 0; i < CATEGORIES.length; i += 1) choice[CATEGORIES[i]] = record.choice && record.choice[CATEGORIES[i]] === true;
    return choice;
  }

  function makeRecord(choice, version, now) {
    var stored = {};
    for (var i = 0; i < CATEGORIES.length; i += 1) stored[CATEGORIES[i]] = !!choice[CATEGORIES[i]];
    return JSON.stringify({ version: version, date: new Date(now).toISOString(), choice: stored });
  }

  /** Only http(s) or site-relative links become the policy href. */
  function safeUrl(url) {
    if (typeof url !== 'string' || url === '') return null;
    // `//host/...` is protocol-relative, i.e. another site: refused.
    return /^(https?:\/\/|\/(?!\/)|\.\.?\/)/i.test(url) ? url : null;
  }

  // --- DOM ----------------------------------------------------------------

  function el(doc, tag, attrs, text) {
    var node = doc.createElement(tag);
    for (var name in attrs) if (Object.prototype.hasOwnProperty.call(attrs, name)) node.setAttribute(name, attrs[name]);
    if (text !== undefined) node.textContent = text;
    return node;
  }

  function start(win) {
    var doc = win.document;
    var config = win.dgCookieBanner || {};
    var version = typeof config.version === 'number' ? config.version : 1;
    var maxAgeDays = typeof config.maxAgeDays === 'number' ? config.maxAgeDays : 180;
    var storageKey = typeof config.storageKey === 'string' ? config.storageKey : 'dg-cookie-consent';
    var lang = resolveLang(config.lang, doc.documentElement.getAttribute('lang'));
    var t = stringsFor(lang, config.strings);
    var policyUrl = safeUrl(config.policyUrl);

    win.dataLayer = win.dataLayer || [];
    var gtag = typeof win.gtag === 'function' ? win.gtag : function () { win.dataLayer.push(arguments); };

    var current = null;
    var banner = null;
    var dialog = null;
    var lastFocus = null;

    function storage() {
      try {
        return win.localStorage;
      } catch (e) {
        return null;
      }
    }

    function load() {
      var s = storage();
      return readRecord(s ? s.getItem(storageKey) : null, version, maxAgeDays, Date.now());
    }

    function persist(choice) {
      var s = storage();
      if (s) {
        try {
          s.setItem(storageKey, makeRecord(choice, version, Date.now()));
        } catch (e) {
          /* private mode: the choice lasts for this page only */
        }
      }
    }

    function clearCookies(category) {
      var prefixes = COOKIE_PREFIXES[category] || [];
      var host = win.location.hostname;
      var domains = ['', host, '.' + host.split('.').slice(-2).join('.')];
      doc.cookie.split(';').forEach(function (pair) {
        var name = pair.split('=')[0].trim();
        if (!prefixes.some(function (p) { return name.indexOf(p) === 0; })) return;
        domains.forEach(function (d) {
          doc.cookie = name + '=; Max-Age=0; path=/' + (d ? '; domain=' + d : '');
        });
      });
    }

    function activate(choice) {
      var blocked = doc.querySelectorAll('script[type="text/plain"][data-consent-category]');
      Array.prototype.forEach.call(blocked, function (old) {
        if (!choice[old.getAttribute('data-consent-category')]) return;
        var live = doc.createElement('script');
        Array.prototype.forEach.call(old.attributes, function (a) {
          if (a.name === 'type' || a.name === 'data-src' || a.name === 'data-consent-category') return;
          live.setAttribute(a.name, a.value);
        });
        var src = old.getAttribute('data-src');
        if (src) live.src = src;
        else live.text = old.text;
        old.parentNode.replaceChild(live, old);
      });
      var frames = doc.querySelectorAll('iframe[data-consent-category][data-src]');
      Array.prototype.forEach.call(frames, function (frame) {
        if (!choice[frame.getAttribute('data-consent-category')]) return;
        frame.setAttribute('src', frame.getAttribute('data-src'));
        frame.removeAttribute('data-src');
        var holder = frame.previousElementSibling;
        if (holder && holder.hasAttribute('data-consent-placeholder')) holder.parentNode.removeChild(holder);
      });
    }

    function placeholders() {
      var frames = doc.querySelectorAll('iframe[data-consent-category][data-src]');
      Array.prototype.forEach.call(frames, function (frame) {
        var prev = frame.previousElementSibling;
        if (prev && prev.hasAttribute('data-consent-placeholder')) return;
        var category = frame.getAttribute('data-consent-category');
        var box = el(doc, 'div', { class: 'dgcb-placeholder', 'data-consent-placeholder': '' });
        box.appendChild(el(doc, 'p', {}, t.placeholder));
        var allow = el(doc, 'button', { type: 'button', class: 'dgcb-btn' }, t.placeholderButton);
        allow.addEventListener('click', function () {
          var choice = { analytics: !!(current && current.analytics), marketing: !!(current && current.marketing) };
          choice[category] = true;
          apply(choice, true);
        });
        box.appendChild(allow);
        frame.parentNode.insertBefore(box, frame);
      });
    }

    function apply(choice, fromUser) {
      var previous = current;
      current = choice;
      gtag('consent', 'update', consentModeState(choice));
      if (fromUser) persist(choice);
      activate(choice);
      hideBanner();
      closeDialog();
      doc.dispatchEvent(new CustomEvent('dg:consent', { detail: { analytics: !!choice.analytics, marketing: !!choice.marketing } }));
      // A script that already ran cannot be unloaded: drop its cookies and
      // reload, so nothing withdrawn keeps running on this page.
      if (previous) {
        var withdrawn = CATEGORIES.filter(function (c) { return previous[c] && !choice[c]; });
        if (withdrawn.length > 0) {
          withdrawn.forEach(clearCookies);
          win.location.reload();
        }
      }
    }

    function all(value) {
      var choice = {};
      CATEGORIES.forEach(function (c) { choice[c] = value; });
      return choice;
    }

    function buildBanner() {
      banner = el(doc, 'section', {
        class: 'dgcb',
        role: 'region',
        'aria-labelledby': 'dgcb-title',
        'aria-describedby': 'dgcb-desc',
        lang: lang
      });
      var title = el(doc, 'h2', { id: 'dgcb-title', class: 'dgcb-title', tabindex: '-1' }, t.title);
      var desc = el(doc, 'p', { id: 'dgcb-desc', class: 'dgcb-text' }, t.description + ' ');
      if (policyUrl) desc.appendChild(el(doc, 'a', { href: policyUrl, class: 'dgcb-link' }, t.policy));
      var actions = el(doc, 'div', { class: 'dgcb-actions' });
      var accept = el(doc, 'button', { type: 'button', class: 'dgcb-btn dgcb-btn-choice' }, t.acceptAll);
      var reject = el(doc, 'button', { type: 'button', class: 'dgcb-btn dgcb-btn-choice' }, t.rejectAll);
      var custom = el(doc, 'button', { type: 'button', class: 'dgcb-btn dgcb-btn-secondary' }, t.customize);
      accept.addEventListener('click', function () { apply(all(true), true); });
      reject.addEventListener('click', function () { apply(all(false), true); });
      custom.addEventListener('click', function () { openDialog(custom); });
      actions.appendChild(reject);
      actions.appendChild(accept);
      actions.appendChild(custom);
      banner.appendChild(title);
      banner.appendChild(desc);
      banner.appendChild(actions);
      doc.body.insertBefore(banner, doc.body.firstChild);
      title.focus();
    }

    function hideBanner() {
      if (banner && banner.parentNode) banner.parentNode.removeChild(banner);
      banner = null;
    }

    function categoryRow(id, label, description, checked, disabled) {
      var row = el(doc, 'div', { class: 'dgcb-category' });
      var input = el(doc, 'input', { type: 'checkbox', id: 'dgcb-' + id, 'aria-describedby': 'dgcb-' + id + '-desc' });
      input.checked = checked;
      input.disabled = disabled;
      var labelEl = el(doc, 'label', { for: 'dgcb-' + id }, label);
      row.appendChild(input);
      row.appendChild(labelEl);
      row.appendChild(el(doc, 'p', { id: 'dgcb-' + id + '-desc', class: 'dgcb-text' }, description));
      return { row: row, input: input };
    }

    function openDialog(opener) {
      closeDialog();
      lastFocus = opener || doc.activeElement;
      dialog = el(doc, 'div', {
        class: 'dgcb-dialog',
        role: 'dialog',
        'aria-modal': 'true',
        'aria-labelledby': 'dgcb-prefs-title',
        lang: lang
      });
      var panel = el(doc, 'div', { class: 'dgcb-panel' });
      panel.appendChild(el(doc, 'h2', { id: 'dgcb-prefs-title', class: 'dgcb-title' }, t.preferencesTitle));
      var necessary = categoryRow('necessary', t.necessaryLabel, t.necessaryDescription, true, true);
      var analytics = categoryRow('analytics', t.analyticsLabel, t.analyticsDescription, !!(current && current.analytics), false);
      var marketing = categoryRow('marketing', t.marketingLabel, t.marketingDescription, !!(current && current.marketing), false);
      panel.appendChild(necessary.row);
      panel.appendChild(analytics.row);
      panel.appendChild(marketing.row);
      var actions = el(doc, 'div', { class: 'dgcb-actions' });
      var reject = el(doc, 'button', { type: 'button', class: 'dgcb-btn dgcb-btn-choice' }, t.rejectAll);
      var save = el(doc, 'button', { type: 'button', class: 'dgcb-btn dgcb-btn-choice' }, t.save);
      var close = el(doc, 'button', { type: 'button', class: 'dgcb-btn dgcb-btn-secondary' }, t.close);
      reject.addEventListener('click', function () { apply(all(false), true); });
      save.addEventListener('click', function () {
        apply({ analytics: analytics.input.checked, marketing: marketing.input.checked }, true);
      });
      // Closing records nothing: the first layer stays until a real choice.
      close.addEventListener('click', closeDialog);
      actions.appendChild(reject);
      actions.appendChild(save);
      actions.appendChild(close);
      panel.appendChild(actions);
      dialog.appendChild(panel);
      dialog.addEventListener('keydown', trapKeys);
      doc.body.appendChild(dialog);
      analytics.input.focus();
    }

    function closeDialog() {
      if (!dialog) return;
      if (dialog.parentNode) dialog.parentNode.removeChild(dialog);
      dialog = null;
      if (lastFocus && typeof lastFocus.focus === 'function' && doc.body.contains(lastFocus)) lastFocus.focus();
      lastFocus = null;
    }

    function trapKeys(event) {
      if (event.key === 'Escape') {
        event.preventDefault();
        closeDialog();
        return;
      }
      if (event.key !== 'Tab' || !dialog) return;
      var focusable = dialog.querySelectorAll('button, input:not([disabled]), a[href]');
      if (focusable.length === 0) return;
      var first = focusable[0];
      var last = focusable[focusable.length - 1];
      if (event.shiftKey && doc.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && doc.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    }

    function init() {
      var stored = load();
      placeholders();
      if (stored) apply(stored, false);
      else buildBanner();
      doc.addEventListener('click', function (event) {
        var target = event.target && event.target.closest ? event.target.closest('[data-cookie-preferences]') : null;
        if (!target) return;
        event.preventDefault();
        openDialog(target);
      });
    }

    if (doc.readyState === 'loading') doc.addEventListener('DOMContentLoaded', init);
    else init();
  }

  return {
    CATEGORIES: CATEGORIES,
    STRINGS: STRINGS,
    resolveLang: resolveLang,
    stringsFor: stringsFor,
    consentModeState: consentModeState,
    readRecord: readRecord,
    makeRecord: makeRecord,
    safeUrl: safeUrl,
    start: start
  };
});
