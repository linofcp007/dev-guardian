/**
 * `verifySecrets` — one read-only request per distinct secret, to that
 * secret's own provider, and a verdict that is `live` or `revoked` only on a
 * response that proves it.
 *
 * Every request here goes to a mocked `fetch`; nothing touches the network.
 */

import { describe, expect, it } from 'vitest';

import { verifySecrets, type SecretCandidate } from '../../../../src/secrets/verify/verify.js';

type Handler = (url: string, init: RequestInit) => Promise<Response> | Response;

interface Recorded {
  url: string;
  method: string;
  headers: Record<string, string>;
  redirect: string | undefined;
}

function mockFetch(handler: Handler): { fetch: typeof fetch; calls: Recorded[] } {
  const calls: Recorded[] = [];
  const impl = async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
    const headers: Record<string, string> = {};
    new Headers(init?.headers).forEach((v, k) => {
      headers[k] = v;
    });
    calls.push({ url, method: init?.method ?? 'GET', headers, redirect: init?.redirect });
    return handler(url, init ?? {});
  };
  return { fetch: impl as typeof fetch, calls };
}

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
}

/** Token-shaped values, built at runtime so this file holds no key-shaped literal. */
const tok = {
  github: ['ghp', 'A'.repeat(36)].join('_'),
  gitlab: ['glpat', 'B'.repeat(20)].join('-'),
  slack: ['xoxb', '1234567890', '1234567890123', 'C'.repeat(24)].join('-'),
  stripe: ['sk', 'live', 'D'.repeat(24)].join('_'),
  openai: ['sk', 'proj', 'E'.repeat(40)].join('-'),
  anthropic: ['sk', 'ant', 'api03', 'F'.repeat(40)].join('-'),
  npm: ['npm', 'g'.repeat(36)].join('_'),
  sendgrid: ['SG', 'H'.repeat(22), 'I'.repeat(43)].join('.'),
};

async function one(rule: string, secret: string, handler: Handler) {
  const m = mockFetch(handler);
  const [check] = await verifySecrets([{ rule, secret }], { fetchImpl: m.fetch, offline: false });
  if (check === undefined) throw new Error('no result');
  return { check, calls: m.calls };
}

describe('verifySecrets — verdicts per provider', () => {
  it('GitHub: 200 from api.github.com/user is live; the token goes as a Bearer header, redirects are not followed', async () => {
    const { check, calls } = await one('github-pat', tok.github, () => json(200, { login: 'someone' }));
    expect(check.verdict).toBe('live');
    expect(check.sent).toBe(true);
    expect(calls).toHaveLength(1);
    expect(calls[0]?.url).toBe('https://api.github.com/user');
    expect(calls[0]?.headers['authorization']).toBe(`Bearer ${tok.github}`);
    expect(calls[0]?.redirect).toBe('manual');
  });

  it('GitHub: 401 is UNKNOWN, never revoked — the token may belong to a GitHub Enterprise Server', async () => {
    const { check } = await one('github-pat', tok.github, () => json(401, { message: 'Bad credentials' }));
    expect(check.verdict).toBe('unknown');
    expect(check.reason).toMatch(/not valid on github\.com — may belong to a self-hosted instance/);
  });

  it('GitHub: 403 (rate limit, SSO, login lockout) is unknown', async () => {
    const { check } = await one('github-fine-grained-pat', tok.github, () => json(403, {}));
    expect(check.verdict).toBe('unknown');
  });

  it('GitLab: 200 from gitlab.com personal_access_tokens/self is live, 401 is unknown (self-managed)', async () => {
    const live = await one('gitlab-pat', tok.gitlab, () => json(200, { active: true }));
    expect(live.check.verdict).toBe('live');
    expect(live.calls[0]?.url).toBe('https://gitlab.com/api/v4/personal_access_tokens/self');
    expect(live.calls[0]?.headers['private-token']).toBe(tok.gitlab);
    const gone = await one('gitlab-pat', tok.gitlab, () => json(401, { message: '401 Unauthorized' }));
    expect(gone.check.verdict).toBe('unknown');
    expect(gone.check.reason).toMatch(/not valid on gitlab\.com — may belong to a self-hosted instance/);
  });

  it('Slack: ok:true is live; invalid_auth / token_revoked / account_inactive / token_expired are revoked; other errors unknown', async () => {
    const live = await one('slack-bot-token', tok.slack, () => json(200, { ok: true, team: 't' }));
    expect(live.check.verdict).toBe('live');
    expect(live.calls[0]?.url).toBe('https://slack.com/api/auth.test');
    expect(live.calls[0]?.method).toBe('POST');
    for (const error of ['invalid_auth', 'token_revoked', 'account_inactive', 'token_expired']) {
      const { check } = await one('slack-bot-token', tok.slack, () => json(200, { ok: false, error }));
      expect(check.verdict, error).toBe('revoked');
    }
    const other = await one('slack-bot-token', tok.slack, () => json(200, { ok: false, error: 'ekm_access_denied' }));
    expect(other.check.verdict).toBe('unknown');
    const limited = await one('slack-bot-token', tok.slack, () => json(429, { ok: false, error: 'ratelimited' }));
    expect(limited.check.verdict).toBe('unknown');
  });

  it('Stripe: 200 and 403 (documented: key lacks permission) are live; 401 is revoked only with the invalid-key signal', async () => {
    expect((await one('stripe-access-token', tok.stripe, () => json(200, { id: 'acct' }))).check.verdict).toBe('live');
    expect((await one('stripe-access-token', tok.stripe, () => json(403, { error: {} }))).check.verdict).toBe('live');
    const invalid = await one('stripe-access-token', tok.stripe, () =>
      json(401, { error: { type: 'invalid_request_error', message: 'Invalid API Key provided: sk_live_****DDDD' } }),
    );
    expect(invalid.check.verdict).toBe('revoked');
    const expired = await one('stripe-access-token', tok.stripe, () => json(401, { error: { code: 'api_key_expired' } }));
    expect(expired.check.verdict).toBe('revoked');
    // A key restricted to other IP addresses is also a 401 — no invalid-key signal, so unknown.
    const other = await one('stripe-access-token', tok.stripe, () => json(401, { error: { message: 'something else' } }));
    expect(other.check.verdict).toBe('unknown');
    expect(invalid.calls[0]?.url).toBe('https://api.stripe.com/v1/account');
  });

  it('OpenAI: 401 is revoked only with code invalid_api_key; IP allowlist / org / scope 401s and 403 are unknown', async () => {
    expect((await one('openai-api-key', tok.openai, () => json(200, { data: [] }))).check.verdict).toBe('live');
    const invalid = await one('openai-api-key', tok.openai, () =>
      json(401, { error: { code: 'invalid_api_key', message: 'Incorrect API key provided' } }),
    );
    expect(invalid.check.verdict).toBe('revoked');
    const ip = await one('openai-api-key', tok.openai, () => json(401, { error: { code: 'ip_not_authorized' } }));
    expect(ip.check.verdict).toBe('unknown');
    const region = await one('openai-api-key', tok.openai, () => json(403, { error: { code: 'unsupported_country_region_territory' } }));
    expect(region.check.verdict).toBe('unknown');
    expect(invalid.calls[0]?.url).toBe('https://api.openai.com/v1/models');
  });

  it('Anthropic: x-api-key + anthropic-version; 401 authentication_error revoked, 403 permission_error live', async () => {
    const live = await one('anthropic-api-key', tok.anthropic, () => json(200, { data: [] }));
    expect(live.check.verdict).toBe('live');
    expect(live.calls[0]?.url).toBe('https://api.anthropic.com/v1/models');
    expect(live.calls[0]?.headers['x-api-key']).toBe(tok.anthropic);
    expect(live.calls[0]?.headers['anthropic-version']).toBe('2023-06-01');
    const bad = await one('anthropic-api-key', tok.anthropic, () =>
      json(401, { type: 'error', error: { type: 'authentication_error', message: 'invalid x-api-key' } }),
    );
    expect(bad.check.verdict).toBe('revoked');
    const perm = await one('anthropic-api-key', tok.anthropic, () =>
      json(403, { type: 'error', error: { type: 'permission_error', message: 'no' } }),
    );
    expect(perm.check.verdict).toBe('live');
    const overloaded = await one('anthropic-api-key', tok.anthropic, () => json(529, { type: 'error' }));
    expect(overloaded.check.verdict).toBe('unknown');
  });

  it('npm: 200 from registry.npmjs.org/-/whoami is live, 401 is revoked', async () => {
    const live = await one('npm-access-token', tok.npm, () => json(200, { username: 'u' }));
    expect(live.check.verdict).toBe('live');
    expect(live.calls[0]?.url).toBe('https://registry.npmjs.org/-/whoami');
    expect((await one('npm-access-token', tok.npm, () => json(401, {}))).check.verdict).toBe('revoked');
    expect((await one('npm-access-token', tok.npm, () => json(403, {}))).check.verdict).toBe('unknown');
  });

  it('SendGrid: 200/403 live; 401 revoked only with the documented invalid-credential message', async () => {
    expect((await one('sendgrid-api-token', tok.sendgrid, () => json(200, { scopes: [] }))).check.verdict).toBe('live');
    expect((await one('sendgrid-api-token', tok.sendgrid, () => json(403, { errors: [] }))).check.verdict).toBe('live');
    const bad = await one('sendgrid-api-token', tok.sendgrid, () =>
      json(401, { errors: [{ field: null, message: 'authorization required' }] }),
    );
    expect(bad.check.verdict).toBe('revoked');
    expect(bad.calls[0]?.url).toBe('https://api.sendgrid.com/v3/scopes');
    // An EU-regional key rejected by the global host says something else: unknown.
    const eu = await one('sendgrid-api-token', tok.sendgrid, () =>
      json(401, { errors: [{ message: 'User is not authorized based on their regional attribute' }] }),
    );
    expect(eu.check.verdict).toBe('unknown');
  });

  it('a redirect is unknown and is not followed', async () => {
    const { check, calls } = await one('npm-access-token', tok.npm, () =>
      new Response(null, { status: 302, headers: { location: 'https://elsewhere.example/' } }),
    );
    expect(check.verdict).toBe('unknown');
    expect(calls).toHaveLength(1);
  });
});

describe('verifySecrets — failures are unknown, with a reason', () => {
  it('429 and 5xx are unknown', async () => {
    for (const status of [429, 500, 502, 503]) {
      const { check } = await one('github-pat', tok.github, () => json(status, {}));
      expect(check.verdict, String(status)).toBe('unknown');
      expect(check.reason).toMatch(new RegExp(String(status)));
    }
  });

  it('a DNS / offline failure is unknown and names the error code, not the error text', async () => {
    const { check } = await one('github-pat', tok.github, () => {
      throw Object.assign(new TypeError(`fetch failed ${tok.github}`), {
        cause: Object.assign(new Error(`getaddrinfo ENOTFOUND api.github.com ${tok.github}`), { code: 'ENOTFOUND' }),
      });
    });
    expect(check.verdict).toBe('unknown');
    expect(check.reason).toMatch(/ENOTFOUND/);
    expect(check.reason).not.toContain(tok.github);
  });

  it('no answer within the timeout is unknown (5 s by default; shortened here)', async () => {
    const m = mockFetch(
      (_url, init) =>
        new Promise<Response>((_resolve, reject) => {
          init.signal?.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError')));
        }),
    );
    const started = Date.now();
    const [check] = await verifySecrets([{ rule: 'github-pat', secret: tok.github }], {
      fetchImpl: m.fetch,
      offline: false,
      timeoutMs: 50,
    });
    expect(Date.now() - started).toBeLessThan(5_000);
    expect(check?.verdict).toBe('unknown');
    expect(check?.reason).toMatch(/no answer/);
  });

  it('defaults to a 5 s timeout per request', async () => {
    const { DEFAULT_TIMEOUT_MS } = await import('../../../../src/secrets/verify/verify.js');
    expect(DEFAULT_TIMEOUT_MS).toBe(5_000);
  });

  it('a provider body echoing the token is never copied into the reason', async () => {
    const { check } = await one('openai-api-key', tok.openai, () =>
      json(401, { error: { code: tok.openai, message: `Incorrect API key provided: ${tok.openai}` } }),
    );
    expect(check.verdict).toBe('unknown');
    expect(JSON.stringify(check)).not.toContain(tok.openai);
  });

  it('GUARDIAN_OFFLINE: nothing is sent, every candidate is unknown', async () => {
    const m = mockFetch(() => json(200, {}));
    const checks = await verifySecrets([{ rule: 'github-pat', secret: tok.github }], { fetchImpl: m.fetch, offline: true });
    expect(m.calls).toHaveLength(0);
    expect(checks[0]?.verdict).toBe('unknown');
    expect(checks[0]?.sent).toBe(false);
    expect(checks[0]?.reason).toMatch(/GUARDIAN_OFFLINE/);
  });

  it('reads GUARDIAN_OFFLINE from the environment when offline is not given', async () => {
    const m = mockFetch(() => json(200, {}));
    const checks = await verifySecrets([{ rule: 'github-pat', secret: tok.github }], {
      fetchImpl: m.fetch,
      env: { GUARDIAN_OFFLINE: '1' },
    });
    expect(m.calls).toHaveLength(0);
    expect(checks[0]?.verdict).toBe('unknown');
  });
});

describe('verifySecrets — bounds', () => {
  it('verifies each distinct secret once, and gives every finding that holds it the same verdict', async () => {
    const m = mockFetch(() => json(200, {}));
    const candidates: SecretCandidate[] = [
      { rule: 'github-pat', secret: tok.github },
      { rule: 'github-pat', secret: tok.github },
      { rule: 'npm-access-token', secret: tok.npm },
      { rule: 'github-pat', secret: tok.github },
    ];
    const checks = await verifySecrets(candidates, { fetchImpl: m.fetch, offline: false });
    expect(m.calls).toHaveLength(2);
    expect(checks.map((c) => c.verdict)).toEqual(['live', 'live', 'live', 'live']);
  });

  it('keeps at most 4 requests in flight', async () => {
    let inFlight = 0;
    let peak = 0;
    const m = mockFetch(async () => {
      inFlight += 1;
      peak = Math.max(peak, inFlight);
      await new Promise((r) => setTimeout(r, 5));
      inFlight -= 1;
      return json(200, {});
    });
    const candidates = Array.from({ length: 20 }, (_, i) => ({ rule: 'npm-access-token', secret: `${tok.npm}${i}` }));
    const checks = await verifySecrets(candidates, { fetchImpl: m.fetch, offline: false, concurrency: 99 });
    expect(m.calls).toHaveLength(20);
    expect(peak).toBeLessThanOrEqual(4);
    expect(peak).toBeGreaterThan(1);
    expect(checks.every((c) => c.verdict === 'live')).toBe(true);
  });

  it('stops at 50 distinct secrets per scan; the rest are unknown "not verified: per-scan limit" and never sent', async () => {
    const m = mockFetch(() => json(200, {}));
    const candidates = Array.from({ length: 60 }, (_, i) => ({ rule: 'npm-access-token', secret: `${tok.npm}${i}` }));
    const checks = await verifySecrets(candidates, { fetchImpl: m.fetch, offline: false });
    expect(m.calls).toHaveLength(50);
    expect(checks.slice(0, 50).every((c) => c.verdict === 'live' && c.sent)).toBe(true);
    const rest = checks.slice(50);
    expect(rest).toHaveLength(10);
    for (const c of rest) {
      expect(c.verdict).toBe('unknown');
      expect(c.sent).toBe(false);
      expect(c.reason).toMatch(/not verified: per-scan limit/);
    }
    const sentSecrets = m.calls.map((c) => c.headers['authorization']);
    expect(sentSecrets).not.toContain(`Bearer ${tok.npm}55`);
  });

  it('a token shape the endpoint cannot judge is skipped, never sent', async () => {
    const m = mockFetch(() => json(200, { ok: false, error: 'invalid_auth' }));
    const refresh = ['xoxe', '1', '2345678901', 'abcdef'].join('-');
    const [check] = await verifySecrets([{ rule: 'slack-user-token', secret: refresh }], { fetchImpl: m.fetch, offline: false });
    expect(m.calls).toHaveLength(0);
    expect(check?.verdict).toBe('skipped');
  });

  it('an unsupported rule is skipped, never sent', async () => {
    const m = mockFetch(() => json(200, {}));
    const [check] = await verifySecrets([{ rule: 'aws-access-token', secret: 'x' }], { fetchImpl: m.fetch, offline: false });
    expect(m.calls).toHaveLength(0);
    expect(check?.verdict).toBe('skipped');
  });

  it('a cancelled scan sends nothing further', async () => {
    const controller = new AbortController();
    controller.abort();
    const m = mockFetch(() => json(200, {}));
    const [check] = await verifySecrets([{ rule: 'github-pat', secret: tok.github }], {
      fetchImpl: m.fetch,
      offline: false,
      signal: controller.signal,
    });
    expect(m.calls).toHaveLength(0);
    expect(check?.verdict).toBe('unknown');
  });
});
