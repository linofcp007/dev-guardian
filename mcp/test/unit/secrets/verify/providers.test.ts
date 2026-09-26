/**
 * The provider table behind `scan_secrets verify_live`.
 *
 * Ruling 2 of the task: an endpoint is a compile-time constant per rule — the
 * provider's own read-only identity endpoint — and nothing about a request is
 * ever derived from repository content or from the finding. A GitLab token
 * sitting next to `https://git.example.internal` is checked against
 * gitlab.com and nowhere else: sending it to the host named beside it would
 * hand the secret to whoever controls that host.
 */

import { describe, expect, it } from 'vitest';

import {
  PROVIDERS,
  SUPPORTED_RULES,
  isVerifiableRule,
  providerForRule,
} from '../../../../src/secrets/verify/providers.js';

/** The one host each provider may be sent a secret on. */
const EXPECTED_HOSTS: Record<string, string> = {
  'github-pat': 'api.github.com',
  'github-fine-grained-pat': 'api.github.com',
  'gitlab-pat': 'gitlab.com',
  'slack-bot-token': 'slack.com',
  'slack-user-token': 'slack.com',
  'stripe-access-token': 'api.stripe.com',
  'openai-api-key': 'api.openai.com',
  'anthropic-api-key': 'api.anthropic.com',
  'npm-access-token': 'registry.npmjs.org',
  'sendgrid-api-token': 'api.sendgrid.com',
};

describe('verify_live provider table', () => {
  it('supports exactly the gitleaks rules the task names (ids as gitleaks 8.30 reports them)', () => {
    expect([...SUPPORTED_RULES].sort()).toEqual(Object.keys(EXPECTED_HOSTS).sort());
  });

  it.each(Object.entries(EXPECTED_HOSTS))('%s maps to exactly one fixed https host: %s', (rule, host) => {
    const matching = PROVIDERS.filter((p) => p.rules.includes(rule));
    expect(matching).toHaveLength(1);
    const provider = providerForRule(rule);
    expect(provider).toBe(matching[0]);
    const url = new URL(provider?.endpoint ?? 'invalid:');
    expect(url.protocol).toBe('https:');
    expect(url.host).toBe(host);
    expect(url.username).toBe('');
    expect(url.password).toBe('');
    expect(url.search).toBe('');
  });

  it('every provider endpoint is https, and no two providers share a rule', () => {
    const seen = new Set<string>();
    for (const p of PROVIDERS) {
      expect(new URL(p.endpoint).protocol).toBe('https:');
      for (const rule of p.rules) {
        expect(seen.has(rule)).toBe(false);
        seen.add(rule);
      }
    }
  });

  it('the secret goes into request headers only — never into the URL', () => {
    const secret = ['sentinel', 'value', 'x9'].join('-');
    for (const p of PROVIDERS) {
      expect(p.endpoint).not.toContain(secret);
      const headers = p.headers(secret);
      expect(Object.values(headers).some((v) => v.includes(secret))).toBe(true);
      // No header value names a host: nothing here can redirect the request.
      for (const [name, value] of Object.entries(headers)) {
        expect(name.toLowerCase()).not.toBe('host');
        if (!value.includes(secret)) expect(value).not.toMatch(/https?:\/\//);
      }
    }
  });

  it('unsupported rules have no provider', () => {
    expect(providerForRule('aws-access-token')).toBeUndefined();
    expect(providerForRule('generic-api-key')).toBeUndefined();
    expect(isVerifiableRule('aws-access-token')).toBe(false);
    expect(isVerifiableRule('github-pat')).toBe(true);
  });

  it('declines token shapes its endpoint cannot judge (a Slack refresh token, an OpenAI admin key)', () => {
    const slack = providerForRule('slack-user-token');
    expect(slack?.accepts?.(['xoxe', '1', '2345678901', 'abc'].join('-'))).toBe(false);
    expect(slack?.accepts?.(['xoxp', '1', '2345678901', 'abc'].join('-'))).toBe(true);
    const openai = providerForRule('openai-api-key');
    expect(openai?.accepts?.(['sk', 'admin', 'abc'].join('-'))).toBe(false);
    expect(openai?.accepts?.(['sk', 'proj', 'abc'].join('-'))).toBe(true);
  });

  it('every provider carries rotation guidance naming where to revoke', () => {
    for (const p of PROVIDERS) expect(p.rotate).toMatch(/https:\/\//);
  });
});
