/**
 * The providers `scan_secrets verify_live` can ask "is this credential
 * live?", one per gitleaks rule — and the ONLY places a secret is ever sent.
 *
 * ---- One fixed endpoint per rule ----------------------------------------
 *
 * Each provider's `endpoint` is a compile-time constant: the provider's own
 * read-only identity endpoint, on its own public host. Nothing about a
 * request — host, path, header — is derived from the repository or from the
 * finding. A GitLab token sitting next to `https://git.example.internal` is
 * checked against gitlab.com and nowhere else: sending it to the host written
 * beside it would hand the secret to whoever controls that host. The secret
 * travels in a request header only, never in the URL (URLs end up in proxy
 * and server access logs).
 *
 * ---- What a verdict needs ------------------------------------------------
 *
 *   - `live` only on a response that proves the credential authenticates: a
 *     success, or a 403 the provider documents as "valid, but not allowed to
 *     do this" (Stripe, Anthropic's `permission_error`).
 *   - `revoked` only for a SaaS-only provider, on its DOCUMENTED
 *     invalid-credential response — and where the provider documents OTHER
 *     causes for the same status (OpenAI and Stripe answer 401 for an IP
 *     allowlist too), only with the body field that names the invalid
 *     credential. That field is compared against constants here and never
 *     copied anywhere: some of these bodies echo the token back. npm and
 *     SendGrid document no response that tells an invalid key apart (a
 *     granular npm token restricted to other IP ranges; SendGrid's 401 is
 *     just "requires authentication"), so neither is ever `revoked`.
 *   - GitHub, GitLab and Slack's `invalid_auth` are never `revoked`: GitHub
 *     Enterprise Server, self-managed GitLab and GovSlack (slack-gov.com)
 *     issue tokens with the same prefixes, so "invalid" from github.com /
 *     gitlab.com / slack.com only says the token is not valid THERE. Slack's
 *     `token_revoked`, `token_expired` and `account_inactive` are specific
 *     enough to stay `revoked`.
 *   - Everything else — 429, 5xx, a redirect, an undocumented status — is
 *     `unknown` with a reason.
 *
 * The response semantics, and the documentation each one comes from, are
 * tabled in the task report (`.superpowers/sdd/2026-09-25-full-review/
 * task-17-report.md`).
 */
/** Sent with every request, so a provider's logs say what asked. */
const USER_AGENT = 'dev-guardian-secret-verify';
function hostOf(endpoint) {
    return new URL(endpoint).host;
}
function isRecord(v) {
    return typeof v === 'object' && v !== null && !Array.isArray(v);
}
/** `body[key]` when the body is an object, else undefined. */
function field(body, key) {
    return isRecord(body) ? body[key] : undefined;
}
function live(host, status, note = '') {
    return { verdict: 'live', reason: `${host} accepted it (HTTP ${status}${note})` };
}
/** The reading of every status a provider-specific rule did not claim. */
function otherStatus(host, status) {
    if (status === 429)
        return { verdict: 'unknown', reason: `${host} rate-limited the check (HTTP 429) — try again later` };
    if (status >= 500) {
        return { verdict: 'unknown', reason: `${host} answered HTTP ${status} — a provider-side error says nothing about the credential` };
    }
    if (status >= 300 && status < 400) {
        return { verdict: 'unknown', reason: `${host} answered with a redirect (HTTP ${status}), which is not followed` };
    }
    return { verdict: 'unknown', reason: `${host} answered HTTP ${status}, which does not establish whether the credential is valid` };
}
function bearer(secret) {
    return { authorization: `Bearer ${secret}`, accept: 'application/json', 'user-agent': USER_AGENT };
}
// ---- GitHub ---------------------------------------------------------------
const GITHUB_ENDPOINT = 'https://api.github.com/user';
const GITHUB_HOST = hostOf(GITHUB_ENDPOINT);
const github = {
    name: 'GitHub',
    rules: ['github-pat', 'github-fine-grained-pat'],
    endpoint: GITHUB_ENDPOINT,
    method: 'GET',
    headers: (secret) => ({
        ...bearer(secret),
        accept: 'application/vnd.github+json',
        'x-github-api-version': '2022-11-28',
    }),
    classify({ status }) {
        if (status === 200)
            return live(GITHUB_HOST, status);
        if (status === 401) {
            return {
                verdict: 'unknown',
                reason: 'not valid on github.com — may belong to a self-hosted instance (GitHub Enterprise Server issues ' +
                    'tokens with the same prefixes)',
            };
        }
        if (status === 403) {
            return {
                verdict: 'unknown',
                reason: `${GITHUB_HOST} refused the check (HTTP 403: a rate limit, SSO enforcement or a failed-login lockout)`,
            };
        }
        return otherStatus(GITHUB_HOST, status);
    },
    rotate: 'revoke it at https://github.com/settings/tokens (classic) or ' +
        'https://github.com/settings/personal-access-tokens (fine-grained) and issue a new one',
};
// ---- GitLab ---------------------------------------------------------------
const GITLAB_ENDPOINT = 'https://gitlab.com/api/v4/personal_access_tokens/self';
const GITLAB_HOST = hostOf(GITLAB_ENDPOINT);
const gitlab = {
    name: 'GitLab',
    rules: ['gitlab-pat'],
    endpoint: GITLAB_ENDPOINT,
    method: 'GET',
    headers: (secret) => ({ 'private-token': secret, accept: 'application/json', 'user-agent': USER_AGENT }),
    classify({ status }) {
        if (status === 200)
            return live(GITLAB_HOST, status);
        if (status === 401) {
            return {
                verdict: 'unknown',
                reason: 'not valid on gitlab.com — may belong to a self-hosted instance (self-managed GitLab issues ' +
                    'tokens with the same glpat- prefix)',
            };
        }
        return otherStatus(GITLAB_HOST, status);
    },
    rotate: 'revoke it at https://gitlab.com/-/user_settings/personal_access_tokens (or on the instance that issued it)',
};
// ---- Slack ----------------------------------------------------------------
const SLACK_ENDPOINT = 'https://slack.com/api/auth.test';
const SLACK_HOST = hostOf(SLACK_ENDPOINT);
/**
 * auth.test's documented errors that say THIS token is dead. `invalid_auth`
 * is not one: a GovSlack token (slack-gov.com, same prefixes) reads the same.
 */
const SLACK_DEAD = ['token_revoked', 'account_inactive', 'token_expired'];
const slack = {
    name: 'Slack',
    rules: ['slack-bot-token', 'slack-user-token'],
    endpoint: SLACK_ENDPOINT,
    method: 'POST',
    headers: (secret) => ({ ...bearer(secret), 'content-type': 'application/x-www-form-urlencoded' }),
    // Bot and user ACCESS tokens only: `xoxe-` (refresh) matches the user rule.
    accepts: (secret) => /^xox[bp]-/.test(secret),
    classify({ status, body }) {
        if (status !== 200)
            return otherStatus(SLACK_HOST, status);
        if (field(body, 'ok') === true)
            return live(SLACK_HOST, status, ', ok: true');
        const error = field(body, 'error');
        const dead = SLACK_DEAD.find((e) => e === error);
        if (dead !== undefined) {
            return { verdict: 'revoked', reason: `${SLACK_HOST} rejected it (${dead}): it no longer authenticates` };
        }
        if (error === 'invalid_auth') {
            return { verdict: 'unknown', reason: 'not valid on slack.com (a GovSlack token reads the same)' };
        }
        return { verdict: 'unknown', reason: `${SLACK_HOST} answered ok: false with an error that does not establish validity` };
    },
    rotate: 'revoke it from the app at https://api.slack.com/apps (OAuth & Permissions), then reinstall to issue a new one',
};
// ---- Stripe ---------------------------------------------------------------
const STRIPE_ENDPOINT = 'https://api.stripe.com/v1/account';
const STRIPE_HOST = hostOf(STRIPE_ENDPOINT);
const stripe = {
    name: 'Stripe',
    rules: ['stripe-access-token'],
    endpoint: STRIPE_ENDPOINT,
    method: 'GET',
    headers: bearer,
    classify({ status, body }) {
        if (status === 200)
            return live(STRIPE_HOST, status);
        // Documented: "The API key doesn't have permissions to perform the request."
        if (status === 403)
            return live(STRIPE_HOST, status, ': a valid key without permission to read the account');
        if (status === 401) {
            const error = field(body, 'error');
            const code = field(error, 'code');
            const message = field(error, 'message');
            if (code === 'api_key_expired')
                return { verdict: 'revoked', reason: `${STRIPE_HOST} reports the key expired (api_key_expired)` };
            if (typeof message === 'string' && message.toLowerCase().startsWith('invalid api key provided')) {
                return { verdict: 'revoked', reason: `${STRIPE_HOST} rejected it as an invalid API key (HTTP 401)` };
            }
            return {
                verdict: 'unknown',
                reason: `${STRIPE_HOST} answered HTTP 401 without its invalid-key signal — the key may be restricted to other IP addresses`,
            };
        }
        return otherStatus(STRIPE_HOST, status);
    },
    rotate: 'roll it at https://dashboard.stripe.com/apikeys',
};
// ---- OpenAI ---------------------------------------------------------------
const OPENAI_ENDPOINT = 'https://api.openai.com/v1/models';
const OPENAI_HOST = hostOf(OPENAI_ENDPOINT);
const openai = {
    name: 'OpenAI',
    rules: ['openai-api-key'],
    endpoint: OPENAI_ENDPOINT,
    method: 'GET',
    headers: bearer,
    // An admin key does not call the model API; its answer there proves nothing.
    accepts: (secret) => !secret.startsWith('sk-admin-'),
    classify({ status, body }) {
        if (status === 200)
            return live(OPENAI_HOST, status);
        if (status === 401) {
            if (field(field(body, 'error'), 'code') === 'invalid_api_key') {
                return { verdict: 'revoked', reason: `${OPENAI_HOST} rejected it as an incorrect API key (invalid_api_key)` };
            }
            return {
                verdict: 'unknown',
                reason: `${OPENAI_HOST} answered HTTP 401 without code invalid_api_key — it also does so for an IP ` +
                    'allowlist, a missing organization or a restricted key',
            };
        }
        if (status === 403) {
            return { verdict: 'unknown', reason: `${OPENAI_HOST} refused the check (HTTP 403: region not supported)` };
        }
        return otherStatus(OPENAI_HOST, status);
    },
    rotate: 'revoke it at https://platform.openai.com/api-keys',
};
// ---- Anthropic ------------------------------------------------------------
const ANTHROPIC_ENDPOINT = 'https://api.anthropic.com/v1/models';
const ANTHROPIC_HOST = hostOf(ANTHROPIC_ENDPOINT);
const anthropic = {
    name: 'Anthropic',
    rules: ['anthropic-api-key'],
    endpoint: ANTHROPIC_ENDPOINT,
    method: 'GET',
    headers: (secret) => ({
        'x-api-key': secret,
        'anthropic-version': '2023-06-01',
        accept: 'application/json',
        'user-agent': USER_AGENT,
    }),
    classify({ status, body }) {
        const type = field(field(body, 'error'), 'type');
        if (status === 200)
            return live(ANTHROPIC_HOST, status);
        if (status === 403 && type === 'permission_error') {
            return live(ANTHROPIC_HOST, status, ': a valid key not permitted this resource (permission_error)');
        }
        if (status === 401 && type === 'authentication_error') {
            return { verdict: 'revoked', reason: `${ANTHROPIC_HOST} rejected it (authentication_error): invalid, revoked or deleted` };
        }
        return otherStatus(ANTHROPIC_HOST, status);
    },
    rotate: 'delete it at https://console.anthropic.com/settings/keys and create a new one',
};
// ---- npm ------------------------------------------------------------------
const NPM_ENDPOINT = 'https://registry.npmjs.org/-/whoami';
const NPM_HOST = hostOf(NPM_ENDPOINT);
const npm = {
    name: 'npm',
    rules: ['npm-access-token'],
    endpoint: NPM_ENDPOINT,
    method: 'GET',
    headers: bearer,
    classify({ status }) {
        if (status === 200)
            return live(NPM_HOST, status);
        // npm documents no invalid-credential response: never `revoked`.
        if (status === 401) {
            return {
                verdict: 'unknown',
                reason: `${NPM_HOST} answered HTTP 401: invalid, expired or revoked — or a granular token restricted to ` +
                    'other IP ranges; npm documents no response that tells these apart',
            };
        }
        return otherStatus(NPM_HOST, status);
    },
    rotate: 'revoke it with `npm token revoke <id>` or at https://www.npmjs.com/ (Access Tokens)',
};
// ---- SendGrid -------------------------------------------------------------
const SENDGRID_ENDPOINT = 'https://api.sendgrid.com/v3/scopes';
const SENDGRID_HOST = hostOf(SENDGRID_ENDPOINT);
const sendgrid = {
    name: 'SendGrid',
    rules: ['sendgrid-api-token'],
    endpoint: SENDGRID_ENDPOINT,
    method: 'GET',
    headers: bearer,
    // SendGrid documents 401 only as "requires authentication" and this
    // endpoint's 403 as "Scopes forbidden response": neither says which keys
    // get them, so only a 200 is a verdict.
    classify({ status }) {
        if (status === 200)
            return live(SENDGRID_HOST, status);
        if (status === 401) {
            return {
                verdict: 'unknown',
                reason: `${SENDGRID_HOST} answered HTTP 401 — invalid, expired or revoked, or the key of an EU-regional ` +
                    'subuser (valid only on api.eu.sendgrid.com, not contacted); SendGrid documents nothing that tells these apart',
            };
        }
        if (status === 403) {
            return { verdict: 'unknown', reason: `${SENDGRID_HOST} answered HTTP 403, which SendGrid does not document as a valid key` };
        }
        return otherStatus(SENDGRID_HOST, status);
    },
    rotate: 'delete it at https://app.sendgrid.com/settings/api_keys and create a new one',
};
/** Every provider, in no particular order; each rule belongs to exactly one. */
export const PROVIDERS = [github, gitlab, slack, stripe, openai, anthropic, npm, sendgrid];
const BY_RULE = new Map(PROVIDERS.flatMap((p) => p.rules.map((r) => [r, p])));
/** Every gitleaks rule `verify_live` can check. */
export const SUPPORTED_RULES = [...BY_RULE.keys()];
export function providerForRule(ruleId) {
    return BY_RULE.get(ruleId);
}
export function isVerifiableRule(ruleId) {
    return BY_RULE.has(ruleId);
}
/** The one host a provider's secrets are sent to. */
export function providerHost(p) {
    return hostOf(p.endpoint);
}
//# sourceMappingURL=providers.js.map