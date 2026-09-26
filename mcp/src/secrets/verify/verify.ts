/**
 * `verifySecrets` — ask each secret's own provider whether it still
 * authenticates, within bounds:
 *
 *   - each DISTINCT secret is sent once (per provider), however many findings
 *     hold it, and every one of those findings gets the same answer;
 *   - at most {@link MAX_IN_FLIGHT} requests are in flight at once;
 *   - at most {@link DEFAULT_MAX_SECRETS} distinct secrets per scan — beyond
 *     that, `unknown` "not verified: per-scan limit", and nothing is sent;
 *   - {@link DEFAULT_TIMEOUT_MS} per request, body included;
 *   - `GUARDIAN_OFFLINE=1` sends nothing at all.
 *
 * **The secret goes into one request's headers and nowhere else.** No reason
 * string is built from anything but constants, status numbers and a
 * `/^[A-Z][A-Z0-9_]+$/` error code: not from an exception's text (an
 * undici error can carry the request), and not from a response body (some
 * providers echo the token back in their error). Nothing here logs.
 */

import { providerForRule, providerHost, type SecretProvider, type SecretVerdict } from './providers.js';

/** Per request, body included. */
export const DEFAULT_TIMEOUT_MS = 5_000;
/** Distinct secrets verified per scan; the rest are `unknown`. */
export const DEFAULT_MAX_SECRETS = 50;
/** The ceiling on concurrent requests, whatever a caller asks for. */
export const MAX_IN_FLIGHT = 4;
/** A response body larger than this is not read (every verdict here needs a few hundred bytes). */
const MAX_BODY_BYTES = 64 * 1024;

export const OFFLINE_REASON = 'network disabled (GUARDIAN_OFFLINE=1) — nothing was sent';

export interface SecretCandidate {
  /** The gitleaks rule id. */
  rule: string;
  secret: string;
}

/** One finding's verification. */
export interface SecretCheck {
  /** `skipped`: no verifier for this rule or token shape — nothing was sent. */
  verdict: SecretVerdict | 'skipped';
  reason: string;
  /** The provider's name, when the rule has one. */
  provider: string | null;
  /** The one host the secret is (or would have been) sent to. */
  host: string | null;
  /** Whether the secret was sent to `host`. */
  sent: boolean;
  /** Where to revoke it, for `live` guidance. */
  rotate: string | null;
}

export interface VerifyOptions {
  /** Defaults to the global `fetch`, read at call time. */
  fetchImpl?: typeof fetch;
  timeoutMs?: number;
  /** Clamped to 1..{@link MAX_IN_FLIGHT}. */
  concurrency?: number;
  maxSecrets?: number;
  /** The scan's signal: once aborted, nothing further is sent. */
  signal?: AbortSignal;
  /** Forces (or forbids) the offline path; default: `GUARDIAN_OFFLINE` from `env`. */
  offline?: boolean;
  env?: Record<string, string | undefined>;
}

export async function verifySecrets(
  candidates: readonly SecretCandidate[],
  opts: VerifyOptions = {},
): Promise<SecretCheck[]> {
  const offline = opts.offline ?? (opts.env ?? process.env)['GUARDIAN_OFFLINE'] === '1';
  const maxSecrets = opts.maxSecrets ?? DEFAULT_MAX_SECRETS;
  const results: Array<SecretCheck | null> = candidates.map(() => null);

  // Distinct (provider, secret) pairs in first-seen order, and which
  // candidates each one answers for.
  const distinct: Array<{ provider: SecretProvider; secret: string; holders: number[] }> = [];
  const byKey = new Map<string, number>();
  candidates.forEach((c, i) => {
    const provider = providerForRule(c.rule);
    if (provider === undefined) {
      results[i] = skipped(null, `no verifier for rule ${c.rule}`);
      return;
    }
    if (c.secret.length === 0 || (provider.accepts !== undefined && !provider.accepts(c.secret))) {
      results[i] = skipped(provider, `${provider.name}: this token type has no read-only identity check`);
      return;
    }
    const key = `${provider.name}\u0000${c.secret}`;
    let slot = byKey.get(key);
    if (slot === undefined) {
      slot = distinct.length;
      byKey.set(key, slot);
      distinct.push({ provider, secret: c.secret, holders: [] });
    }
    distinct[slot]?.holders.push(i);
  });

  const answers: SecretCheck[] = distinct.map((d, j) => {
    if (offline) return notSent(d.provider, OFFLINE_REASON);
    if (j >= maxSecrets) {
      return notSent(d.provider, `not verified: per-scan limit of ${maxSecrets} distinct secrets reached`);
    }
    return notSent(d.provider, 'not verified');
  });

  if (!offline) {
    const toCheck = distinct.slice(0, maxSecrets);
    const workers = Math.min(Math.max(1, Math.floor(opts.concurrency ?? MAX_IN_FLIGHT)), MAX_IN_FLIGHT, toCheck.length);
    let next = 0;
    const work = async (): Promise<void> => {
      for (;;) {
        const j = next;
        next += 1;
        const d = toCheck[j];
        if (d === undefined) return;
        answers[j] = await checkOne(d.provider, d.secret, opts);
      }
    };
    await Promise.all(Array.from({ length: workers }, work));
  }

  distinct.forEach((d, j) => {
    const answer = answers[j];
    if (answer === undefined) return;
    for (const i of d.holders) results[i] = answer;
  });
  return results.map((r) => r ?? skipped(null, 'not verified'));
}

/** One request to one provider. Never throws. */
async function checkOne(provider: SecretProvider, secret: string, opts: VerifyOptions): Promise<SecretCheck> {
  const host = providerHost(provider);
  if (opts.signal?.aborted === true) return notSent(provider, 'not verified: the scan was cancelled');
  const fetchImpl = opts.fetchImpl ?? (typeof globalThis.fetch === 'function' ? globalThis.fetch : undefined);
  if (fetchImpl === undefined) return notSent(provider, 'not verified: no fetch implementation in this runtime');

  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const timeout = AbortSignal.timeout(timeoutMs);
  const signal = opts.signal !== undefined ? AbortSignal.any([opts.signal, timeout]) : timeout;
  const base = { provider: provider.name, host, sent: true, rotate: provider.rotate };
  try {
    const res = await fetchImpl(provider.endpoint, {
      method: provider.method,
      headers: provider.headers(secret),
      // A redirect would carry the credential somewhere else: never followed.
      redirect: 'manual',
      signal,
    });
    const body = await readJsonBody(res);
    const c = provider.classify({ status: res.status, body });
    return { ...base, verdict: c.verdict, reason: c.reason };
  } catch (e) {
    return { ...base, verdict: 'unknown', reason: describeFailure(e, host, timeout, opts.signal, timeoutMs) };
  }
}

/** The body as JSON, or null — bounded in size, and never surfaced as text. */
async function readJsonBody(res: Response): Promise<unknown> {
  if (res.body === null) return null;
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > MAX_BODY_BYTES) {
        await reader.cancel().catch(() => undefined);
        return null;
      }
      chunks.push(value);
    }
    return JSON.parse(Buffer.concat(chunks).toString('utf8')) as unknown;
  } catch {
    return null;
  }
}

function describeFailure(
  e: unknown,
  host: string,
  timeout: AbortSignal,
  cancel: AbortSignal | undefined,
  timeoutMs: number,
): string {
  if (timeout.aborted) return `no answer from ${host} within ${timeoutMs / 1000} s`;
  if (cancel?.aborted === true) return `the scan was cancelled before ${host} answered`;
  const code = errorCode(e);
  return code !== null
    ? `could not reach ${host} (${code}) — offline, DNS or a proxy?`
    : `could not reach ${host} (network error)`;
}

/** A Node/undici error code from `e` or its causes — an identifier, never message text. */
function errorCode(e: unknown): string | null {
  let current: unknown = e;
  for (let depth = 0; depth < 4 && typeof current === 'object' && current !== null; depth += 1) {
    const code = (current as { code?: unknown }).code;
    if (typeof code === 'string' && /^[A-Z][A-Z0-9_]{1,40}$/.test(code)) return code;
    current = (current as { cause?: unknown }).cause;
  }
  return null;
}

/**
 * The check of a finding whose value is not sent at all (offline, no value
 * captured): `skipped` for a rule with no verifier, else `unknown`.
 */
export function unsentCheck(rule: string, reason: string): SecretCheck {
  const provider = providerForRule(rule);
  return provider === undefined ? skipped(null, `no verifier for rule ${rule}`) : notSent(provider, reason);
}

function skipped(provider: SecretProvider | null, reason: string): SecretCheck {
  return {
    verdict: 'skipped',
    reason,
    provider: provider?.name ?? null,
    host: provider === null ? null : providerHost(provider),
    sent: false,
    rotate: provider?.rotate ?? null,
  };
}

function notSent(provider: SecretProvider, reason: string): SecretCheck {
  return { verdict: 'unknown', reason, provider: provider.name, host: providerHost(provider), sent: false, rotate: provider.rotate };
}
