/**
 * `redactHeaderCredentials` — the credentials a target sends back never
 * reach a DAST evidence file: a cookie's value goes, its name and the
 * attributes that say how it is protected stay.
 */
import { describe, expect, it } from 'vitest';
import { redactHeaderCredentials } from '../../../src/dast/redact.js';

describe('redactHeaderCredentials', () => {
  it("removes a Set-Cookie's values and keeps its names and attributes", () => {
    const out = redactHeaderCredentials({
      'set-cookie': 'sid=abc==; Path=/; Expires=Wed, 21 Oct 2037 07:28:00 GMT; HttpOnly; Secure; SameSite=Lax',
    });
    expect(out['set-cookie']).toBe('sid=«redacted»; Path=/; Expires=Wed, 21 Oct 2037 07:28:00 GMT; HttpOnly; Secure; SameSite=Lax');
  });

  it('removes every cookie of a combined line', () => {
    const out = redactHeaderCredentials({ 'set-cookie': 'a=1; Path=/, b=2; Max-Age=60' });
    expect(out['set-cookie']).toBe('a=«redacted»; Path=/, b=«redacted»; Max-Age=60');
  });

  it('removes an Authorization, Proxy-Authorization or Cookie value whole, and leaves the rest', () => {
    expect(redactHeaderCredentials({
      authorization: 'Bearer t', 'proxy-authorization': 'Basic x', cookie: 'sid=1', 'content-type': 'text/html',
    })).toEqual({
      authorization: '«redacted»', 'proxy-authorization': '«redacted»', cookie: '«redacted»', 'content-type': 'text/html',
    });
  });
});
