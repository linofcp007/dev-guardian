import { describe, expect, it } from 'vitest';
import { classifyTarget } from '../../../src/dast/target.js';

describe('classifyTarget', () => {
  it('allows loopback without attestation', () => {
    for (const url of [
      'http://localhost:3000',
      'http://127.0.0.1:8080',
      'http://127.0.0.5/',
      'http://[::1]:3000',
    ]) {
      const d = classifyTarget(url, false);
      expect(d.allowed, url).toBe(true);
      expect(d.target_class, url).toBe('loopback');
      expect(d.reason, url).toBeNull();
    }
  });

  it('refuses a non-loopback host without attestation and names the class', () => {
    const priv = classifyTarget('http://192.168.1.50:8080', false);
    expect(priv.allowed).toBe(false);
    expect(priv.target_class).toBe('private');
    expect(priv.reason).toMatch(/private network/i);

    const pub = classifyTarget('https://api.example.com', false);
    expect(pub.allowed).toBe(false);
    expect(pub.target_class).toBe('public');
    expect(pub.reason).toMatch(/public internet/i);
  });

  it('allows a non-loopback host once attested, keeping the class', () => {
    const d = classifyTarget('https://staging.example.com', true);
    expect(d.allowed).toBe(true);
    expect(d.target_class).toBe('public');
    expect(d.reason).toBeNull();
  });

  // Guards the wrong implementation that resolves DNS (or pattern-matches
  // "localhost" anywhere in the host): a hostname that merely CONTAINS or
  // resolves to loopback must still need attestation. Erring toward asking
  // for attestation is the safe direction; erring the other way is a scanner
  // pointed at a stranger's server.
  it('does not treat a loopback-looking hostname as loopback', () => {
    for (const url of [
      'http://localhost.evil.com',
      'http://127.0.0.1.evil.com',
      'http://notlocalhost',
    ]) {
      const d = classifyTarget(url, false);
      expect(d.allowed, url).toBe(false);
      expect(d.target_class, url).toBe('public');
    }
  });

  it('classifies every RFC1918 range plus link-local and ULA as private', () => {
    const cases: [string, string][] = [
      ['http://10.0.0.1', 'private'],
      ['http://172.16.0.1', 'private'],
      ['http://172.31.255.254', 'private'],
      ['http://192.168.0.1', 'private'],
      ['http://169.254.1.1', 'private'],
      ['http://[fc00::1]', 'private'],
      // 172.32.x is OUTSIDE the /12 — the classic off-by-one. Public.
      ['http://172.32.0.1', 'public'],
      ['http://172.15.0.1', 'public'],
      ['http://8.8.8.8', 'public'],
    ];
    for (const [url, expected] of cases) {
      expect(classifyTarget(url, false).target_class, url).toBe(expected);
    }
  });

  it('refuses a non-http(s) scheme and an unparseable url', () => {
    const ftp = classifyTarget('ftp://localhost/x', true);
    expect(ftp.allowed).toBe(false);
    expect(ftp.reason).toMatch(/http/i);

    const junk = classifyTarget('not a url', true);
    expect(junk.allowed).toBe(false);
    expect(junk.origin).toBe('');
  });

  it('normalises the origin and drops any path, query or fragment', () => {
    const d = classifyTarget('http://localhost:3000/api/v1?x=1#frag', false);
    expect(d.origin).toBe('http://localhost:3000');
    expect(d.host).toBe('localhost');
  });
});
