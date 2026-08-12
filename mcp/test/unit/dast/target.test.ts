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

  // Classic SSRF numeral-obfuscation loopback forms: decimal (`2130706433`),
  // hex-octet (`0x7f.0.0.1`), shorthand (`127.1`), and IPv4-mapped IPv6
  // (`::ffff:127.0.0.1`). `classifyHost`/`parseIpv4` have no decimal, hex or
  // octal parsing of their own — the first three are safe today only because
  // WHATWG `new URL()` canonicalises them to plain dotted-decimal
  // (`127.0.0.1`) before classification ever sees the string. This test pins
  // that dependency: it exists to fail loudly if a future change moves any of
  // this parsing into `parseIpv4` (hand-rolled hex/octal support "for
  // robustness", say) instead of leaving it to the URL parser — such a change
  // could flip the safe direction into the unsafe one with nothing else here
  // to catch it.
  //
  // `::ffff:127.0.0.1` is the deliberate exception, not a gap: `new URL()`
  // keeps it as an IPv6 literal (canonicalised to `[::ffff:7f00:1]`), which
  // the IPv6 branch of `classifyHost` does not recognise as loopback, so it
  // is classified `public` and refused without attestation. That is
  // over-restriction — this module's sanctioned failure direction (see the
  // file doc comment) — so it must stay refused; do not "fix" it by teaching
  // `classifyHost` to unwrap IPv4-mapped IPv6.
  it('pins numeral-obfuscated loopback forms to what the URL parser canonicalises them to', () => {
    const cases: [string, string, boolean][] = [
      ['http://2130706433', 'loopback', true],
      ['http://127.1', 'loopback', true],
      ['http://0x7f.0.0.1', 'loopback', true],
      ['http://[::ffff:127.0.0.1]', 'public', false],
    ];
    for (const [url, expectedClass, expectedAllowed] of cases) {
      const d = classifyTarget(url, false);
      expect(d.target_class, url).toBe(expectedClass);
      expect(d.allowed, url).toBe(expectedAllowed);
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
