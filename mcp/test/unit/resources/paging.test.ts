import { describe, expect, it } from 'vitest';
import { UriTemplate } from '@modelcontextprotocol/sdk/shared/uriTemplate.js';
import {
  MAX_PAGE_SIZE,
  MESSAGE_MAX_CHARS,
  QueryTolerantUriTemplate,
  boundFinding,
  paginate,
} from '../../../src/resources/paging.js';

describe('QueryTolerantUriTemplate', () => {
  const open = new QueryTolerantUriTemplate('guardian://findings/open{?page,page_size}');
  const bySeverity = new QueryTolerantUriTemplate('guardian://findings/by-severity/{level}{?page,page_size}');

  it("is needed: the SDK's own matcher wants every query parameter, in order", () => {
    const sdk = new UriTemplate('guardian://findings/open{?page,page_size}');
    expect(sdk.match('guardian://findings/open?page=2')).toBeNull();
    expect(sdk.match('guardian://findings/open?page_size=5&page=2')).toBeNull();
  });

  it('matches the bare URI, any subset of the parameters, in any order', () => {
    expect(open.match('guardian://findings/open')).toEqual({});
    expect(open.match('guardian://findings/open?page=2')).toEqual({ page: '2' });
    expect(open.match('guardian://findings/open?page_size=5&page=2')).toEqual({ page: '2', page_size: '5' });
  });

  it('ignores unknown parameters instead of refusing the read', () => {
    expect(open.match('guardian://findings/open?page=3&foo=bar')).toEqual({ page: '3' });
  });

  it('keeps path variables and rejects other paths', () => {
    expect(bySeverity.match('guardian://findings/by-severity/high?page=1')).toEqual({ level: 'high', page: '1' });
    expect(open.match('guardian://findings/critical?page=1')).toBeNull();
    expect(open.match('guardian://findings/open/extra')).toBeNull();
  });

  it('advertises the declared template', () => {
    expect(open.toString()).toBe('guardian://findings/open{?page,page_size}');
  });
});

describe('paginate', () => {
  const items = Array.from({ length: 7 }, (_, i) => i);
  it('defaults, pages and caps the page size', () => {
    expect(paginate(new URL('guardian://x/y'), items)).toEqual({ items, total: 7, page: 1, page_size: 50 });
    expect(paginate(new URL('guardian://x/y?page=2&page_size=3'), items).items).toEqual([3, 4, 5]);
    expect(paginate(new URL('guardian://x/y?page_size=999'), items).page_size).toBe(MAX_PAGE_SIZE);
    expect(paginate(new URL('guardian://x/y?page=-4&page_size=abc'), items)).toMatchObject({ page: 1, page_size: 50 });
  });
});

describe('boundFinding', () => {
  it(`cuts a message to ${MESSAGE_MAX_CHARS} characters and leaves short ones alone`, () => {
    const base = { fingerprint: 'f', tool: 't', severity: 'low' as const, category: 'bug' as const, title: 't', fix_available: false };
    expect(boundFinding({ ...base, message: 'x'.repeat(5000) }).message).toHaveLength(MESSAGE_MAX_CHARS);
    expect(boundFinding({ ...base, message: 'short' }).message).toBe('short');
    expect(boundFinding(base)).toBe(base);
  });
});
