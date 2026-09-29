import { describe, expect, it } from 'vitest';
import { decodeText } from '../../../src/hooks/textEncoding.js';

const TEXT = 'password = "é-ünïcode ✓ 1234"\nline two\n';

function be(text: string): Buffer {
  return Buffer.from(text, 'utf16le').swap16();
}

describe('decodeText (review M3)', () => {
  it.each([
    ['UTF-8', Buffer.from(TEXT, 'utf8')],
    ['UTF-8 with a BOM', Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(TEXT, 'utf8')])],
    ['UTF-16LE with a BOM', Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(TEXT, 'utf16le')])],
    ['UTF-16BE with a BOM', Buffer.concat([Buffer.from([0xfe, 0xff]), be(TEXT)])],
    ['UTF-16LE, NUL-interleaved', Buffer.from(TEXT, 'utf16le')],
    ['UTF-16BE, NUL-interleaved', be(TEXT)],
  ])('%s', (_label, bytes) => expect(decodeText(bytes)).toBe(TEXT));

  it('an odd trailing byte of UTF-16 is dropped, not a crash', () => {
    const bytes = Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from('ab', 'utf16le'), Buffer.from([0x41])]);
    expect(decodeText(bytes)).toBe('ab');
  });

  it('binary data with NULs on both sides stays UTF-8', () => {
    const bytes = Buffer.from([0, 0, 1, 0, 0, 2, 0, 0, 3, 4, 0, 0]);
    expect(decodeText(bytes)).toBe(bytes.toString('utf8'));
  });

  it('an empty file is empty', () => expect(decodeText(Buffer.alloc(0))).toBe(''));
});
