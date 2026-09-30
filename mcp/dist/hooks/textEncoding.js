/**
 * A file's bytes as text, whatever Windows wrote them in (review of 3.0.0,
 * M3). PowerShell 5.1's `>` and `Out-File` write UTF-16LE by default;
 * `dev-guardian check --file` read every file as UTF-8, so each character of
 * such a file came with a NUL after it, no pattern matched, and a key in it
 * read "No secrets detected".
 *
 * UTF-16 is recognised by its byte-order mark, or — without one — when the
 * bytes are NUL-interleaved the way mostly-ASCII UTF-16 is (a NUL in nearly
 * every other byte, on one side only). Anything else is UTF-8, a UTF-8
 * byte-order mark dropped. Node built-ins only: the CLI imports the compiled
 * copy from `mcp/dist/hooks/`.
 */
/** How much of the start of a file the NUL-interleaving guess reads. */
const SAMPLE = 4096;
/** UTF-16 in either byte order: big-endian is swapped to little-endian first. */
function decodeUtf16(bytes, order) {
    const even = bytes.length - (bytes.length % 2);
    const buf = Buffer.from(bytes.buffer, bytes.byteOffset, even);
    const le = order === 'le' ? buf : Buffer.from(buf).swap16();
    return le.toString('utf16le');
}
/**
 * `le` / `be` when the start of `bytes` reads as mostly-ASCII UTF-16 with no
 * byte-order mark: at least 40% of the byte pairs have a NUL on one side, and
 * at most 5% on the other. `null` otherwise — binary data with NULs scattered
 * on both sides included.
 */
function utf16Order(bytes) {
    const pairs = Math.floor(Math.min(bytes.length, SAMPLE) / 2);
    if (pairs < 2)
        return null;
    let evenNul = 0;
    let oddNul = 0;
    for (let p = 0; p < pairs; p += 1) {
        if (bytes[2 * p] === 0)
            evenNul += 1;
        if (bytes[2 * p + 1] === 0)
            oddNul += 1;
    }
    if (oddNul >= 0.4 * pairs && evenNul <= 0.05 * pairs)
        return 'le';
    if (evenNul >= 0.4 * pairs && oddNul <= 0.05 * pairs)
        return 'be';
    return null;
}
/** `bytes` as text: UTF-16 LE/BE by byte-order mark or NUL-interleaving, else UTF-8 (its byte-order mark dropped). */
export function decodeText(bytes) {
    if (bytes[0] === 0xff && bytes[1] === 0xfe)
        return decodeUtf16(bytes.subarray(2), 'le');
    if (bytes[0] === 0xfe && bytes[1] === 0xff)
        return decodeUtf16(bytes.subarray(2), 'be');
    if (bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf)
        return Buffer.from(bytes.subarray(3)).toString('utf8');
    const order = utf16Order(bytes);
    return order === null ? Buffer.from(bytes).toString('utf8') : decodeUtf16(bytes, order);
}
//# sourceMappingURL=textEncoding.js.map