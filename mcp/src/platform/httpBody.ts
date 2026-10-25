/**
 * A response body read to a byte cap — for every download whose size the
 * other end decides.
 *
 * `await res.arrayBuffer()` and `await res.json()` read whatever arrives,
 * bounded only by the caller's timeout: `scan_skill` on a URL wrote a body of
 * any length to disk inside its 60 s, and the KEV and EPSS clients held one in
 * memory. Here a declared `Content-Length` over the cap is refused before a
 * byte is read, and a body that runs past it (no length, or a wrong one) is
 * cancelled at the cap — never buffered whole first.
 */

/** The body, or `null` when it is longer than `maxBytes`. A stream error rejects, as `arrayBuffer()` would. */
export async function readBodyCapped(res: Response, maxBytes: number): Promise<Buffer | null> {
  const declared = Number(res.headers.get('content-length') ?? '');
  if (Number.isFinite(declared) && declared > maxBytes) {
    await res.body?.cancel().catch(() => undefined);
    return null;
  }
  if (res.body === null) return Buffer.alloc(0);
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > maxBytes) {
      await reader.cancel().catch(() => undefined);
      return null;
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks);
}

/** The body parsed as JSON, read to at most `maxBytes` — `null` when it is longer. Malformed JSON throws, as `res.json()` does. */
export async function readJsonCapped(res: Response, maxBytes: number): Promise<{ json: unknown } | null> {
  const body = await readBodyCapped(res, maxBytes);
  if (body === null) return null;
  return { json: JSON.parse(body.toString('utf8')) as unknown };
}

/** `n` bytes as whole mebibytes, for a message. */
export function mebibytes(n: number): string {
  return `${Math.round(n / (1024 * 1024))} MiB`;
}
