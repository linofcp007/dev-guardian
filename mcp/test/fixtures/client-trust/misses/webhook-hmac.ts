/**
 * A generic webhook handler that verifies an HMAC of the raw body itself
 * (Lemon Squeezy's X-Signature), compared in constant time. Nothing fires.
 */

import crypto from 'node:crypto';

declare function grant(x: unknown): Promise<void>;

export async function POST(req: Request) {
  const raw = await req.text();
  const digest = crypto.createHmac('sha256', process.env.LEMON_SQUEEZY_WEBHOOK_SECRET ?? '').update(raw).digest('hex');
  const given = req.headers.get('x-signature') ?? '';
  if (digest.length !== given.length || !crypto.timingSafeEqual(Buffer.from(digest), Buffer.from(given))) {
    return new Response('bad signature', { status: 401 });
  }
  const payload = JSON.parse(raw);
  if (payload.meta.event_name === 'order_created') {
    await grant(payload.data);
  }
  return new Response('ok');
}
