/**
 * The event re-fetched from the gateway's API by its id — Stripe's
 * `stripe.events.retrieve(id)` — IS the verification: what the request says
 * is only an id. And a queue consumer's `on('message')` callback is no HTTP
 * route. Nothing fires (fix round 2 of the review, items 1a and 1b).
 */

declare const stripe: { events: { retrieve(id: string): Promise<{ type: string; data: { object: unknown } }> } };
declare const consumer: { on(event: string, cb: (msg: { body: string }) => Promise<void>): void };
declare function grant(x: unknown): Promise<void>;

export async function POST(req: Request) {
  const { id } = await req.json();
  const event = await stripe.events.retrieve(id);
  if (event.type === 'invoice.paid') await grant(event.data.object);
  return new Response('ok');
}

consumer.on('message', async (msg) => {
  const event = JSON.parse(msg.body);
  switch (event.type) {
    case 'invoice.paid':
      await grant(event);
  }
});
