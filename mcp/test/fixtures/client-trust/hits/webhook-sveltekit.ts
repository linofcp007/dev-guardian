/**
 * client-webhook-unverified in SvelteKit endpoints (`+server.ts`): the
 * request is a destructured `{ request }`. A response that SAYS `verified`
 * verifies nothing (fix round 2 of the review, item 1c).
 */

type RequestHandler = (event: { request: Request; locals: unknown }) => Promise<Response>;
declare function grant(x: unknown): Promise<void>;
declare function json(x: unknown): Response;

export async function POST({ request }: { request: Request }) { // BUG: client-webhook-unverified -- SvelteKit function, request.json()
  const event = await request.json();
  if (event.type === 'checkout.session.completed') await grant(event.data);
  return json({ received: true, verified: true });
}

export const PUT: RequestHandler = async ({ request, locals }) => { // BUG: client-webhook-unverified -- SvelteKit RequestHandler const
  const event = await request.json();
  switch (event.type) {
    case 'invoice.paid':
      await grant([event.data, locals]);
  }
  return json({ received: true });
};

export async function PATCH({ request }) { // BUG: client-webhook-unverified -- SvelteKit in plain JS style, no type annotation
  const { type, data } = await request.json();
  if (type === 'payment_intent.succeeded') await grant(data);
  return json({ ok: true });
}
