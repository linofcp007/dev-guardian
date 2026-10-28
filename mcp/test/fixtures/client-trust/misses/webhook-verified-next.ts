/**
 * A Stripe webhook verified on the raw body (await req.text()), the event
 * read only after constructEvent. Nothing fires.
 */

import Stripe from 'stripe';

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY ?? '');

declare function grantPlan(session: unknown): Promise<void>;

export async function POST(req: Request) {
  const body = await req.text();
  const signature = req.headers.get('stripe-signature') ?? '';
  let event: Stripe.Event;
  try {
    event = stripe.webhooks.constructEvent(body, signature, process.env.STRIPE_WEBHOOK_SECRET ?? '');
  } catch {
    return new Response('bad signature', { status: 400 });
  }
  switch (event.type) {
    case 'checkout.session.completed':
      await grantPlan(event.data.object);
      break;
  }
  return new Response('ok');
}
