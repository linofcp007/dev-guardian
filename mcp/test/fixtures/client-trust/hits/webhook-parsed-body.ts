/**
 * client-webhook-parsed-body: Stripe's signature covers the exact bytes of
 * the request, and every one of these hands constructEvent a re-serialised
 * or parsed body, so verification always fails.
 */

import express from 'express';
import Stripe from 'stripe';

const stripe = new Stripe('sk_test_placeholder');
const secret = 'whsec_placeholder';

export async function POST(req: Request) {
  const body = await req.json();
  const sig = req.headers.get('stripe-signature') ?? '';
  const a = stripe.webhooks.constructEvent(JSON.stringify(body), sig, secret); // BUG: client-webhook-parsed-body -- JSON.stringify
  const b = await stripe.webhooks.constructEventAsync(body, sig, secret); // BUG: client-webhook-parsed-body -- the await req.json() value
  return new Response(JSON.stringify([a.type, b.type]));
}

const app = express();

app.post('/hook', express.json(), (req, res) => {
  const event = stripe.webhooks.constructEvent(req.body, String(req.headers['stripe-signature']), secret); // BUG: client-webhook-parsed-body -- express.json() route
  res.json({ received: event.id });
});

export function mount(server: express.Express) {
  server.use(express.json());
  server.post('/stripe', express.raw({ type: 'application/json' }), (req, res) => {
    const event = stripe.webhooks.constructEvent(req.body, String(req.headers['stripe-signature']), secret); // BUG: client-webhook-parsed-body -- a global express.json() runs first
    res.json({ received: event.id });
  });
}
