/**
 * client-webhook-parsed-body: the remaining shapes — constructEventAsync of a
 * re-serialised body, constructEvent of the `await req.json()` value, and
 * constructEventAsync of `req.body` behind express.json() (on the route, and
 * global).
 */

import express from 'express';
import Stripe from 'stripe';

const stripe = new Stripe('sk_test_placeholder');
const secret = 'whsec_placeholder';

export async function POST(req: Request) {
  const sig = req.headers.get('stripe-signature') ?? '';
  const body = await req.json();
  const a = await stripe.webhooks.constructEventAsync(JSON.stringify(body), sig, secret); // BUG: client-webhook-parsed-body -- async, JSON.stringify
  const b = stripe.webhooks.constructEvent(body, sig, secret); // BUG: client-webhook-parsed-body -- the await req.json() value
  return new Response(String([a.id, b.id]));
}

const app = express();
app.post('/a', express.json(), async (req, res) => {
  const event = await stripe.webhooks.constructEventAsync(req.body, String(req.headers['stripe-signature']), secret); // BUG: client-webhook-parsed-body -- async, express.json() route
  res.json({ id: event.id });
});

export function mount(server: express.Express) {
  server.use(express.json());
  server.post('/b', async (req, res) => {
    const event = await stripe.webhooks.constructEventAsync(req.body, String(req.headers['stripe-signature']), secret); // BUG: client-webhook-parsed-body -- async, global express.json()
    res.json({ id: event.id });
  });
}
