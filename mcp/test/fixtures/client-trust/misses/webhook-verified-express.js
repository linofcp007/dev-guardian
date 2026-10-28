/**
 * Express done right: the webhook route gets express.raw() and is registered
 * BEFORE the global express.json(), so req.body is the raw Buffer.
 */

const express = require('express');
const Stripe = require('stripe');

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);
const app = express();

app.post('/webhooks/stripe', express.raw({ type: 'application/json' }), (req, res) => {
  const event = stripe.webhooks.constructEvent(req.body, req.headers['stripe-signature'], process.env.STRIPE_WEBHOOK_SECRET);
  if (event.type === 'invoice.paid') {
    markPaid(event.data.object.id);
  }
  res.sendStatus(200);
});

app.use(express.json());

function markPaid(id) {
  return id;
}
