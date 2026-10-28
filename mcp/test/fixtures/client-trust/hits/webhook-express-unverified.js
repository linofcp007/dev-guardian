/**
 * client-webhook-unverified: an Express route that marks an invoice paid on
 * the body's word. The finding covers the route call.
 */

const express = require('express');
const app = express();

app.post('/webhooks/stripe', express.json(), async (req, res) => { // BUG: client-webhook-unverified -- if on req.body.type
  if (req.body.type === 'invoice.paid') {
    await markPaid(req.body.data.object.id);
  }
  res.sendStatus(200);
});

async function markPaid(id) {
  return id;
}
