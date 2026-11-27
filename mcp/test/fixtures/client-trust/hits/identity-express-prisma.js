/**
 * client-identity-from-request in an Express + Prisma API: whose record it is
 * comes from the request (the body, the query, the route), so the caller
 * picks whose orders, notes or settings it reads, creates, changes or
 * deletes. The finding is the object literal that carries the owner key.
 */

const express = require('express');
const { PrismaClient } = require('@prisma/client');
const { requireAuth } = require('./auth');

const prisma = new PrismaClient();
const app = express();
const router = express.Router();

app.post('/api/orders', requireAuth, async (req, res) => {
  const { userId, items } = req.body;
  const order = await prisma.order.create({ data: { userId, items } }); // BUG: client-identity-from-request -- destructured from the body
  res.json(order);
});

app.get('/api/orders', requireAuth, async (req, res) => {
  const orders = await prisma.order.findMany({ where: { userId: req.query.userId } }); // BUG: client-identity-from-request -- the query
  res.json(orders);
});

app.delete('/api/notes/:id', requireAuth, async (req, res) => {
  const ownerId = req.body.ownerId;
  await prisma.note.deleteMany({ where: { id: req.params.id, ownerId } }); // BUG: client-identity-from-request -- a variable from the body
  res.sendStatus(204);
});

router.put('/accounts/:accountId/settings', requireAuth, async (req, res) => {
  await prisma.setting.updateMany({ where: { accountId: req.params.accountId }, data: req.body.settings }); // BUG: client-identity-from-request -- the route
  res.sendStatus(204);
});

router.post('/carts', requireAuth, function (req, res, next) {
  let customer_id = req.body.customer_id;
  prisma.cart
    .upsert({
      where: { customer_id }, // BUG: client-identity-from-request -- a let, a function expression, a multi-line call
      create: { customer_id },  // BUG: client-identity-from-request -- the same variable, the create half
      update: {},
    })
    .then((cart) => res.json(cart), next);
});

// A transaction's callback: the request is a parameter of the route's handler, not of the innermost function.
app.post('/api/transfer', requireAuth, async (req, res) => {
  await prisma.$transaction(async (tx) => {
    await tx.order.create({ data: { userId: req.body.userId, total: 0 } }); // BUG: client-identity-from-request -- inside the transaction
  });
  res.sendStatus(201);
});

// A promise chain's callback.
app.post('/api/reorder', requireAuth, (req, res) => {
  prisma.order
    .findFirst({ where: { id: req.body.orderId } })
    .then((o) => prisma.order.create({ data: { userId: req.body.userId, items: o.items } })) // BUG: client-identity-from-request -- inside .then
    .then((o) => res.json(o));
});

module.exports = { app, router };
