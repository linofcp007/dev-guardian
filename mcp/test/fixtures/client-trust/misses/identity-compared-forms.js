/**
 * client-identity-from-request, safe: every form of the comparison that
 * refuses, one handler each — `!==` and `!=`, the claimed id on the left or
 * on the right, and a branch that leaves by a `return`, a `throw`, or a block
 * that ends in one. (Generated as a table: the realistic shapes are in
 * identity-compared.ts.)
 */

const router = require('express').Router();
const { Order } = require('./models');
const { Forbidden } = require('./errors');

// !==, the claimed id on the left, a return.
router.get('/orders/form-1', requireAuth, async (req, res) => {
  const { userId } = req.query;
  if (userId !== req.user.id) return res.sendStatus(403);
  res.json(await Order.find({ userId }));
});

// !==, the claimed id on the left, a throw.
router.get('/orders/form-2', requireAuth, async (req, res) => {
  const { userId } = req.query;
  if (userId !== req.user.id) throw new Forbidden('not your orders');
  res.json(await Order.find({ userId }));
});

// !==, the claimed id on the left, a block ending in a return.
router.get('/orders/form-3', requireAuth, async (req, res) => {
  const { userId } = req.query;
  if (userId !== req.user.id) {
    res.status(403).json({ error: 'forbidden' });
    return;
  }
  res.json(await Order.find({ userId }));
});

// !==, the claimed id on the left, a block ending in a throw.
router.get('/orders/form-4', requireAuth, async (req, res) => {
  const { userId } = req.query;
  if (userId !== req.user.id) {
    audit.denied(req.user.id, userId);
    throw new Forbidden('not your orders');
  }
  res.json(await Order.find({ userId }));
});

// !==, the claimed id on the right, a return.
router.get('/orders/form-5', requireAuth, async (req, res) => {
  const { userId } = req.query;
  if (req.user.id !== userId) return res.sendStatus(403);
  res.json(await Order.find({ userId }));
});

// !==, the claimed id on the right, a throw.
router.get('/orders/form-6', requireAuth, async (req, res) => {
  const { userId } = req.query;
  if (req.user.id !== userId) throw new Forbidden('not your orders');
  res.json(await Order.find({ userId }));
});

// !==, the claimed id on the right, a block ending in a return.
router.get('/orders/form-7', requireAuth, async (req, res) => {
  const { userId } = req.query;
  if (req.user.id !== userId) {
    res.status(403).json({ error: 'forbidden' });
    return;
  }
  res.json(await Order.find({ userId }));
});

// !==, the claimed id on the right, a block ending in a throw.
router.get('/orders/form-8', requireAuth, async (req, res) => {
  const { userId } = req.query;
  if (req.user.id !== userId) {
    audit.denied(req.user.id, userId);
    throw new Forbidden('not your orders');
  }
  res.json(await Order.find({ userId }));
});

// !=, the claimed id on the left, a return.
router.get('/orders/form-9', requireAuth, async (req, res) => {
  const { userId } = req.query;
  if (userId != req.user.id) return res.sendStatus(403);
  res.json(await Order.find({ userId }));
});

// !=, the claimed id on the left, a throw.
router.get('/orders/form-10', requireAuth, async (req, res) => {
  const { userId } = req.query;
  if (userId != req.user.id) throw new Forbidden('not your orders');
  res.json(await Order.find({ userId }));
});

// !=, the claimed id on the left, a block ending in a return.
router.get('/orders/form-11', requireAuth, async (req, res) => {
  const { userId } = req.query;
  if (userId != req.user.id) {
    res.status(403).json({ error: 'forbidden' });
    return;
  }
  res.json(await Order.find({ userId }));
});

// !=, the claimed id on the left, a block ending in a throw.
router.get('/orders/form-12', requireAuth, async (req, res) => {
  const { userId } = req.query;
  if (userId != req.user.id) {
    audit.denied(req.user.id, userId);
    throw new Forbidden('not your orders');
  }
  res.json(await Order.find({ userId }));
});

// !=, the claimed id on the right, a return.
router.get('/orders/form-13', requireAuth, async (req, res) => {
  const { userId } = req.query;
  if (req.user.id != userId) return res.sendStatus(403);
  res.json(await Order.find({ userId }));
});

// !=, the claimed id on the right, a throw.
router.get('/orders/form-14', requireAuth, async (req, res) => {
  const { userId } = req.query;
  if (req.user.id != userId) throw new Forbidden('not your orders');
  res.json(await Order.find({ userId }));
});

// !=, the claimed id on the right, a block ending in a return.
router.get('/orders/form-15', requireAuth, async (req, res) => {
  const { userId } = req.query;
  if (req.user.id != userId) {
    res.status(403).json({ error: 'forbidden' });
    return;
  }
  res.json(await Order.find({ userId }));
});

// !=, the claimed id on the right, a block ending in a throw.
router.get('/orders/form-16', requireAuth, async (req, res) => {
  const { userId } = req.query;
  if (req.user.id != userId) {
    audit.denied(req.user.id, userId);
    throw new Forbidden('not your orders');
  }
  res.json(await Order.find({ userId }));
});

module.exports = router;
