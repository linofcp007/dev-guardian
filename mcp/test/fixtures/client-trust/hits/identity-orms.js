/**
 * client-identity-from-request across the ORMs an Express API uses: Mongoose,
 * Sequelize, Knex, a MongoDB collection. Two of them are the shapes of OWASP
 * Juice Shop's own forged-feedback and forged-review routes (the owner, and
 * the author, taken from the body).
 */

const router = require('express').Router();
const { Note, Invoice, FeedbackModel } = require('./models');
const knex = require('./knex');
const db = require('./mongo');

router.get('/notes', auth, async (req, res) => {
  const notes = await Note.find({ owner: req.query.userId }); // BUG: client-identity-from-request -- Mongoose, a bare owner key
  res.json(notes);
});

router.get('/invoices', auth, async (req, res) => {
  const { customerId } = req.body;
  const invoices = await Invoice.findAll({ where: { customerId } }); // BUG: client-identity-from-request -- Sequelize
  res.json(invoices);
});

router.post('/members', auth, async (req, res) => {
  await knex('members').where({ tenant_id: req.query.tenant_id }).update({ role: req.body.role }); // BUG: client-identity-from-request -- Knex
  res.sendStatus(204);
});

// Juice Shop's forged feedback: the feedback's owner is whatever the body says.
router.post('/api/Feedbacks', (req, res, next) => {
  FeedbackModel.create({ UserId: req.body.UserId, comment: req.body.comment, rating: req.body.rating }) // BUG: client-identity-from-request -- Sequelize, UserId
    .then((feedback) => res.status(201).json({ status: 'success', data: feedback }))
    .catch(next);
});

// Juice Shop's forged review: the author is whatever the body says.
router.put('/rest/products/:id/reviews', (req, res) => {
  db.reviewsCollection.insert({ product: req.params.id, message: req.body.message, author: req.body.author, likesCount: 0 }) // BUG: client-identity-from-request -- a collection, author
    .then(() => res.status(201).json({ status: 'success' }));
});

// An in-memory store is a lookup by the claimed id all the same.
router.get('/sessions', (req, res) => {
  res.json(sessions.find({ userId: req.query.userId })); // BUG: client-identity-from-request -- an in-memory find
});

module.exports = router;
