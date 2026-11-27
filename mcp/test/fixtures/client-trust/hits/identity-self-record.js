/**
 * client-identity-from-request on the user record itself: chosen by its own
 * key (`_id`, `id`) from a request field that names an owner id, in a WRITE
 * (update, delete, find-and-modify). Reading a record by such an id is a
 * public profile, and does not fire (misses/identity-profile-read.js).
 */

const { PrismaClient } = require('@prisma/client');
const User = require('./models/user');

const prisma = new PrismaClient();

router.post('/profile', auth, async (req, res) => {
  await User.updateOne({ _id: req.body.userId }, { $set: { bio: req.body.bio } }); // BUG: client-identity-from-request -- Mongoose, top level
  res.sendStatus(204);
});

router.post('/account/delete', auth, async (req, res) => {
  await prisma.user.delete({ where: { id: req.body.userId } }); // BUG: client-identity-from-request -- Prisma, under where
  res.sendStatus(204);
});

router.post('/account/email', auth, async (req, res) => {
  const { accountId, email } = req.body;
  const user = await User.findOneAndUpdate({ _id: accountId }, { email }, { new: true }); // BUG: client-identity-from-request -- a variable named as an owner id
  res.json(user);
});
