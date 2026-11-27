/**
 * client-identity-from-request, safe: the user record READ by the id in the
 * route (a public profile), and records looked up by their own id. The
 * record's own key is not an owner key; only a write of the user record by a
 * claimed owner id fires (hits/identity-self-record.js).
 */

router.get('/users/:userId', async (req, res) => {
  const user = await prisma.user.findUnique({ where: { id: req.params.userId }, select: { name: true, avatar: true } });
  res.json(user);
});

router.get('/profiles/:userId', async (req, res) => {
  res.json(await User.findOne({ _id: req.params.userId }).select('name bio'));
});

router.get('/orders/:id', requireAuth, async (req, res) => {
  res.json(await prisma.order.findFirst({ where: { id: req.params.id, userId: req.user.id } }));
});

router.delete('/orders/:id', requireAuth, async (req, res) => {
  await Order.deleteOne({ _id: req.params.id, owner: req.user.id });
  res.sendStatus(204);
});
