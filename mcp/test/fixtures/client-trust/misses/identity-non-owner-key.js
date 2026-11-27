/**
 * client-identity-from-request, safe: request fields under keys that name no
 * owner (a title, a status, the object's own id), next to an owner taken from
 * the session.
 */

router.post('/posts', requireAuth, async (req, res) => {
  await prisma.post.create({ data: { title: req.body.title, body: req.body.body, authorId: req.user.id } });
  res.sendStatus(201);
});

router.get('/products', async (req, res) => {
  res.json(await Product.findAll({ where: { status: req.query.status, categoryId: req.query.categoryId } }));
});

// A user id from the request as the VALUE of another role's key: whom a review is assigned to, not whose it is.
router.put('/reviews/:id/reviewer', requireAuth, async (req, res) => {
  await prisma.review.update({ where: { id: req.params.id }, data: { reviewerId: req.body.userId } });
  res.sendStatus(204);
});

router.put('/products/:productId', requireAuth, async (req, res) => {
  await prisma.product.update({ where: { id: req.params.productId }, data: { price: req.body.price } });
  res.sendStatus(204);
});
