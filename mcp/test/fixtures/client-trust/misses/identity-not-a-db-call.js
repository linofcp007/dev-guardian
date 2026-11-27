/**
 * client-identity-from-request, safe: the claimed id goes into a response,
 * an analytics event, a log line or a template, not into a database call.
 */

router.post('/echo', (req, res) => {
  res.json({ userId: req.body.userId, received: true });
});

router.post('/track', (req, res) => {
  analytics.track({ userId: req.body.userId, event: 'checkout' });
  logger.info({ userId: req.query.userId }, 'checkout');
  res.sendStatus(204);
});

router.get('/users/:userId/card', (req, res) => {
  res.render('card', { userId: req.params.userId });
});
