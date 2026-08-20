// NOT part of the auditor's corpus — added alongside the three-argument mount
// fix, because that fix has no observable effect anywhere else in this tree.
// `app.use(prefix, middleware, router)` is the standard way to protect a
// mounted router, and it was invisible to `guardian-mount-express`: the rule
// had no ellipsis, so it matched the two-argument form only. The cost was not
// the prefix but every route in the mounted file — resolveNodeMounts finds no
// prefix for the file and flips all of them to path_partial.
const express = require('express');
const requireAuth = require('./auth');
const ordersRouter = require('./orders');

const app = express();

// M01 prefix + middleware + router.
app.use('/api/v2', requireAuth, ordersRouter);

module.exports = app;
