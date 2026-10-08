/**
 * web-js-path-traversal -- nothing here may fire (US-2.AC-2).
 *
 * `res.sendFile(p, { root })`: with the `root` option Express refuses a path
 * that climbs out of it (`..`), so the request value reaching the first
 * argument is not a traversal. The clause that leaves this call out needs a
 * fixture of its own: without one the ablation reads it as inert.
 */

import express from 'express';

const app = express();

app.get('/pages/:name', (req, res) => {
  res.sendFile(req.params.name, { root: '/srv/app/public' });
});

export default app;
