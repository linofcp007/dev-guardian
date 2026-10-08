/**
 * web-js-path-traversal -- nothing here may fire (EC-3).
 *
 * `path.join(__dirname, 'static', 'index.html')` holds only literals. The
 * handler does read the request, for something that is not the path.
 */

import fs from 'node:fs';
import path from 'node:path';
import express from 'express';

const app = express();

app.get('/', (req, res) => {
  res.set('x-request-id', String(req.query.rid ?? ''));
  res.sendFile(path.join(__dirname, 'static', 'index.html'));
});

app.get('/robots.txt', (_req, res) => {
  fs.createReadStream(path.resolve(__dirname, 'static', 'robots.txt')).pipe(res);
});

export default app;
