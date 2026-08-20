const cache = new Map();
const fsp = require('node:fs/promises');
const logger = require('./logger');

// F01 Map.get with a path-shaped key — 1 arg, `...` matches zero
const v = cache.get('/etc/passwd');
// F02 Map.set/delete
cache.delete('/tmp/session');
// F03 axios-style client
const api = { get: () => {}, post: () => {} };
api.get('/external/thing', { timeout: 1 });
// F04 fetch wrapper
http.post('/webhook/out', body);
// F05 localStorage-ish
storage.get('/prefs');
// F06 app.use with a non-router second arg
app.use('/static', express.static('public'));
