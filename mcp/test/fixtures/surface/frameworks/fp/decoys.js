const cache = new Map();
const fsp = require('node:fs/promises');
const logger = require('./logger');
const cors = require('cors');

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
// F07 a settings store addressed by path, read with ONE argument. `config` is
//     not on guardian-route-express's $APP denylist the way `cache` (F01) and
//     `storage` (F05) are, so this is the only line in the corpus where
//     `pattern-not: $APP.$METHOD($PATH)` is the clause that decides.
const config = new Map([['/site/title', 'Guardian']]);
const siteTitle = config.get('/site/title');
// F08 middleware first, router last: the first argument is a CALL, not a path.
//     Exercises guardian-mount-express's $PREFIX literal regex — F06 above
//     carries a literal prefix, so the regex never decides anything there.
const apiRouter = express.Router();
app.use(cors(), apiRouter);
