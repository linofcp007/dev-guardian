const { Router } = require('express');

const router = Router();

// M02 resolves to /api/v2/list, and only if BOTH halves of the mount fix hold:
// the rule matched the three-argument form at all, and `synthesizeMount` read
// the LAST argument as $ROUTER rather than the identifier after the prefix
// (which is `requireAuth`, and binds to nothing).
router.get('/list', (req, res) => res.json([]));

module.exports = router;
