'use strict';

const express = require('express');

const router = express.Router();

router.get('/reports', (req, res) => res.json({ reports: [] }));

module.exports = router;
