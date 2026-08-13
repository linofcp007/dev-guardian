'use strict';

const express = require('express');
const adminRouter = require('./admin-router');
const { formatDate, formatCurrency } = require('./format-utils');

const app = express();

app.use('/admin', adminRouter);
app.set('formatters', { formatDate, formatCurrency });

module.exports = app;
