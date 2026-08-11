'use strict';

const express = require('express');
const adminRouter = require('./admin-router');

const app = express();

app.use('/admin', adminRouter);

module.exports = app;
