'use strict';

// Fixture for guardian-import-esm's CommonJS destructuring-require form
// (`const { $SYMBOL, ... } = require("$MODULE")`), which neither
// admin-router.js's plain `const adminRouter = require(...)` nor any ESM
// file in this fixture tree exercises.

function formatDate(date) {
  return date.toISOString();
}

function formatCurrency(amount) {
  return `$${amount.toFixed(2)}`;
}

module.exports = { formatDate, formatCurrency };
