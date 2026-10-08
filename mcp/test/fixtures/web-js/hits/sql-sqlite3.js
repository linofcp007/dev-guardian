// web-js-sql-template on sqlite3 (callback API, CommonJS) -- every `// BUG` line fires the rule exactly once.
//
// `all`, `get` and `run` take the statement as their first argument; a
// template literal with an interpolation, or a concatenation with a value
// that is not a literal, is SQL injection (US-1.AC-1).

const sqlite3 = require('sqlite3');

const db = new sqlite3.Database('app.db');

function shiftsInWard(ward, done) {
  db.all(`SELECT * FROM shifts WHERE ward = '${ward}'`, done); // BUG: web-js-sql-template -- all, template literal
}

function shiftById(id, done) {
  db.get('SELECT * FROM shifts WHERE id = ' + id, done); // BUG: web-js-sql-template -- get, concatenation
}

function rename(id, title, done) {
  db.run(`UPDATE shifts SET title = '${title}' WHERE id = ?`, [id], done); // BUG: web-js-sql-template -- run, template literal
}

module.exports = { shiftsInWard, shiftById, rename };
