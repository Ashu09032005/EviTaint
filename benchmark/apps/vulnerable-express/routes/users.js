// Cross-file helper: the taint flows server.js -> here -> db.query (SQL injection).
const db = require('../db');

async function lookupUser(id) {
  // VULN sqli: `id` originates from req.params.id in server.js
  return db.query('SELECT * FROM users WHERE id = ' + id);
}

function sanitizeId(id) {
  return String(Number(id)); // coercion sanitizer
}

// SAFE helper: coerces before querying
async function lookupUserSafe(id) {
  return db.query('SELECT * FROM users WHERE id = ' + sanitizeId(id));
}

module.exports = { lookupUser, lookupUserSafe };
