// Safe Express app: every route properly sanitizes. All true negatives.
const express = require('express');
const escapeHtml = require('escape-html');
const path = require('path');
const fs = require('fs');
const db = require('./db');

const app = express();
app.use(express.json());

// SAFE: parameterized query
app.get('/search', async (req, res) => {
  const rows = await db.query('SELECT * FROM products WHERE name LIKE ?', ['%' + req.query.term + '%']);
  res.json(rows);
});

// SAFE: output encoded
app.get('/greet', (req, res) => {
  res.send('<h1>Hello ' + escapeHtml(req.query.name) + '</h1>');
});

// SAFE: path contained with basename against a fixed base
app.get('/download', (req, res) => {
  const name = path.basename(req.query.file);
  fs.readFile(path.join('/var/data', name), (err, data) => res.end(data));
});

// SAFE: numeric coercion before query
app.get('/users/:id', async (req, res) => {
  const id = Number(req.params.id);
  const rows = await db.query('SELECT * FROM users WHERE id = ' + id);
  res.json(rows);
});

// SAFE: allowlist guard before redirect
const ALLOWED = ['/home', '/dashboard'];
app.get('/go', (req, res) => {
  const to = req.query.to;
  if (!ALLOWED.includes(to)) return res.status(400).end();
  res.redirect(to);
});

app.listen(3000);
module.exports = app;
