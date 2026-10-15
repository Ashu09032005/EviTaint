// Deliberately vulnerable Express app for EviTaint benchmarking.
// Each vulnerability is annotated in ../../labels/vulnerable-express.json.
const express = require('express');
const cp = require('child_process');
const fs = require('fs');
const db = require('./db');
const { lookupUser } = require('./routes/users');

const app = express();
app.use(express.json());

// VULN sqli: req.query.id concatenated into SQL
app.get('/search', async (req, res) => {
  const term = req.query.term;
  const rows = await db.query('SELECT * FROM products WHERE name LIKE "%' + term + '%"');
  res.json(rows);
});

// VULN cmdi: req.body.host flows to exec through the shell
app.post('/diagnostics/ping', (req, res) => {
  const host = req.body.host;
  cp.exec('ping -c 1 ' + host, (err, stdout) => res.send(stdout));
});

// VULN path: req.query.file flows to readFile without containment
app.get('/download', (req, res) => {
  const file = req.query.file;
  fs.readFile('/var/data/' + file, (err, data) => res.end(data));
});

// VULN xss: req.query.name reflected via res.send
app.get('/greet', (req, res) => {
  res.send('<h1>Hello ' + req.query.name + '</h1>');
});

// VULN sqli (interprocedural + cross-file): req.params.id -> lookupUser -> db.query
app.get('/users/:id', async (req, res) => {
  const user = await lookupUser(req.params.id);
  res.json(user);
});

// SAFE (true negative): parameterized query
app.get('/orders/:id', async (req, res) => {
  const rows = await db.query('SELECT * FROM orders WHERE id = ?', [req.params.id]);
  res.json(rows);
});

// SAFE (true negative): constant command, no taint
app.get('/uptime', (req, res) => {
  cp.exec('uptime', (err, stdout) => res.send(String(stdout).replace(/</g, '&lt;')));
});

app.listen(3000);
module.exports = app;
