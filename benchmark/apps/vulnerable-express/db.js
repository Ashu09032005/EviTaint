// Mock DB module used only for realistic shape; EviTaint treats `query` as a SQL sink.
const mysql = require('mysql2');
const pool = mysql.createPool({ host: 'localhost', user: 'app', database: 'shop' });

async function query(sql, params) {
  const [rows] = await pool.promise().query(sql, params);
  return rows;
}

module.exports = { query };
