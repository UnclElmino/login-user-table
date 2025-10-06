const mysql = require('mysql2/promise');
const { MYSQL_HOST, MYSQL_PORT, MYSQL_USER, MYSQL_PASSWORD, MYSQL_DB } = process.env;

const pool = mysql.createPool({
  host: MYSQL_HOST,
  port: Number(MYSQL_PORT || 3306),
  user: MYSQL_USER,
  password: MYSQL_PASSWORD,
  database: MYSQL_DB,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

module.exports = { pool };
