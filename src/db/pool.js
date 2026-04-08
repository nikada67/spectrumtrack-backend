// src/db/pool.js
// mysql2 connection pool — shared across the whole app
const mysql = require('mysql2/promise');

const pool = mysql.createPool({
  host:               process.env.DB_HOST,
  port:               parseInt(process.env.DB_PORT || '3306'),
  database:           process.env.DB_NAME,
  user:               process.env.DB_USER,
  password:           process.env.DB_PASSWORD,
  waitForConnections: true,
  connectionLimit:    10,
  queueLimit:         0,
  // NOTE: rejectUnauthorized:false disables cert verification.
  // For production, provide the CA cert from your hosting provider instead.
  ssl: process.env.NODE_ENV === 'production'
    ? { rejectUnauthorized: false }
    : undefined,
});

// Quick connectivity test on startup
pool.getConnection()
  .then(conn => {
    console.log('✅  MySQL connected');
    conn.release();
  })
  .catch(err => {
    console.error('❌  MySQL connection failed:', err.message);
    process.exit(1);
  });

module.exports = pool;