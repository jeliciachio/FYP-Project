// ✅ STEP 1: db.js (MySQL connection setup)
// Place this in the root or a separate "config" folder

const mysql = require('mysql2');
require('dotenv').config();

const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: 'c207',
    database: 'rp_digital_bank'
});

db.connect((err) => {
  if (err) {
    console.error('Database connection failed:', err);
    return;
  }
  console.log('Connected to MySQL database');
});


module.exports = db;