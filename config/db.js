const pgpInit = require('pg-promise');
require('dotenv').config();

const pgp = pgpInit();
let db;

if (process.env.DATABASE_URL) {
  // Production: Render PostgreSQL setup
  db = pgp({
    connection: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false },
  });
} else {
  // Development: Localhost PostgreSQL setup
  db = pgp({
    host: process.env.DB_HOST.trim(),
    port: parseInt(process.env.DB_PORT),
    database: process.env.DB_NAME,
    user: process.env.DB_USER,
    password: process.env.DB_PASS,
    ssl: false,
  });
}

module.exports = db;
