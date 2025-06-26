const pgpInit = require('pg-promise');
require('dotenv').config();

const pgp = pgpInit();

let db;

if (process.env.DATABASE_URL) {
  // Production/Render setup
  db = pgp({
    connectionString: process.env.DATABASE_URL,
    ssl: {
      rejectUnauthorized: false, // required for Render
    },
  });
} else {
  // Localhost development setup
  db = pgp({
    host: process.env.DB_HOST || 'localhost',
    port: process.env.DB_PORT || 5432,
    database: process.env.DB_NAME,
    user: process.env.DB_USER,
    password: process.env.DB_PASS,
    ssl: false,
  });
}

module.exports = db;
