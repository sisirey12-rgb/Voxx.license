const { createClient } = require('@libsql/client');

// Turso (libSQL) — hosted, SQLite-compatible, free tier, no persistent disk needed.
// Set these in your .env / Render environment variables:
//   TURSO_DATABASE_URL   e.g. libsql://your-db-name.turso.io
//   TURSO_AUTH_TOKEN     from `turso db tokens create your-db-name`
const db = createClient({
  url: process.env.TURSO_DATABASE_URL,
  authToken: process.env.TURSO_AUTH_TOKEN,
});

async function init() {
  await db.execute(`
    CREATE TABLE IF NOT EXISTS licenses (
      license_key   TEXT PRIMARY KEY,
      device_hwid   TEXT,
      label         TEXT,
      created_at    TEXT NOT NULL,
      expires_at    TEXT NOT NULL,
      max_devices   INTEGER NOT NULL DEFAULT 1,
      status        TEXT NOT NULL DEFAULT 'active'
    );
  `);

  // Tracks every device bound to a key, for max_devices > 1 support.
  await db.execute(`
    CREATE TABLE IF NOT EXISTS license_devices (
      license_key TEXT NOT NULL,
      hwid        TEXT NOT NULL,
      bound_at    TEXT NOT NULL,
      PRIMARY KEY (license_key, hwid)
    );
  `);
}

module.exports = { db, init };
