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
      status        TEXT NOT NULL DEFAULT 'active',
      reseller_id   INTEGER
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

  // Partners who can generate keys against their own credit balance.
  // token is a long random secret sent as X-Reseller-Token — separate from ADMIN_KEY.
  await db.execute(`
    CREATE TABLE IF NOT EXISTS resellers (
      id          INTEGER PRIMARY KEY AUTOINCREMENT,
      name        TEXT NOT NULL,
      token       TEXT NOT NULL UNIQUE,
      credits     INTEGER NOT NULL DEFAULT 0,
      created_at  TEXT NOT NULL,
      status      TEXT NOT NULL DEFAULT 'active'
    );
  `);

  // Reseller-submitted "please add credits" requests, approved by admin.
  await db.execute(`
    CREATE TABLE IF NOT EXISTS credit_topups (
      id            INTEGER PRIMARY KEY AUTOINCREMENT,
      reseller_id   INTEGER NOT NULL,
      amount        INTEGER NOT NULL,
      note          TEXT,
      status        TEXT NOT NULL DEFAULT 'pending',
      requested_at  TEXT NOT NULL,
      resolved_at   TEXT
    );
  `);

  // Best-effort migration for DBs created before reseller_id existed.
  try {
    await db.execute(`ALTER TABLE licenses ADD COLUMN reseller_id INTEGER`);
  } catch (e) {
    // Already exists — fine.
  }
}

module.exports = { db, init };
