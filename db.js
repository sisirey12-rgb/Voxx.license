const Database = require('better-sqlite3');
const path = require('path');

// SQLite file lives alongside the server. On most hosts (Render, Railway, Fly)
// attach a persistent volume at this path in production, or swap this file
// for a Postgres connection later if you need multiple server instances.
const db = new Database(path.join(__dirname, 'licenses.db'));

db.pragma('journal_mode = WAL');

db.exec(`
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
db.exec(`
  CREATE TABLE IF NOT EXISTS license_devices (
    license_key TEXT NOT NULL,
    hwid        TEXT NOT NULL,
    bound_at    TEXT NOT NULL,
    PRIMARY KEY (license_key, hwid)
  );
`);

module.exports = db;
