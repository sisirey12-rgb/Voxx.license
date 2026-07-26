const express = require('express');
const { db } = require('../db');
const adminAuth = require('../middleware/adminAuth');
const { generateKeyString, addDaysISO, nowISO, computeStatus } = require('../helpers');

const router = express.Router();
router.use(adminAuth);

// List all keys (console dashboard)
router.get('/keys', async (req, res) => {
  const result = await db.execute('SELECT * FROM licenses ORDER BY created_at DESC');
  const withStatus = result.rows.map(r => ({ ...r, computed_status: computeStatus(r) }));
  res.json({ licenses: withStatus });
});

// Generate a new key
router.post('/generate-key', async (req, res) => {
  const { validity_days = 30, max_devices = 1, label = null, custom_key, license_key: legacyKey } = req.body || {};
  const customKey = (custom_key || legacyKey || '').trim() || null;

  if (!Number.isFinite(Number(validity_days)) || Number(validity_days) <= 0) {
    return res.status(400).json({ error: 'validity_days must be a positive number' });
  }
  if (!Number.isFinite(Number(max_devices)) || Number(max_devices) <= 0) {
    return res.status(400).json({ error: 'max_devices must be a positive number' });
  }

  if (customKey) {
    const existing = await db.execute({
      sql: 'SELECT 1 FROM licenses WHERE license_key = ?',
      args: [customKey],
    });
    if (existing.rows.length > 0) {
      return res.status(409).json({ error: 'license_key already exists' });
    }
  }

  const license_key = customKey || generateKeyString();
  const created_at = nowISO();
  const expires_at = addDaysISO(created_at, validity_days);

  await db.execute({
    sql: `
      INSERT INTO licenses (license_key, device_hwid, label, created_at, expires_at, max_devices, status)
      VALUES (?, NULL, ?, ?, ?, ?, 'active')
    `,
    args: [license_key, label, created_at, expires_at, max_devices],
  });

  res.json({ license_key, created_at, expires_at, max_devices, label, status: 'active' });
});

// Reset HWID — frees the key up to be activated on a new device
router.post('/reset-hwid', async (req, res) => {
  const { license_key } = req.body || {};
  if (!license_key) return res.status(400).json({ error: 'license_key required' });

  const result = await db.execute({
    sql: 'SELECT * FROM licenses WHERE license_key = ?',
    args: [license_key],
  });
  const lic = result.rows[0];
  if (!lic) return res.status(404).json({ error: 'license_key not found' });

  await db.execute({ sql: 'UPDATE licenses SET device_hwid = NULL WHERE license_key = ?', args: [license_key] });
  await db.execute({ sql: 'DELETE FROM license_devices WHERE license_key = ?', args: [license_key] });

  res.json({ success: true });
});

// Extend expiry by N days
router.post('/extend', async (req, res) => {
  const { license_key, days } = req.body || {};
  if (!license_key || !days) return res.status(400).json({ error: 'license_key and days required' });

  const result = await db.execute({
    sql: 'SELECT * FROM licenses WHERE license_key = ?',
    args: [license_key],
  });
  const lic = result.rows[0];
  if (!lic) return res.status(404).json({ error: 'license_key not found' });

  const newExpiry = addDaysISO(lic.expires_at, days);
  await db.execute({ sql: 'UPDATE licenses SET expires_at = ? WHERE license_key = ?', args: [newExpiry, license_key] });

  res.json({ success: true, expires_at: newExpiry });
});

// Regenerate — swaps in a new key string on the same entry (keeps expiry, label, device limit)
router.post('/regenerate', async (req, res) => {
  const { license_key } = req.body || {};
  if (!license_key) return res.status(400).json({ error: 'license_key required' });

  const oldResult = await db.execute({
    sql: 'SELECT * FROM licenses WHERE license_key = ?',
    args: [license_key],
  });
  const old = oldResult.rows[0];
  if (!old) return res.status(404).json({ error: 'license_key not found' });

  const newKey = generateKeyString();

  // Update the same row's key in place — no duplicate/orphaned entry left behind.
  await db.execute({
    sql: 'UPDATE licenses SET license_key = ? WHERE license_key = ?',
    args: [newKey, license_key],
  });
  // Keep any bound-device history pointed at the new key string.
  await db.execute({
    sql: 'UPDATE license_devices SET license_key = ? WHERE license_key = ?',
    args: [newKey, license_key],
  });

  res.json({ success: true, new_license_key: newKey });
});

// Revoke a key
router.post('/revoke', async (req, res) => {
  const { license_key } = req.body || {};
  if (!license_key) return res.status(400).json({ error: 'license_key required' });

  const result = await db.execute({
    sql: `UPDATE licenses SET status = 'revoked' WHERE license_key = ?`,
    args: [license_key],
  });
  if (result.rowsAffected === 0) return res.status(404).json({ error: 'license_key not found' });

  res.json({ success: true });
});

// Permanently delete one key (and its device-binding history)
router.post('/delete-key', async (req, res) => {
  const { license_key } = req.body || {};
  if (!license_key) return res.status(400).json({ error: 'license_key required' });

  await db.execute({ sql: 'DELETE FROM license_devices WHERE license_key = ?', args: [license_key] });
  const result = await db.execute({ sql: 'DELETE FROM licenses WHERE license_key = ?', args: [license_key] });
  if (result.rowsAffected === 0) return res.status(404).json({ error: 'license_key not found' });

  res.json({ success: true });
});

// Permanently delete every revoked key (leaves active/expiring/expired keys alone)
router.post('/delete-revoked', async (req, res) => {
  await db.execute(`
    DELETE FROM license_devices WHERE license_key IN (
      SELECT license_key FROM licenses WHERE status = 'revoked'
    )
  `);
  const result = await db.execute(`DELETE FROM licenses WHERE status = 'revoked'`);

  res.json({ success: true, deleted: result.rowsAffected });
});

module.exports = router;
