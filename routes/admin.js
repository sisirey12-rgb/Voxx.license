const express = require('express');
const db = require('../db');
const adminAuth = require('../middleware/adminAuth');
const { generateKeyString, addDaysISO, nowISO, computeStatus } = require('../helpers');

const router = express.Router();
router.use(adminAuth);

// List all keys (console dashboard)
router.get('/keys', (req, res) => {
  const rows = db.prepare('SELECT * FROM licenses ORDER BY created_at DESC').all();
  const withStatus = rows.map(r => ({ ...r, computed_status: computeStatus(r) }));
  res.json({ licenses: withStatus });
});

// Generate a new key
router.post('/generate-key', (req, res) => {
  const { validity_days = 30, max_devices = 1, label = null } = req.body || {};

  if (!Number.isFinite(Number(validity_days)) || Number(validity_days) <= 0) {
    return res.status(400).json({ error: 'validity_days must be a positive number' });
  }
  if (!Number.isFinite(Number(max_devices)) || Number(max_devices) <= 0) {
    return res.status(400).json({ error: 'max_devices must be a positive number' });
  }

  const license_key = generateKeyString();
  const created_at = nowISO();
  const expires_at = addDaysISO(created_at, validity_days);

  db.prepare(`
    INSERT INTO licenses (license_key, device_hwid, label, created_at, expires_at, max_devices, status)
    VALUES (?, NULL, ?, ?, ?, ?, 'active')
  `).run(license_key, label, created_at, expires_at, max_devices);

  res.json({ license_key, created_at, expires_at, max_devices, label, status: 'active' });
});

// Reset HWID — unbinds all devices from this key
router.post('/reset-hwid', (req, res) => {
  const { license_key } = req.body || {};
  if (!license_key) return res.status(400).json({ error: 'license_key required' });

  const lic = db.prepare('SELECT * FROM licenses WHERE license_key = ?').get(license_key);
  if (!lic) return res.status(404).json({ error: 'License not found' });

  db.prepare('UPDATE licenses SET device_hwid = NULL WHERE license_key = ?').run(license_key);
  db.prepare('DELETE FROM license_devices WHERE license_key = ?').run(license_key);

  res.json({ success: true });
});

// Extend validity by N days
router.post('/extend', (req, res) => {
  const { license_key, days } = req.body || {};
  if (!license_key || !days) return res.status(400).json({ error: 'license_key and days required' });

  const lic = db.prepare('SELECT * FROM licenses WHERE license_key = ?').get(license_key);
  if (!lic) return res.status(404).json({ error: 'License not found' });

  const newExpiry = addDaysISO(lic.expires_at, days);
  db.prepare('UPDATE licenses SET expires_at = ? WHERE license_key = ?').run(newExpiry, license_key);

  res.json({ success: true, expires_at: newExpiry });
});

// Regenerate — revoke old key, issue a new one carrying over expiry/limits
router.post('/regenerate', (req, res) => {
  const { license_key } = req.body || {};
  if (!license_key) return res.status(400).json({ error: 'license_key required' });

  const old = db.prepare('SELECT * FROM licenses WHERE license_key = ?').get(license_key);
  if (!old) return res.status(404).json({ error: 'License not found' });

  const newKey = generateKeyString();
  const created_at = nowISO();

  db.prepare(`
    INSERT INTO licenses (license_key, device_hwid, label, created_at, expires_at, max_devices, status)
    VALUES (?, NULL, ?, ?, ?, ?, 'active')
  `).run(newKey, old.label, created_at, old.expires_at, old.max_devices);

  db.prepare(`UPDATE licenses SET status = 'revoked' WHERE license_key = ?`).run(license_key);

  res.json({ success: true, new_license_key: newKey });
});

// Revoke a key
router.post('/revoke', (req, res) => {
  const { license_key } = req.body || {};
  if (!license_key) return res.status(400).json({ error: 'license_key required' });

  const result = db.prepare(`UPDATE licenses SET status = 'revoked' WHERE license_key = ?`).run(license_key);
  if (result.changes === 0) return res.status(404).json({ error: 'License not found' });

  res.json({ success: true });
});

module.exports = router;
