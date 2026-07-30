const express = require('express');
const { db } = require('../db');
const { computeStatus, daysLeft, nowISO } = require('../helpers');

const router = express.Router();
console.log("========== ACTIVATE ==========");
console.log("Headers:", req.headers);
console.log("Body:", req.body);
// Called once from the app's activation screen when the user enters a key.
router.post('/activate', async (req, res) => {
  const { license_key, hwid } = req.body || {};
  if (!license_key || !hwid) {
    return res.status(400).json({ success: false, reason: 'license_key and hwid required' });
  }

  const licResult = await db.execute({
    sql: 'SELECT * FROM licenses WHERE license_key = ?',
    args: [license_key],
  });
  const lic = licResult.rows[0];
  if (!lic) return res.status(404).json({ success: false, reason: 'invalid_key' });

  const status = computeStatus(lic);
  if (status === 'revoked') return res.status(403).json({ success: false, reason: 'revoked' });
  if (status === 'expired') return res.status(403).json({ success: false, reason: 'expired' });

  const boundResult = await db.execute({
    sql: 'SELECT hwid FROM license_devices WHERE license_key = ?',
    args: [license_key],
  });
  const boundDevices = boundResult.rows;
  const alreadyBound = boundDevices.some(d => d.hwid === hwid);

  if (alreadyBound) {
    return res.json({ success: true, expires_at: lic.expires_at, days_left: daysLeft(lic.expires_at) });
  }

  if (boundDevices.length >= lic.max_devices) {
    return res.status(403).json({ success: false, reason: 'device_limit_reached' });
  }

  await db.execute({
    sql: 'INSERT INTO license_devices (license_key, hwid, bound_at) VALUES (?, ?, ?)',
    args: [license_key, hwid, nowISO()],
  });

  // Keep device_hwid column populated with the most recent bind, useful for
  // single-device (max_devices=1) keys and for the admin console display.
  await db.execute({
    sql: 'UPDATE licenses SET device_hwid = ? WHERE license_key = ?',
    args: [hwid, license_key],
  });

  res.json({ success: true, expires_at: lic.expires_at, days_left: daysLeft(lic.expires_at) });
});

// Called on every app launch to confirm the key is still good.
router.post('/validate', async (req, res) => {
  const { license_key, hwid } = req.body || {};
  if (!license_key || !hwid) {
    return res.json({ valid: false, reason: 'license_key and hwid required' });
  }

  const licResult = await db.execute({
    sql: 'SELECT * FROM licenses WHERE license_key = ?',
    args: [license_key],
  });
  const lic = licResult.rows[0];
  if (!lic) return res.json({ valid: false, reason: 'invalid_key' });

  const status = computeStatus(lic);
  if (status === 'revoked') return res.json({ valid: false, reason: 'revoked' });
  if (status === 'expired') return res.json({ valid: false, reason: 'expired' });

  const boundResult = await db.execute({
    sql: 'SELECT 1 FROM license_devices WHERE license_key = ? AND hwid = ?',
    args: [license_key, hwid],
  });
  if (boundResult.rows.length === 0) return res.json({ valid: false, reason: 'device_not_bound' });

  res.json({ valid: true, expires_at: lic.expires_at, days_left: daysLeft(lic.expires_at) });
});

// Public status check — no hwid required, and never reveals any device IDs.
router.post('/status', async (req, res) => {
  const { license_key } = req.body || {};
  if (!license_key) return res.json({ valid: false, reason: 'license_key_required' });

  const licResult = await db.execute({
    sql: 'SELECT * FROM licenses WHERE license_key = ?',
    args: [license_key],
  });
  const lic = licResult.rows[0];
  if (!lic) return res.json({ valid: false, reason: 'invalid_key' });

  const status = computeStatus(lic);
  if (status === 'revoked') return res.json({ valid: false, reason: 'revoked' });
  if (status === 'expired') return res.json({ valid: false, reason: 'expired', expires_at: lic.expires_at });

  const boundResult = await db.execute({
    sql: 'SELECT COUNT(*) as count FROM license_devices WHERE license_key = ?',
    args: [license_key],
  });
  const boundCount = Number(boundResult.rows[0]?.count || 0);

  res.json({
    valid: true,
    bound: boundCount > 0,
    expires_at: lic.expires_at,
    days_left: daysLeft(lic.expires_at),
  });
});

module.exports = router;
