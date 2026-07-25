const express = require('express');
const db = require('../db');
const { computeStatus, daysLeft, nowISO } = require('../helpers');

const router = express.Router();

// Called once from the app's activation screen when the user enters a key.
router.post('/activate', (req, res) => {
  const { license_key, hwid } = req.body || {};
  if (!license_key || !hwid) {
    return res.status(400).json({ success: false, reason: 'license_key and hwid required' });
  }

  const lic = db.prepare('SELECT * FROM licenses WHERE license_key = ?').get(license_key);
  if (!lic) return res.status(404).json({ success: false, reason: 'invalid_key' });

  const status = computeStatus(lic);
  if (status === 'revoked') return res.status(403).json({ success: false, reason: 'revoked' });
  if (status === 'expired') return res.status(403).json({ success: false, reason: 'expired' });

  const boundDevices = db.prepare('SELECT hwid FROM license_devices WHERE license_key = ?').all(license_key);
  const alreadyBound = boundDevices.some(d => d.hwid === hwid);

  if (alreadyBound) {
    return res.json({ success: true, expires_at: lic.expires_at, days_left: daysLeft(lic.expires_at) });
  }

  if (boundDevices.length >= lic.max_devices) {
    return res.status(403).json({ success: false, reason: 'device_limit_reached' });
  }

  db.prepare('INSERT INTO license_devices (license_key, hwid, bound_at) VALUES (?, ?, ?)')
    .run(license_key, hwid, nowISO());

  // Keep device_hwid column populated with the most recent bind, useful for
  // single-device (max_devices=1) keys and for the admin console display.
  db.prepare('UPDATE licenses SET device_hwid = ? WHERE license_key = ?').run(hwid, license_key);

  res.json({ success: true, expires_at: lic.expires_at, days_left: daysLeft(lic.expires_at) });
});

// Called on every app launch to confirm the key is still good.
router.post('/validate', (req, res) => {
  const { license_key, hwid } = req.body || {};
  if (!license_key || !hwid) {
    return res.json({ valid: false, reason: 'license_key and hwid required' });
  }

  const lic = db.prepare('SELECT * FROM licenses WHERE license_key = ?').get(license_key);
  if (!lic) return res.json({ valid: false, reason: 'invalid_key' });

  const status = computeStatus(lic);
  if (status === 'revoked') return res.json({ valid: false, reason: 'revoked' });
  if (status === 'expired') return res.json({ valid: false, reason: 'expired' });

  const bound = db.prepare('SELECT 1 FROM license_devices WHERE license_key = ? AND hwid = ?').get(license_key, hwid);
  if (!bound) return res.json({ valid: false, reason: 'device_not_bound' });

  res.json({ valid: true, expires_at: lic.expires_at, days_left: daysLeft(lic.expires_at) });
});

module.exports = router;
