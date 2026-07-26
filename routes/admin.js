const express = require('express');
const { db } = require('../db');
const adminAuth = require('../middleware/adminAuth');
const { generateKeyString, generateResellerToken, addDaysISO, nowISO, computeStatus } = require('../helpers');

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

// ---- Reseller management ----

// List all resellers, most recently created first — includes each
// reseller's total keys sold, currently-active keys, and days since they
// were created (the console uses these for the sales-count/rate display).
router.get('/resellers', async (req, res) => {
  const resellersResult = await db.execute('SELECT id, name, credits, status, created_at FROM resellers ORDER BY created_at DESC');
  const licensesResult = await db.execute('SELECT reseller_id, status, expires_at FROM licenses WHERE reseller_id IS NOT NULL');

  const counts = {};
  for (const l of licensesResult.rows) {
    const rid = l.reseller_id;
    if (!counts[rid]) counts[rid] = { total: 0, active: 0 };
    counts[rid].total += 1;
    const st = computeStatus(l);
    if (st === 'active' || st === 'expiring') counts[rid].active += 1;
  }

  const resellers = resellersResult.rows.map(r => {
    const c = counts[r.id] || { total: 0, active: 0 };
    const daysActive = Math.max(1, Math.ceil((Date.now() - new Date(r.created_at)) / 86400000));
    return {
      ...r,
      total_sales: c.total,
      active_sales: c.active,
      sales_per_day: Number((c.total / daysActive).toFixed(2)),
    };
  });

  res.json({ resellers });
});

// Create a new reseller and hand back their token once — store it safely,
// it's the only time the full token is returned.
router.post('/resellers', async (req, res) => {
  const { name, initial_credits = 0 } = req.body || {};
  if (!name || !name.trim()) return res.status(400).json({ error: 'name required' });
  if (!Number.isFinite(Number(initial_credits)) || Number(initial_credits) < 0) {
    return res.status(400).json({ error: 'initial_credits must be zero or a positive number' });
  }

  const token = generateResellerToken();
  const created_at = nowISO();

  const result = await db.execute({
    sql: `INSERT INTO resellers (name, token, credits, created_at, status) VALUES (?, ?, ?, ?, 'active')`,
    args: [name.trim(), token, initial_credits, created_at],
  });

  res.json({ id: Number(result.lastInsertRowid), name: name.trim(), token, credits: initial_credits, status: 'active' });
});

// Directly adjust a reseller's balance (grant or correct, bypassing the top-up flow).
router.post('/resellers/:id/adjust-credits', async (req, res) => {
  const { id } = req.params;
  const { delta } = req.body || {};
  if (!Number.isFinite(Number(delta)) || Number(delta) === 0) {
    return res.status(400).json({ error: 'delta must be a non-zero number' });
  }

  const result = await db.execute({ sql: 'UPDATE resellers SET credits = credits + ? WHERE id = ?', args: [delta, id] });
  if (result.rowsAffected === 0) return res.status(404).json({ error: 'reseller not found' });

  const updated = await db.execute({ sql: 'SELECT credits FROM resellers WHERE id = ?', args: [id] });
  res.json({ success: true, credits: updated.rows[0]?.credits });
});

// Suspend/reactivate a reseller (suspended tokens are rejected by resellerAuth).
router.post('/resellers/:id/set-status', async (req, res) => {
  const { id } = req.params;
  const { status } = req.body || {};
  if (!['active', 'suspended'].includes(status)) {
    return res.status(400).json({ error: "status must be 'active' or 'suspended'" });
  }

  const result = await db.execute({ sql: 'UPDATE resellers SET status = ? WHERE id = ?', args: [status, id] });
  if (result.rowsAffected === 0) return res.status(404).json({ error: 'reseller not found' });

  res.json({ success: true });
});

// A reseller's key-generation history (admin view — any reseller_id).
router.get('/resellers/:id/sales', async (req, res) => {
  const { id } = req.params;
  const result = await db.execute({
    sql: 'SELECT * FROM licenses WHERE reseller_id = ? ORDER BY created_at DESC',
    args: [id],
  });
  const withStatus = result.rows.map(r => ({ ...r, computed_status: computeStatus(r) }));
  res.json({ licenses: withStatus });
});

// ---- Credit top-up requests ----

// List top-up requests, optionally filtered by status (?status=pending).
router.get('/topups', async (req, res) => {
  const { status } = req.query;
  const sql = status
    ? 'SELECT t.*, r.name AS reseller_name FROM credit_topups t JOIN resellers r ON r.id = t.reseller_id WHERE t.status = ? ORDER BY t.requested_at DESC'
    : 'SELECT t.*, r.name AS reseller_name FROM credit_topups t JOIN resellers r ON r.id = t.reseller_id ORDER BY t.requested_at DESC';
  const result = await db.execute(status ? { sql, args: [status] } : sql);
  res.json({ topups: result.rows });
});

// Approve a pending top-up — credits the reseller and marks it resolved.
router.post('/topups/:id/approve', async (req, res) => {
  const { id } = req.params;

  const topupResult = await db.execute({ sql: 'SELECT * FROM credit_topups WHERE id = ?', args: [id] });
  const topup = topupResult.rows[0];
  if (!topup) return res.status(404).json({ error: 'topup not found' });
  if (topup.status !== 'pending') return res.status(409).json({ error: `topup already ${topup.status}` });

  await db.execute({ sql: 'UPDATE resellers SET credits = credits + ? WHERE id = ?', args: [topup.amount, topup.reseller_id] });
  await db.execute({
    sql: `UPDATE credit_topups SET status = 'approved', resolved_at = ? WHERE id = ?`,
    args: [nowISO(), id],
  });

  res.json({ success: true });
});

// Reject a pending top-up — no credits change.
router.post('/topups/:id/reject', async (req, res) => {
  const { id } = req.params;

  const topupResult = await db.execute({ sql: 'SELECT * FROM credit_topups WHERE id = ?', args: [id] });
  const topup = topupResult.rows[0];
  if (!topup) return res.status(404).json({ error: 'topup not found' });
  if (topup.status !== 'pending') return res.status(409).json({ error: `topup already ${topup.status}` });

  await db.execute({
    sql: `UPDATE credit_topups SET status = 'rejected', resolved_at = ? WHERE id = ?`,
    args: [nowISO(), id],
  });

  res.json({ success: true });
});

module.exports = router;
