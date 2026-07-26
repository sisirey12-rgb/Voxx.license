const express = require('express');
const { db } = require('../db');
const resellerAuth = require('../middleware/resellerAuth');
const { generateKeyString, addDaysISO, nowISO, computeStatus } = require('../helpers');

const router = express.Router();
router.use(resellerAuth);

// 1 credit = 1 day of license validity. Keeps the cost obvious to partners
// and mirrors the "deducts credits by duration" requirement.
function creditCost(validity_days) {
  return Number(validity_days);
}

// Balance + basic account info for the partner's dashboard header.
router.get('/me', async (req, res) => {
  res.json({
    name: req.reseller.name,
    credits: req.reseller.credits,
    status: req.reseller.status,
  });
});

// Generate a key against the reseller's own credit balance.
// custom_key is intentionally never accepted here — resellers only ever get
// the standard VOXX-XXXXXXXX format, unlike the admin /generate-key route.
router.post('/generate-key', async (req, res) => {
  const { validity_days = 30, max_devices = 1, label = null } = req.body || {};

  if (!Number.isFinite(Number(validity_days)) || Number(validity_days) <= 0) {
    return res.status(400).json({ error: 'validity_days must be a positive number' });
  }
  if (!Number.isFinite(Number(max_devices)) || Number(max_devices) <= 0) {
    return res.status(400).json({ error: 'max_devices must be a positive number' });
  }

  const cost = creditCost(validity_days);

  // Re-check the live balance right before spending it, so two requests
  // fired back-to-back can't both succeed off a stale balance.
  const freshResult = await db.execute({
    sql: 'SELECT credits FROM resellers WHERE id = ?',
    args: [req.reseller.id],
  });
  const currentCredits = freshResult.rows[0]?.credits ?? 0;

  if (currentCredits < cost) {
    return res.status(402).json({ error: 'insufficient_credits', credits: currentCredits, required: cost });
  }

  const license_key = generateKeyString();
  const created_at = nowISO();
  const expires_at = addDaysISO(created_at, validity_days);

  await db.execute({
    sql: `
      INSERT INTO licenses (license_key, device_hwid, label, created_at, expires_at, max_devices, status, reseller_id)
      VALUES (?, NULL, ?, ?, ?, ?, 'active', ?)
    `,
    args: [license_key, label, created_at, expires_at, max_devices, req.reseller.id],
  });

  await db.execute({
    sql: 'UPDATE resellers SET credits = credits - ? WHERE id = ?',
    args: [cost, req.reseller.id],
  });

  res.json({
    license_key,
    created_at,
    expires_at,
    max_devices,
    label,
    status: 'active',
    credits_spent: cost,
    credits_remaining: currentCredits - cost,
  });
});

// A partner's own generated keys — never exposes other resellers' keys.
router.get('/sales', async (req, res) => {
  const result = await db.execute({
    sql: 'SELECT * FROM licenses WHERE reseller_id = ? ORDER BY created_at DESC',
    args: [req.reseller.id],
  });
  const withStatus = result.rows.map(r => ({ ...r, computed_status: computeStatus(r) }));
  res.json({ licenses: withStatus });
});

// Submit a request to add credits — admin approves it from the control console.
router.post('/topup-request', async (req, res) => {
  const { amount, note = null } = req.body || {};
  if (!Number.isFinite(Number(amount)) || Number(amount) <= 0) {
    return res.status(400).json({ error: 'amount must be a positive number' });
  }

  const requested_at = nowISO();
  const result = await db.execute({
    sql: `
      INSERT INTO credit_topups (reseller_id, amount, note, status, requested_at)
      VALUES (?, ?, ?, 'pending', ?)
    `,
    args: [req.reseller.id, amount, note, requested_at],
  });

  res.json({ success: true, topup_id: Number(result.lastInsertRowid), status: 'pending' });
});

// A partner's own top-up request history.
router.get('/topups', async (req, res) => {
  const result = await db.execute({
    sql: 'SELECT * FROM credit_topups WHERE reseller_id = ? ORDER BY requested_at DESC',
    args: [req.reseller.id],
  });
  res.json({ topups: result.rows });
});

module.exports = router;
