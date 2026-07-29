const express = require('express');
const { db } = require('../db');
const resellerAuth = require('../middleware/resellerAuth');
const { generateKeyString, addDaysISO, nowISO, computeStatus, asyncHandler } = require('../helpers');

const router = express.Router();
router.use(resellerAuth);

const CREDIT_TIERS = {
  1: 0.5,
  3: 1.0,
  7: 2.0,
  15: 3.5,
  30: 6.0,
};

function creditCost(validity_days) {
  return CREDIT_TIERS[Number(validity_days)];
}

router.get('/me', asyncHandler(async (req, res) => {
  res.json({
    name: req.reseller.name,
    credits: req.reseller.credits,
    status: req.reseller.status,
  });
}));

router.get('/pricing', asyncHandler(async (req, res) => {
  res.json({ tiers: CREDIT_TIERS });
}));

router.post('/generate-key', asyncHandler(async (req, res) => {
  const { validity_days = 30, max_devices = 1, label = null } = req.body || {};

  const cost = creditCost(validity_days);
  if (cost === undefined) {
    return res.status(400).json({
      error: 'invalid_validity_days',
      message: 'validity_days must be one of the standard key durations',
      allowed_days: Object.keys(CREDIT_TIERS).map(Number),
    });
  }
  if (!Number.isFinite(Number(max_devices)) || Number(max_devices) <= 0) {
    return res.status(400).json({ error: 'max_devices must be a positive number' });
  }

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
}));

router.get('/sales', asyncHandler(async (req, res) => {
  const result = await db.execute({
    sql: 'SELECT * FROM licenses WHERE reseller_id = ? ORDER BY created_at DESC',
    args: [req.reseller.id],
  });
  const withStatus = result.rows.map(r => ({ ...r, computed_status: computeStatus(r) }));
  res.json({ licenses: withStatus });
}));

router.post('/topup-request', asyncHandler(async (req, res) => {
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
}));

router.get('/topups', asyncHandler(async (req, res) => {
  const result = await db.execute({
    sql: 'SELECT * FROM credit_topups WHERE reseller_id = ? ORDER BY requested_at DESC',
    args: [req.reseller.id],
  });
  res.json({ topups: result.rows });
}));

module.exports = router;
