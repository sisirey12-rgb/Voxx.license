const express = require('express');
const bcrypt = require('bcrypt');
const speakeasy = require('speakeasy');
const qrcode = require('qrcode');
const { db } = require('../db');
const adminAuth = require('../middleware/adminAuth');
const { checkLockout, recordAttempt, logAction, getClientIp } = require('../middleware/security');

const router = express.Router();

// POST /admin/login  { username, password, totp_code? }
// On success, returns the shared ADMIN_KEY. The frontend stores it and
// sends it as X-Admin-Key on every subsequent request — same mechanism
// your existing admin routes already use.
router.post('/login', async (req, res) => {
  const { username, password, totp_code } = req.body || {};
  const ip = getClientIp(req);
  const userAgent = req.headers['user-agent'];

  if (!username || !password) {
    return res.status(400).json({ error: 'username_and_password_required' });
  }

  const lock = await checkLockout(username, ip);
  if (lock.locked) {
    return res.status(429).json({
      error: 'locked_out',
      message: `Too many failed attempts. Locked until ${lock.until}.`,
    });
  }

  const rows = await db.execute({
    sql: `SELECT id, password_hash, totp_secret, totp_enabled FROM admin_users WHERE username = ?`,
    args: [username],
  });
  const hits = rows.rows || rows;

  if (hits.length === 0) {
    await recordAttempt(username, ip, false);
    await logAction({ username, action: 'login_fail', ip, userAgent, details: { reason: 'no_such_user' } });
    return res.status(401).json({ error: 'invalid_credentials' });
  }

  const user = hits[0];
  const passwordOk = await bcrypt.compare(password, user.password_hash);

  if (!passwordOk) {
    await recordAttempt(username, ip, false);
    await logAction({ adminId: user.id, username, action: 'login_fail', ip, userAgent, details: { reason: 'bad_password' } });
    return res.status(401).json({ error: 'invalid_credentials' });
  }

  if (user.totp_enabled) {
    if (!totp_code) {
      return res.status(401).json({ error: 'totp_required' });
    }
    const totpOk = speakeasy.totp.verify({
      secret: user.totp_secret,
      encoding: 'base32',
      token: totp_code,
      window: 1,
    });
    if (!totpOk) {
      await recordAttempt(username, ip, false);
      await logAction({ adminId: user.id, username, action: 'login_fail', ip, userAgent, details: { reason: 'bad_totp' } });
      return res.status(401).json({ error: 'invalid_totp' });
    }
  }

  await recordAttempt(username, ip, true);
  await logAction({ adminId: user.id, username, action: 'login_success', ip, userAgent });

  res.json({ ok: true, admin_key: process.env.ADMIN_KEY });
});

// POST /admin/logout — nothing to invalidate server-side (no session state);
// the frontend just clears its stored key. Kept for symmetry / future audit use.
router.post('/logout', adminAuth, async (req, res) => {
  await logAction({ action: 'logout', ip: getClientIp(req), userAgent: req.headers['user-agent'] });
  res.json({ ok: true });
});

// GET /admin/session — frontend calls this on load to check the stored key still works
router.get('/session', adminAuth, (req, res) => {
  res.json({ ok: true });
});

// --- 2FA management. Since there's no per-session identity anymore,
// these take `username` explicitly and are gated by the shared admin key. ---

router.post('/2fa/setup', adminAuth, async (req, res) => {
  const { username } = req.body || {};
  if (!username) return res.status(400).json({ error: 'username_required' });
  const rows = await db.execute({ sql: `SELECT id FROM admin_users WHERE username = ?`, args: [username] });
  const hits = rows.rows || rows;
  if (hits.length === 0) return res.status(404).json({ error: 'no_such_user' });

  const secret = speakeasy.generateSecret({ name: 'VOXX Admin' });
  await db.execute({
    sql: `UPDATE admin_users SET totp_secret = ? WHERE id = ?`,
    args: [secret.base32, hits[0].id],
  });
  const qr = await qrcode.toDataURL(secret.otpauth_url);
  res.json({ qr_code: qr, secret: secret.base32 });
});

router.post('/2fa/verify', adminAuth, async (req, res) => {
  const { username, totp_code } = req.body || {};
  if (!username) return res.status(400).json({ error: 'username_required' });
  const rows = await db.execute({ sql: `SELECT id, totp_secret FROM admin_users WHERE username = ?`, args: [username] });
  const hits = rows.rows || rows;
  if (hits.length === 0 || !hits[0].totp_secret) {
    return res.status(400).json({ error: 'run_2fa_setup_first' });
  }
  const ok = speakeasy.totp.verify({
    secret: hits[0].totp_secret,
    encoding: 'base32',
    token: totp_code,
    window: 1,
  });
  if (!ok) return res.status(401).json({ error: 'invalid_totp' });

  await db.execute({ sql: `UPDATE admin_users SET totp_enabled = 1 WHERE id = ?`, args: [hits[0].id] });
  await logAction({ username, action: '2fa_enabled', ip: getClientIp(req), userAgent: req.headers['user-agent'] });
  res.json({ ok: true });
});

router.post('/2fa/disable', adminAuth, async (req, res) => {
  const { username } = req.body || {};
  if (!username) return res.status(400).json({ error: 'username_required' });
  await db.execute({
    sql: `UPDATE admin_users SET totp_enabled = 0, totp_secret = NULL WHERE username = ?`,
    args: [username],
  });
  await logAction({ username, action: '2fa_disabled', ip: getClientIp(req), userAgent: req.headers['user-agent'] });
  res.json({ ok: true });
});

module.exports = router;
