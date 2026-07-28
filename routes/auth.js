const express = require('express');
const bcrypt = require('bcrypt');
const speakeasy = require('speakeasy');
const qrcode = require('qrcode');
const { db } = require('../db');
const { createSession, destroySession, requireSession } = require('../middleware/authSession');
const { checkLockout, recordAttempt, logAction, getClientIp } = require('../middleware/security');

const router = express.Router();

// POST /admin/login  { username, password, totp_code? }
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
      // Password was right, but 2FA is required — don't count this as a failure yet.
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
  const sessionId = await createSession(user.id, ip, userAgent);
  await logAction({ adminId: user.id, username, action: 'login_success', ip, userAgent });

  // Token goes in the JSON body, not a cookie — the frontend stores it and
  // sends it back as `Authorization: Bearer <token>` on every request.
  res.json({ ok: true, session_token: sessionId });
});

// POST /admin/logout
router.post('/logout', requireSession, async (req, res) => {
  const ip = getClientIp(req);
  await destroySession(req.sessionId);
  await logAction({ adminId: req.adminId, action: 'logout', ip, userAgent: req.headers['user-agent'] });
  res.json({ ok: true });
});

// GET /admin/session — frontend calls this on load to check if still logged in
router.get('/session', requireSession, (req, res) => {
  res.json({ ok: true });
});

// POST /admin/2fa/setup — generates a secret + QR code, does NOT enable 2FA yet
router.post('/2fa/setup', requireSession, async (req, res) => {
  const secret = speakeasy.generateSecret({ name: 'VOXX Admin' });
  await db.execute({
    sql: `UPDATE admin_users SET totp_secret = ? WHERE id = ?`,
    args: [secret.base32, req.adminId],
  });
  const qr = await qrcode.toDataURL(secret.otpauth_url);
  res.json({ qr_code: qr, secret: secret.base32 });
});

// POST /admin/2fa/verify  { totp_code } — confirms the code works, then enables 2FA
router.post('/2fa/verify', requireSession, async (req, res) => {
  const { totp_code } = req.body || {};
  const rows = await db.execute({
    sql: `SELECT totp_secret FROM admin_users WHERE id = ?`,
    args: [req.adminId],
  });
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

  await db.execute({ sql: `UPDATE admin_users SET totp_enabled = 1 WHERE id = ?`, args: [req.adminId] });
  await logAction({ adminId: req.adminId, action: '2fa_enabled', ip: getClientIp(req), userAgent: req.headers['user-agent'] });
  res.json({ ok: true });
});

// POST /admin/2fa/disable
router.post('/2fa/disable', requireSession, async (req, res) => {
  await db.execute({
    sql: `UPDATE admin_users SET totp_enabled = 0, totp_secret = NULL WHERE id = ?`,
    args: [req.adminId],
  });
  await logAction({ adminId: req.adminId, action: '2fa_disabled', ip: getClientIp(req), userAgent: req.headers['user-agent'] });
  res.json({ ok: true });
});

module.exports = router;
