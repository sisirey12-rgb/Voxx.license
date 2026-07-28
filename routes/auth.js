const express = require('express');
const bcrypt = require('bcrypt');
const speakeasy = require('speakeasy');
const qrcode = require('qrcode');
const { db } = require('../db');
const { createSession, destroySession, requireSession } = require('../middleware/authSession');
const { checkLockout, recordAttempt, logAction, getClientIp } = require('../middleware/security');

const router = express.Router();

// POST /admin/login  { username, password, totp_code? }
// On success, returns the shared ADMIN_KEY. The frontend stores it and
// sends it as X-Admin-Key on every subsequent request — same mechanism
// your existing admin routes already use.
router.post('/login', async (req, res) => {
  const { username, password, admin_key, totp_code } = req.body || {};
  const ip = getClientIp(req);
  const userAgent = req.headers['user-agent'];

  if (!username || !password || !admin_key) {
    return res.status(400).json({ error: 'username_password_and_admin_key_required' });
  }

  // Second, independent secret — must match exactly, regardless of username/password.
  if (admin_key !== process.env.ADMIN_KEY) {
    await logAction({ username, action: 'login_fail', ip, userAgent, details: { reason: 'bad_admin_key' } });
    return res.status(401).json({ error: 'invalid_admin_key' });
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

  // Issue a short-lived, revocable session token instead of handing back the
  // static ADMIN_KEY. The browser never sees ADMIN_KEY after this point —
  // it only holds this token, which expires in 15 minutes of inactivity and
  // can be individually revoked (unlike the shared key).
  const token = await createSession(user.id, ip, userAgent);
  res.json({ ok: true, token, expires_in_minutes: 15 });
});

// POST /admin/logout — deletes the session row server-side, so this exact
// token stops working immediately (not just when it naturally expires).
router.post('/logout', requireSession, async (req, res) => {
  await destroySession(req.sessionId);
  await logAction({ adminId: req.adminId, action: 'logout', ip: getClientIp(req), userAgent: req.headers['user-agent'] });
  res.json({ ok: true });
});

// GET /admin/session — frontend calls this on load to check the stored token
// is still valid. requireSession also slides the expiry forward on success.
router.get('/session', requireSession, (req, res) => {
  res.json({ ok: true });
});

// --- 2FA management. Now identity comes from the verified session
// (req.adminId), not a username the caller types in — so a session for
// admin A can never be used to set up or disable 2FA on admin B. ---

router.post('/2fa/setup', requireSession, async (req, res) => {
  const secret = speakeasy.generateSecret({ name: 'VOXX Admin' });
  await db.execute({
    sql: `UPDATE admin_users SET totp_secret = ? WHERE id = ?`,
    args: [secret.base32, req.adminId],
  });
  const qr = await qrcode.toDataURL(secret.otpauth_url);
  res.json({ qr_code: qr, secret: secret.base32 });
});

router.post('/2fa/verify', requireSession, async (req, res) => {
  const { totp_code } = req.body || {};
  const rows = await db.execute({ sql: `SELECT totp_secret FROM admin_users WHERE id = ?`, args: [req.adminId] });
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

router.post('/2fa/disable', requireSession, async (req, res) => {
  await db.execute({
    sql: `UPDATE admin_users SET totp_enabled = 0, totp_secret = NULL WHERE id = ?`,
    args: [req.adminId],
  });
  await logAction({ adminId: req.adminId, action: '2fa_disabled', ip: getClientIp(req), userAgent: req.headers['user-agent'] });
  res.json({ ok: true });
});

module.exports = router;
