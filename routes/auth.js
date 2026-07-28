const express = require('express');
const bcrypt = require('bcrypt');
const speakeasy = require('speakeasy');
const qrcode = require('qrcode');
const { db } = require('../db');
const { createSession, destroySession, requireSession } = require('../middleware/authSession');
const { checkLockout, recordAttempt, logAction, getClientIp } = require('../middleware/security');

const router = express.Router();

// POST /admin/setup-admin  { admin_key, username, password }
// Bootstraps the first admin account, or resets an existing one's password.
// Replaces the old GET .../setup-admin?key=...&username=...&password=...
// route: that version put the password in the URL itself, which ends up in
// browser history, server access logs, and Render's request logs. This is a
// POST with the values in the body, same as every other route here.
// Gated only by ADMIN_KEY (server env var) since, on first run, no admin
// account exists yet to authenticate a session against.
router.post('/setup-admin', async (req, res) => {
  const { admin_key, username, password } = req.body || {};
  const ip = getClientIp(req);
  const userAgent = req.headers['user-agent'];

  if (!admin_key || admin_key !== process.env.ADMIN_KEY) {
    return res.status(403).json({ error: 'invalid_admin_key' });
  }
  if (!username || !password) {
    return res.status(400).json({ error: 'username_and_password_required' });
  }
  if (password.length < 12) {
    return res.status(400).json({ error: 'password_too_short', message: 'Use at least 12 characters.' });
  }

  const hash = await bcrypt.hash(password, 12);
  await db.execute({
    sql: `INSERT INTO admin_users (username, password_hash)
          VALUES (?, ?)
          ON CONFLICT(username) DO UPDATE SET password_hash = excluded.password_hash`,
    args: [username, hash],
  });

  await logAction({ username, action: 'admin_account_created_or_reset', ip, userAgent });
  res.json({ ok: true, message: `Admin account "${username}" is ready. You can log in now.` });
});

// POST /admin/change-password  { current_password, new_password }
// Requires an active session — proves you're already logged in as the
// account you're changing, and additionally re-checks current_password so
// a hijacked-but-still-live session can't silently lock the real owner out.
router.post('/change-password', requireSession, async (req, res) => {
  const { current_password, new_password } = req.body || {};
  const ip = getClientIp(req);
  const userAgent = req.headers['user-agent'];

  if (!current_password || !new_password) {
    return res.status(400).json({ error: 'current_and_new_password_required' });
  }
  if (new_password.length < 12) {
    return res.status(400).json({ error: 'password_too_short', message: 'Use at least 12 characters.' });
  }

  const rows = await db.execute({ sql: `SELECT username, password_hash FROM admin_users WHERE id = ?`, args: [req.adminId] });
  const hits = rows.rows || rows;
  if (hits.length === 0) return res.status(404).json({ error: 'no_such_user' });

  const ok = await bcrypt.compare(current_password, hits[0].password_hash);
  if (!ok) {
    await logAction({ adminId: req.adminId, username: hits[0].username, action: 'change_password_fail', ip, userAgent });
    return res.status(401).json({ error: 'current_password_incorrect' });
  }

  const newHash = await bcrypt.hash(new_password, 12);
  await db.execute({ sql: `UPDATE admin_users SET password_hash = ? WHERE id = ?`, args: [newHash, req.adminId] });
  await logAction({ adminId: req.adminId, username: hits[0].username, action: 'change_password_success', ip, userAgent });

  res.json({ ok: true });
});

// POST /admin/login  { username, password, totp_code? }
// ADMIN_KEY is no longer part of login — it's only ever used, separately,
// by POST /setup-admin below to bootstrap or reset an account. On success
// this issues a real session token (see authSession.js), not a static key.
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
