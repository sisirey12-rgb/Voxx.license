const express = require('express');
const bcrypt = require('bcrypt');
const speakeasy = require('speakeasy');
const qrcode = require('qrcode');
const { db } = require('../db');
const { createSession, destroySession, requireSession } = require('../middleware/authSession');
const { checkLockout, recordAttempt, logAction, getClientIp } = require('../middleware/security');

const router = express.Router();

// POST /admin/setup-admin  { admin_key, username, password }
// This is now the ONE path for creating an account OR replacing its
// credentials — used both before you're logged in (bootstrap) and from
// inside the console (credential reset). There is no "enter your current
// password to change it" flow anymore: current_password isn't a strong
// gate (anyone with a live/stolen session already has it implicitly, since
// they're already past login) and it's one more thing that can be phished.
// ADMIN_KEY is the one root secret that actually proves you're the owner —
// so it's the one thing that can rewrite credentials.
//
// Replaces the old GET .../setup-admin?key=...&username=...&password=...
// route: that put the password in the URL, which ends up in browser
// history, server access logs, and Render's request logs. This is a POST
// with everything in the body, same as every other route here.
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

  // Whatever the old credentials were, they're gone now — kill every
  // outstanding session for this account so a stolen/old token (or a
  // browser you forgot was still logged in) stops working immediately,
  // not just whenever it happens to expire.
  const rows = await db.execute({ sql: `SELECT id FROM admin_users WHERE username = ?`, args: [username] });
  const hits = rows.rows || rows;
  let revoked = 0;
  if (hits.length > 0) {
    const result = await db.execute({ sql: `DELETE FROM sessions WHERE admin_id = ?`, args: [hits[0].id] });
    revoked = result.rowsAffected || 0;
  }

  await logAction({ username, action: 'admin_credentials_reset', ip, userAgent, details: { sessions_revoked: revoked } });
  res.json({ ok: true, message: `Admin account "${username}" is ready. Every previous session was signed out — log in again.`, sessions_revoked: revoked });
});

// POST /admin/logout-all  — kills every OTHER session for the currently
// signed-in account (keeps the one making this request alive). Use this
// when you suspect a device you're not holding right now is still logged
// in, without wanting to reset your password or sign yourself out too.
router.post('/logout-all', requireSession, async (req, res) => {
  const result = await db.execute({
    sql: `DELETE FROM sessions WHERE admin_id = ? AND id != ?`,
    args: [req.adminId, req.sessionId],
  });
  await logAction({ adminId: req.adminId, action: 'logout_all_other_sessions', ip: getClientIp(req), userAgent: req.headers['user-agent'], details: { sessions_revoked: result.rowsAffected } });
  res.json({ ok: true, sessions_revoked: result.rowsAffected || 0 });
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
