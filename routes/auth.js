const express = require('express');
const bcrypt = require('bcrypt');
const speakeasy = require('speakeasy');
const qrcode = require('qrcode');
const { db } = require('../db');
const { createSession, destroySession, requireSession, markSessionVerified } = require('../middleware/authSession');
const { checkLockout, recordAttempt, logAction, getClientIp, toIST } = require('../middleware/security');
const { sendTelegram } = require('../utils/telegram');

const router = express.Router();

router.post('/setup-admin', async (req, res) => {
  try {
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

    const rows = await db.execute({ sql: `SELECT id FROM admin_users WHERE username = ?`, args: [username] });
    const hits = rows.rows || rows;
    let revoked = 0;
    if (hits.length > 0) {
      const result = await db.execute({ sql: `DELETE FROM sessions WHERE admin_id = ?`, args: [hits[0].id] });
      revoked = result.rowsAffected || 0;
    }

    await logAction({ username, action: 'admin_credentials_reset', ip, userAgent, details: { sessions_revoked: revoked } });
    res.json({ ok: true, message: `Admin account "${username}" is ready. Every previous session was signed out — log in again.`, sessions_revoked: revoked });
  } catch (e) {
    console.error('/setup-admin error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: 'server_error' });
  }
});

router.post('/logout-all', requireSession, async (req, res) => {
  try {
    const result = await db.execute({
      sql: `DELETE FROM sessions WHERE admin_id = ? AND id != ?`,
      args: [req.adminId, req.sessionId],
    });
    await logAction({ adminId: req.adminId, action: 'logout_all_other_sessions', ip: getClientIp(req), userAgent: req.headers['user-agent'], details: { sessions_revoked: result.rowsAffected } });
    res.json({ ok: true, sessions_revoked: result.rowsAffected || 0 });
  } catch (e) {
    console.error('/logout-all error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: 'server_error' });
  }
});

// POST /admin/login  { username, password }
// TOTP is intentionally NOT checked here anymore. Username+password is
// enough to open the dashboard shell; if the account has 2FA on, the
// session is created with totp_verified=0 and every real action
// (routes/admin.js) is blocked by requireVerified until the code is
// entered inside the dashboard via POST /admin/2fa/verify-login. This
// keeps the login screen itself to one gate, and moves the second factor
// to where the account's actual actions live.
router.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body || {};
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
      await sendTelegram(
`❌ YORVOXX INVALID LOGIN ATTEMPT

Username: ${username}
IP: ${ip}
Reason: no such user

Time: ${toIST(new Date().toISOString())}`
      );
      return res.status(401).json({ error: 'invalid_credentials' });
    }

    const user = hits[0];
    const passwordOk = await bcrypt.compare(password, user.password_hash);

    if (!passwordOk) {
      await recordAttempt(username, ip, false);
      await logAction({ adminId: user.id, username, action: 'login_fail', ip, userAgent, details: { reason: 'bad_password' } });
      await sendTelegram(
`❌ YORVOXX INVALID LOGIN ATTEMPT

Username: ${username}
IP: ${ip}
Reason: wrong password

Time: ${toIST(new Date().toISOString())}`
      );
      return res.status(401).json({ error: 'invalid_credentials' });
    }

    await recordAttempt(username, ip, true);
    await logAction({ adminId: user.id, username, action: 'login_success', ip, userAgent, details: { totp_pending: !!user.totp_enabled } });

    await sendTelegram(
`✅ YORVOXX ADMIN LOGIN

Username: ${username}
IP: ${ip}

Time: ${toIST(new Date().toISOString())}`
    );

    const needsVerify = !!user.totp_enabled;
    await createSession(res, user.id, ip, userAgent, !needsVerify);
    res.json({ ok: true, expires_in_minutes: 15, totp_enabled: needsVerify, totp_pending: needsVerify });
  } catch (e) {
    console.error('/login error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: 'server_error', message: e.message });
  }
});

// POST /admin/2fa/verify-login  { totp_code }
// The in-dashboard second-factor check. Reachable on an unverified session
// (only requireSession, not requireVerified) — this IS the route that
// clears totp_verified for the session so requireVerified starts passing.
router.post('/2fa/verify-login', requireSession, async (req, res) => {
  try {
    if (req.totpVerified) {
      return res.json({ ok: true, already_verified: true });
    }
    const { totp_code } = req.body || {};
    if (!totp_code) {
      return res.status(400).json({ error: 'totp_code_required' });
    }

    const rows = await db.execute({ sql: `SELECT username, totp_secret FROM admin_users WHERE id = ?`, args: [req.adminId] });
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

    if (!ok) {
      await logAction({ adminId: req.adminId, username: hits[0].username, action: 'login_2fa_fail', ip: getClientIp(req), userAgent: req.headers['user-agent'] });
      await sendTelegram(
`❌ YORVOXX INVALID 2FA CODE

Username: ${hits[0].username}
IP: ${getClientIp(req)}

Time: ${toIST(new Date().toISOString())}`
      );
      return res.status(401).json({ error: 'invalid_totp' });
    }

    await markSessionVerified(req.sessionId);
    await logAction({ adminId: req.adminId, username: hits[0].username, action: 'login_2fa_verified', ip: getClientIp(req), userAgent: req.headers['user-agent'] });
    res.json({ ok: true });
  } catch (e) {
    console.error('/2fa/verify-login error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: 'server_error' });
  }
});

router.post('/logout', requireSession, async (req, res) => {
  try {
    await destroySession(req.sessionId, res);
    await logAction({ adminId: req.adminId, action: 'logout', ip: getClientIp(req), userAgent: req.headers['user-agent'] });
    await sendTelegram(
`🚪 YORVOXX ADMIN LOGOUT

Admin ID: ${req.adminId}
IP: ${getClientIp(req)}

Time: ${toIST(new Date().toISOString())}`
    );
    res.json({ ok: true });
  } catch (e) {
    console.error('/logout error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: 'server_error' });
  }
});

// GET /admin/session — frontend calls this on load. Reachable even on an
// unverified session (requireSession only) so the dashboard shell can load
// and know to show the in-dashboard "enter your code" step via totp_pending.
router.get('/session', requireSession, async (req, res) => {
  try {
    const rows = await db.execute({ sql: `SELECT totp_enabled FROM admin_users WHERE id = ?`, args: [req.adminId] });
    const hits = rows.rows || rows;
    res.json({
      ok: true,
      totp_enabled: !!(hits[0] && hits[0].totp_enabled),
      totp_pending: !req.totpVerified,
    });
  } catch (e) {
    console.error('/session error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: 'server_error' });
  }
});

// --- 2FA setup/enable/disable — unchanged. These already require a full
// session; since totp isn't enabled yet when a user first sets it up,
// totp_verified is already 1 at that point, so requireSession is enough. ---

router.post('/2fa/setup', requireSession, async (req, res) => {
  try {
    const secret = speakeasy.generateSecret({ name: 'VOXX Admin' });
    await db.execute({
      sql: `UPDATE admin_users SET totp_secret = ? WHERE id = ?`,
      args: [secret.base32, req.adminId],
    });
    const qr = await qrcode.toDataURL(secret.otpauth_url);
    res.json({ qr_code: qr, secret: secret.base32 });
  } catch (e) {
    console.error('/2fa/setup error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: 'server_error' });
  }
});

router.post('/2fa/verify', requireSession, async (req, res) => {
  try {
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
    await sendTelegram(
`📱 YORVOXX 2FA ENABLED

Admin ID: ${req.adminId}
IP: ${getClientIp(req)}

Time: ${toIST(new Date().toISOString())}`
    );
    res.json({ ok: true });
  } catch (e) {
    console.error('/2fa/verify error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: 'server_error' });
  }
});

router.post('/2fa/disable', requireSession, async (req, res) => {
  try {
    await db.execute({
      sql: `UPDATE admin_users SET totp_enabled = 0, totp_secret = NULL WHERE id = ?`,
      args: [req.adminId],
    });
    await logAction({ adminId: req.adminId, action: '2fa_disabled', ip: getClientIp(req), userAgent: req.headers['user-agent'] });
    await sendTelegram(
`📱 YORVOXX 2FA DISABLED

Admin ID: ${req.adminId}
IP: ${getClientIp(req)}

Time: ${toIST(new Date().toISOString())}`
    );
    res.json({ ok: true });
  } catch (e) {
    console.error('/2fa/disable error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: 'server_error' });
  }
});

module.exports = router;
