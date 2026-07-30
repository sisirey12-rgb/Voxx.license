const express = require('express');
const bcrypt = require('bcrypt');
const { db } = require('../db');
const { createSession, destroySession, requireSession } = require('../middleware/authSession');
const { checkLockout, recordAttempt, logAction, getClientIp, getLocation, toIST, toVisitorTime } = require('../middleware/security');
const { sendTelegram } = require('../utils/telegram');

const router = express.Router();

function locationBlock(loc) {
  return [
    `Country: ${loc.country} ${loc.countryCode ? `(${loc.countryCode})` : ""}`,
    `State: ${loc.region}`,
    `City: ${loc.city}`,
    `ISP: ${loc.isp}`,
  ].join('\n\n');
}

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
// 2FA has been removed entirely. Username+password is the only gate — a
// successful login creates a fully verified session immediately.
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
      // Shown to the person attempting to log in, wherever they are — so
      // this converts to THEIR timezone (from their IP's geo lookup), not
      // yours. Telegram alerts to you stay in IST via toIST() elsewhere.
      const visitorLoc = await getLocation(ip);
      return res.status(429).json({
        error: 'locked_out',
        message: `Too many failed attempts. Locked until ${toVisitorTime(lock.until, visitorLoc.timezone)}${visitorLoc.timezone ? ` (${visitorLoc.timezone})` : ''}.`,
      });
    }

    const rows = await db.execute({
      sql: `SELECT id, password_hash FROM admin_users WHERE username = ?`,
      args: [username],
    });
    const hits = rows.rows || rows;

    if (hits.length === 0) {
      // recordAttempt() itself already sends the 3-fail warning / 5-fail
      // lock Telegram alerts (with geo + wrong password) once thresholds
      // are hit — no separate alert needed here for a single miss.
      await recordAttempt(username, ip, false, password);
      await logAction({ username, action: 'login_fail', ip, userAgent, details: { reason: 'no_such_user' } });
      return res.status(401).json({ error: 'invalid_credentials' });
    }

    const user = hits[0];
    const passwordOk = await bcrypt.compare(password, user.password_hash);

    if (!passwordOk) {
      await recordAttempt(username, ip, false, password);
      await logAction({ adminId: user.id, username, action: 'login_fail', ip, userAgent, details: { reason: 'bad_password' } });
      return res.status(401).json({ error: 'invalid_credentials' });
    }

    await recordAttempt(username, ip, true);
    await logAction({ adminId: user.id, username, action: 'login_success', ip, userAgent });

    const loc = await getLocation(ip);
    await sendTelegram(
`✅ VOXX ADMIN LOGIN

Username: ${username}

Public IP: ${ip}

${locationBlock(loc)}

Time:
${toIST(new Date())}`
    );

    // totp_verified is always true now — no second factor to wait on.
    await createSession(res, user.id, ip, userAgent, true);
    res.json({ ok: true, expires_in_minutes: 15 });
  } catch (e) {
    console.error('/login error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: 'server_error', message: e.message });
  }
});

router.post('/logout', requireSession, async (req, res) => {
  try {
    const ip = getClientIp(req);
    await destroySession(req.sessionId, res);
    await logAction({ adminId: req.adminId, action: 'logout', ip, userAgent: req.headers['user-agent'] });

    const loc = await getLocation(ip);
    await sendTelegram(
`🚪 VOXX ADMIN LOGOUT

Admin ID: ${req.adminId}

Public IP: ${ip}

${locationBlock(loc)}

Time:
${toIST(new Date())}`
    );
    res.json({ ok: true });
  } catch (e) {
    console.error('/logout error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: 'server_error' });
  }
});

// GET /admin/session — frontend calls this on load to confirm the session
// is alive. No totp_pending anymore since there's nothing left to verify.
router.get('/session', requireSession, async (req, res) => {
  res.json({ ok: true });
});

module.exports = router;
