// Validates the session on every protected /admin/* request.
// Sliding 15-minute expiry: every valid request pushes expires_at forward,
// both in the DB and on the cookie itself, so they stay in sync.
//
// Sent as: an httpOnly cookie (voxx_session), not a header. JavaScript on
// the page — including any injected via XSS — cannot read this cookie's
// value, unlike a Bearer token, which has to sit in localStorage/JS-visible
// memory to be attached to requests. Cross-site (frontend and backend on
// different domains) means the cookie needs SameSite=None; Secure, and the
// server's CORS config must set credentials:true with an exact origin
// (never '*') for the browser to send/accept it.

const crypto = require('crypto');
const { db } = require('../db');

const SESSION_MINUTES = 15;
const COOKIE_NAME = 'voxx_session';

function newSessionId() {
  return crypto.randomBytes(32).toString('hex');
}

function minutesFromNow(mins) {
  return new Date(Date.now() + mins * 60000).toISOString();
}

function cookieOptions() {
  return {
    httpOnly: true,
    secure: true,
    sameSite: 'none',
    maxAge: SESSION_MINUTES * 60 * 1000,
    path: '/',
  };
}

async function createSession(res, adminId, ip, userAgent) {
  const id = newSessionId();
  console.log('DEBUG createSession adminId=', adminId, 'typeof=', typeof adminId, 'ip=', ip, 'ua=', userAgent);
  try {
    const result = await db.execute({
      sql: `INSERT INTO sessions (id, admin_id, ip, user_agent, expires_at)
            VALUES (?, ?, ?, ?, ?)`,
      args: [id, adminId, ip, userAgent || null, minutesFromNow(SESSION_MINUTES)],
    });
    console.log('DEBUG createSession INSERT ok, rowsAffected=', result.rowsAffected);
  } catch (e) {
    console.error('DEBUG createSession FAILED. adminId was:', adminId, 'error:', e.message);
    throw e;
  }
  res.cookie(COOKIE_NAME, id, cookieOptions());
  return id;
}

async function destroySession(sessionId, res) {
  await db.execute({ sql: `DELETE FROM sessions WHERE id = ?`, args: [sessionId] });
  if (res) res.clearCookie(COOKIE_NAME, { httpOnly: true, secure: true, sameSite: 'none', path: '/' });
}

async function requireSession(req, res, next) {
  const sessionId = req.cookies ? req.cookies[COOKIE_NAME] : null;
  if (!sessionId) return res.status(401).json({ error: 'not_authenticated' });

  const now = new Date().toISOString();
  const rows = await db.execute({
    sql: `SELECT id, admin_id, expires_at FROM sessions WHERE id = ? AND expires_at > ?`,
    args: [sessionId, now],
  });
  const hits = rows.rows || rows;

  if (hits.length === 0) {
    res.clearCookie(COOKIE_NAME, { httpOnly: true, secure: true, sameSite: 'none', path: '/' });
    return res.status(401).json({ error: 'session_expired' });
  }

  await db.execute({
    sql: `UPDATE sessions SET expires_at = ?, last_seen_at = ? WHERE id = ?`,
    args: [minutesFromNow(SESSION_MINUTES), now, sessionId],
  });
  res.cookie(COOKIE_NAME, sessionId, cookieOptions());

  req.adminId = hits[0].admin_id;
  req.sessionId = sessionId;
  next();
}

module.exports = {
  createSession,
  destroySession,
  requireSession,
  COOKIE_NAME,
};
