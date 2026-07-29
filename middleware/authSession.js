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

// totpVerified: pass false when the account has 2FA enabled and the user
// hasn't entered their code yet this session — the dashboard shell loads,
// but requireVerified() blocks every real admin route until they verify
// inside the dashboard (POST /admin/2fa/verify-login).
async function createSession(res, adminId, ip, userAgent, totpVerified) {
  const id = newSessionId();
  await db.execute({
    sql: `INSERT INTO sessions (id, admin_id, ip, user_agent, expires_at, totp_verified)
          VALUES (?, ?, ?, ?, ?, ?)`,
    args: [id, adminId, ip, userAgent || null, minutesFromNow(SESSION_MINUTES), totpVerified ? 1 : 0],
  });
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
    sql: `SELECT id, admin_id, expires_at, totp_verified FROM sessions WHERE id = ? AND expires_at > ?`,
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
  req.totpVerified = !!hits[0].totp_verified;
  next();
}

// Sits after requireSession on any route that should actually be blocked
// until 2FA is verified for THIS session (i.e. everything in admin.js —
// key/reseller management). Login itself, /admin/session, and
// /admin/2fa/verify-login stay reachable on an unverified session so the
// dashboard shell can load and show the "enter your code" step.
function requireVerified(req, res, next) {
  if (!req.totpVerified) {
    return res.status(401).json({ error: 'totp_pending' });
  }
  next();
}

async function markSessionVerified(sessionId) {
  await db.execute({ sql: `UPDATE sessions SET totp_verified = 1 WHERE id = ?`, args: [sessionId] });
}

module.exports = {
  createSession,
  destroySession,
  requireSession,
  requireVerified,
  markSessionVerified,
  COOKIE_NAME,
};
