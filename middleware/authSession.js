// Validates the session token on every protected /admin/* request.
// Sliding 15-minute expiry: every valid request pushes expires_at forward.
//
// Sent as: Authorization: Bearer <token>  (not a cookie — avoids third-party
// cookie blocking, since the frontend and backend live on different domains).

const crypto = require('crypto');
const { db } = require('../db');

const SESSION_MINUTES = 15;

function newSessionId() {
  return crypto.randomBytes(32).toString('hex');
}

function minutesFromNow(mins) {
  return new Date(Date.now() + mins * 60000).toISOString();
}

async function createSession(adminId, ip, userAgent) {
  const id = newSessionId();
  await db.execute({
    sql: `INSERT INTO sessions (id, admin_id, ip, user_agent, expires_at)
          VALUES (?, ?, ?, ?, ?)`,
    args: [id, adminId, ip, userAgent || null, minutesFromNow(SESSION_MINUTES)],
  });
  return id;
}

async function destroySession(sessionId) {
  await db.execute({ sql: `DELETE FROM sessions WHERE id = ?`, args: [sessionId] });
}

function getBearerToken(req) {
  const header = req.headers['authorization'] || '';
  const match = header.match(/^Bearer\s+(.+)$/i);
  return match ? match[1].trim() : null;
}

// Express middleware: requires a valid, unexpired session token
// in the Authorization: Bearer <token> header.
async function requireSession(req, res, next) {
  const sessionId = getBearerToken(req);
  if (!sessionId) return res.status(401).json({ error: 'not_authenticated' });

  const now = new Date().toISOString();
  const rows = await db.execute({
    sql: `SELECT id, admin_id, expires_at FROM sessions WHERE id = ? AND expires_at > ?`,
    args: [sessionId, now],
  });
  const hits = rows.rows || rows;

  if (hits.length === 0) {
    return res.status(401).json({ error: 'session_expired' });
  }

  // Sliding window: extend expiry on activity.
  await db.execute({
    sql: `UPDATE sessions SET expires_at = ?, last_seen_at = ? WHERE id = ?`,
    args: [minutesFromNow(SESSION_MINUTES), now, sessionId],
  });

  req.adminId = hits[0].admin_id;
  req.sessionId = sessionId;
  next();
}

module.exports = {
  createSession,
  destroySession,
  requireSession,
};
