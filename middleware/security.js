// Lockout tracking (by username AND by IP, independently) + audit logging.
// Adjust `db.execute({ sql, args })` calls if your db.js wraps @libsql/client differently.

const db = require('../db');

const MAX_ATTEMPTS = 5;
const LOCKOUT_MINUTES = 60;
const ATTEMPT_WINDOW_MINUTES = 60; // failures older than this don't count

function minutesFromNow(mins) {
  return new Date(Date.now() + mins * 60000).toISOString();
}

// Returns { locked: bool, reason: 'username'|'ip'|null, until: iso|null }
async function checkLockout(username, ip) {
  const now = new Date().toISOString();

  const rows = await db.execute({
    sql: `SELECT scope_type, locked_until FROM lockouts
          WHERE ((scope_type = 'username' AND scope_value = ?)
              OR (scope_type = 'ip' AND scope_value = ?))
            AND locked_until > ?`,
    args: [username, ip, now],
  });

  const hits = rows.rows || rows; // support either libsql shape
  if (hits.length > 0) {
    const hit = hits[0];
    return { locked: true, reason: hit.scope_type, until: hit.locked_until };
  }
  return { locked: false, reason: null, until: null };
}

// Call after every login attempt (success or fail).
async function recordAttempt(username, ip, success) {
  await db.execute({
    sql: `INSERT INTO login_attempts (username, ip, success) VALUES (?, ?, ?)`,
    args: [username, ip, success ? 1 : 0],
  });

  if (success) {
    // Successful login clears any standing failure streak for this pair.
    return;
  }

  const since = new Date(Date.now() - ATTEMPT_WINDOW_MINUTES * 60000).toISOString();

  const [byUser, byIp] = await Promise.all([
    db.execute({
      sql: `SELECT COUNT(*) as n FROM login_attempts
            WHERE username = ? AND success = 0 AND created_at > ?`,
      args: [username, since],
    }),
    db.execute({
      sql: `SELECT COUNT(*) as n FROM login_attempts
            WHERE ip = ? AND success = 0 AND created_at > ?`,
      args: [ip, since],
    }),
  ]);

  const userFails = (byUser.rows || byUser)[0].n;
  const ipFails = (byIp.rows || byIp)[0].n;

  if (userFails >= MAX_ATTEMPTS) {
    await db.execute({
      sql: `INSERT INTO lockouts (scope_type, scope_value, locked_until)
            VALUES ('username', ?, ?)
            ON CONFLICT(scope_type, scope_value) DO UPDATE SET locked_until = excluded.locked_until`,
      args: [username, minutesFromNow(LOCKOUT_MINUTES)],
    });
  }
  if (ipFails >= MAX_ATTEMPTS) {
    await db.execute({
      sql: `INSERT INTO lockouts (scope_type, scope_value, locked_until)
            VALUES ('ip', ?, ?)
            ON CONFLICT(scope_type, scope_value) DO UPDATE SET locked_until = excluded.locked_until`,
      args: [ip, minutesFromNow(LOCKOUT_MINUTES)],
    });
  }
}

async function logAction({ adminId = null, username = null, action, ip, userAgent, details = null }) {
  await db.execute({
    sql: `INSERT INTO audit_log (admin_id, username, action, ip, user_agent, details)
          VALUES (?, ?, ?, ?, ?, ?)`,
    args: [adminId, username, action, ip, userAgent || null, details ? JSON.stringify(details) : null],
  });
}

// Real client IP even behind Render/Railway/Fly's proxy.
// Requires app.set('trust proxy', 1) in server.js (see integration notes).
function getClientIp(req) {
  return req.ip || (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.socket.remoteAddress;
}

module.exports = { checkLockout, recordAttempt, logAction, getClientIp, MAX_ATTEMPTS, LOCKOUT_MINUTES };
