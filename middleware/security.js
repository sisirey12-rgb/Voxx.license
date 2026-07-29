// Lockout tracking (by username AND by IP) + audit logging

const { db } = require('../db');

const MAX_ATTEMPTS = 5;
const LOCKOUT_MINUTES = 60;
const ATTEMPT_WINDOW_MINUTES = 60;

function minutesFromNow(mins) {
  const d = new Date(Date.now() + mins * 60000);
  return d.toISOString().replace("T", " ").substring(0, 19);
}

// --------------------------------------------------
// Check whether username or IP is currently locked
// --------------------------------------------------
async function checkLockout(username, ip) {
  try {
    // Clean expired lockouts
    await db.execute({
      sql: `DELETE FROM lockouts WHERE locked_until <= datetime('now')`
    });

    const result = await db.execute({
      sql: `
        SELECT scope_type, scope_value, locked_until
        FROM lockouts
        WHERE
          (
            (scope_type='username' AND scope_value=?)
            OR
            (scope_type='ip' AND scope_value=?)
          )
          AND locked_until > datetime('now')
      `,
      args: [username, ip]
    });

    const rows = result.rows || result;

    if (rows.length > 0) {
      return {
        locked: true,
        reason: rows[0].scope_type,
        until: rows[0].locked_until
      };
    }

    return {
      locked: false,
      reason: null,
      until: null
    };

  } catch (err) {
    console.error("checkLockout()", err);
    return {
      locked: false,
      reason: null,
      until: null
    };
  }
}

// --------------------------------------------------
// Record login attempt
// --------------------------------------------------
async function recordAttempt(username, ip, success) {

  await db.execute({
    sql: `
      INSERT INTO login_attempts
      (username, ip, success)
      VALUES (?, ?, ?)
    `,
    args: [username, ip, success ? 1 : 0]
  });

  // Successful login = nothing else to do
  if (success) return;

  // Count username failures
  const byUserResult = await db.execute({
    sql: `
      SELECT COUNT(*) AS n
      FROM login_attempts
      WHERE
        username = ?
        AND success = 0
        AND created_at > datetime('now','-60 minutes')
    `,
    args: [username]
  });

  // Count IP failures
  const byIpResult = await db.execute({
    sql: `
      SELECT COUNT(*) AS n
      FROM login_attempts
      WHERE
        ip = ?
        AND success = 0
        AND created_at > datetime('now','-60 minutes')
    `,
    args: [ip]
  });

  const userFails =
    Number((byUserResult.rows || byUserResult)[0].n);

  const ipFails =
    Number((byIpResult.rows || byIpResult)[0].n);

  console.log({
    username,
    ip,
    userFails,
    ipFails
  });

  // Username lock
  if (userFails >= MAX_ATTEMPTS) {

    console.log("LOCKING USER:", username);

    await db.execute({
      sql: `
        INSERT OR REPLACE INTO lockouts
        (scope_type, scope_value, locked_until)
        VALUES
        ('username', ?, datetime('now','+60 minutes'))
      `,
      args: [username]
    });
  }

  // IP lock
  if (ipFails >= MAX_ATTEMPTS) {

    console.log("LOCKING IP:", ip);

    await db.execute({
      sql: `
        INSERT OR REPLACE INTO lockouts
        (scope_type, scope_value, locked_until)
        VALUES
        ('ip', ?, datetime('now','+60 minutes'))
      `,
      args: [ip]
    });
  }
}

// --------------------------------------------------
// Audit Log
// --------------------------------------------------
async function logAction({
  adminId = null,
  username = null,
  action,
  ip,
  userAgent,
  details = null
}) {

  await db.execute({
    sql: `
      INSERT INTO audit_log
      (
        admin_id,
        username,
        action,
        ip,
        user_agent,
        details
      )
      VALUES (?, ?, ?, ?, ?, ?)
    `,
    args: [
      adminId,
      username,
      action,
      ip,
      userAgent || null,
      details ? JSON.stringify(details) : null
    ]
  });

}

// --------------------------------------------------
// Client IP
// --------------------------------------------------
function getClientIp(req) {

  return (
    req.ip ||
    (req.headers["x-forwarded-for"] || "")
      .split(",")[0]
      .trim() ||
    req.socket.remoteAddress
  );

}

module.exports = {
  checkLockout,
  recordAttempt,
  logAction,
  getClientIp,
  MAX_ATTEMPTS,
  LOCKOUT_MINUTES
};
