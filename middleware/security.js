// Lockout tracking (by username AND by IP) + audit logging

const { db } = require('../db');
const { sendTelegram } = require("../utils/telegram");

const MAX_ATTEMPTS = 5;
const LOCKOUT_MINUTES = 60;
const ATTEMPT_WINDOW_MINUTES = 60;

function minutesFromNow(mins) {
  const d = new Date(Date.now() + mins * 60000);
  return d.toISOString().replace("T", " ").substring(0, 19);
}

// Converts a UTC "YYYY-MM-DD HH:MM:SS" string (as stored in Turso) or a
// full ISO string into an India-local, human-readable string. Appending
// 'Z' only when it's missing tells JS the source string is UTC — without
// it, JS would wrongly assume the string is already local time.
function toIST(utcString) {
  if (!utcString) return utcString;
  const iso = utcString.includes('T') ? utcString : utcString.replace(' ', 'T');
  const withZone = iso.endsWith('Z') ? iso : iso + 'Z';
  return new Date(withZone).toLocaleString('en-IN', {
    timeZone: 'Asia/Kolkata',
    hour12: true,
  });
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
        until: toIST(rows[0].locked_until)
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

  // Warning after 3 failed username attempts
  if (userFails === 3) {
    await sendTelegram(
`⚠️ YORVOXX ADMIN SECURITY WARNING

Username: ${username}
IP: ${ip}

3 failed login attempts detected.

Time: ${toIST(new Date().toISOString())}`
    );
  }

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

    await sendTelegram(
`🔒 YORVOXX ATTACKER ACCOUNT LOCKED

Username: ${username}

IP: ${ip}

Reason:
5 failed login attempts.

Time:
${toIST(new Date().toISOString())}`
    );
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

    await sendTelegram(
`🚫 YORVOXX ATTACKER IP LOCKED

IP: ${ip}

Reason:
5 failed login attempts.

Time:
${toIST(new Date().toISOString())}`
    );
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
  const forwarded = req.headers["x-forwarded-for"];

  if (forwarded) {
    return forwarded.split(",")[0].trim();
  }

  return req.ip || req.socket.remoteAddress;
}

module.exports = {
  checkLockout,
  recordAttempt,
  logAction,
  getClientIp,
  toIST,
  MAX_ATTEMPTS,
  LOCKOUT_MINUTES
};
