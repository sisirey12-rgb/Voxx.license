// Lockout tracking (by username AND by IP) + audit logging

const { db } = require("../db");
const { sendTelegram } = require("../utils/telegram");
const axios = require("axios");

const MAX_ATTEMPTS = 5;
const LOCKOUT_MINUTES = 60;

function toIST(date) {
  return new Date(date).toLocaleString("en-IN", {
    timeZone: "Asia/Kolkata",
    hour12: true,
  });
}

// Formats a time in the visitor's own timezone (from their IP lookup)
// instead of always showing IST. Falls back to IST if the timezone is
// missing or invalid.
function toLocalTime(date, timezone) {
  try {
    return new Date(date).toLocaleString("en-US", {
      timeZone: timezone || "Asia/Kolkata",
      hour12: true,
      dateStyle: "short",
      timeStyle: "medium",
    });
  } catch {
    return toIST(date);
  }
}

async function getLocation(ip) {
  try {
    const { data } = await axios.get(`http://ip-api.com/json/${ip}`);

    return {
      country: data.country || "Unknown",
      countryCode: data.countryCode || "",
      region: data.regionName || "Unknown",
      city: data.city || "Unknown",
      isp: data.isp || "Unknown",
      timezone: data.timezone || "Asia/Kolkata",
    };
  } catch {
    return {
      country: "Unknown",
      countryCode: "",
      region: "Unknown",
      city: "Unknown",
      isp: "Unknown",
      timezone: "Asia/Kolkata",
    };
  }
}

function getClientIp(req) {
  const forwarded = req.headers["x-forwarded-for"];

  if (forwarded) {
    return forwarded.split(",")[0].trim();
  }

  return req.ip || req.socket.remoteAddress;
}

async function checkLockout(username, ip) {
  await db.execute({
    sql: `DELETE FROM lockouts WHERE locked_until <= datetime('now')`,
  });

  const result = await db.execute({
    sql: `
      SELECT *
      FROM lockouts
      WHERE
      (
        (scope_type='username' AND scope_value=?)
        OR
        (scope_type='ip' AND scope_value=?)
      )
      AND locked_until > datetime('now')
    `,
    args: [username, ip],
  });

  const rows = result.rows || result;

  if (rows.length > 0) {
    return {
      locked: true,
      reason: rows[0].scope_type,
      until: rows[0].locked_until,
    };
  }

  return {
    locked: false,
    reason: null,
    until: null,
  };
}

async function recordAttempt(
  username,
  ip,
  success,
  wrongPassword = ""
) {

  await db.execute({
    sql: `
      INSERT INTO login_attempts
      (username, ip, success)
      VALUES (?, ?, ?)
    `,
    args: [username, ip, success ? 1 : 0],
  });

  if (success) return;

  const userResult = await db.execute({
    sql: `
      SELECT COUNT(*) AS n
      FROM login_attempts
      WHERE
      username=?
      AND success=0
      AND created_at > datetime('now','-60 minutes')
    `,
    args: [username],
  });

  const ipResult = await db.execute({
    sql: `
      SELECT COUNT(*) AS n
      FROM login_attempts
      WHERE
      ip=?
      AND success=0
      AND created_at > datetime('now','-60 minutes')
    `,
    args: [ip],
  });

  const userFails = Number((userResult.rows || userResult)[0].n);
  const ipFails = Number((ipResult.rows || ipResult)[0].n);

  const loc = await getLocation(ip);

  if (userFails === 3) {

    await sendTelegram(
`⚠️ YORVOXX ADMIN SECURITY WARNING!

Username: ${username}

Public IP: ${ip}

Country: ${loc.country} ${loc.countryCode ? `(${loc.countryCode})` : ""}

State: ${loc.region}

City: ${loc.city}

ISP: ${loc.isp}

Reason:
3 failed login attempts

Wrong Password:
${wrongPassword || "(hidden)"}

Time:
${toLocalTime(new Date(), loc.timezone)}`
    );

  }
    if (userFails >= MAX_ATTEMPTS) {

    await db.execute({
      sql: `
        INSERT OR REPLACE INTO lockouts
        (scope_type, scope_value, locked_until)
        VALUES
        ('username', ?, datetime('now','+60 minutes'))
      `,
      args: [username],
    });

    await sendTelegram(
`🚨 YORVOXX ADMIN SECURITY ALERT!

Username: ${username}

Public IP: ${ip}

Country: ${loc.country} ${loc.countryCode ? `(${loc.countryCode})` : ""}

State: ${loc.region}

City: ${loc.city}

ISP: ${loc.isp}

Reason:
5 failed login attempts

Wrong Password:
${wrongPassword || "(hidden)"}

Time:
${toLocalTime(new Date(), loc.timezone)}`
    );

  }

  if (ipFails >= MAX_ATTEMPTS) {

    await db.execute({
      sql: `
        INSERT OR REPLACE INTO lockouts
        (scope_type, scope_value, locked_until)
        VALUES
        ('ip', ?, datetime('now','+60 minutes'))
      `,
      args: [ip],
    });

    await sendTelegram(
`🚫 YORVOXX ATTACKER IP LOCKED!

Public IP: ${ip}

Country: ${loc.country} ${loc.countryCode ? `(${loc.countryCode})` : ""}

State: ${loc.region}

City: ${loc.city}

ISP: ${loc.isp}

Reason:
5 failed login attempts

Time:
${toLocalTime(new Date(), loc.timezone)}`
    );

  }

}

async function logAction({
  adminId = null,
  username = null,
  action,
  ip,
  userAgent,
  details = null,
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
      details ? JSON.stringify(details) : null,
    ],
  });

}

module.exports = {
  checkLockout,
  recordAttempt,
  logAction,
  getClientIp,
  getLocation,
  toIST,
  toLocalTime,
  MAX_ATTEMPTS,
  LOCKOUT_MINUTES,
};
