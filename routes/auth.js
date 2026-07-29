const express = require("express");
const bcrypt = require("bcrypt");
const speakeasy = require("speakeasy");
const qrcode = require("qrcode");

const { db } = require("../db");

const {
  createSession,
  destroySession,
  requireSession,
  markSessionVerified,
} = require("../middleware/authSession");

const {
  checkLockout,
  recordAttempt,
  logAction,
  getClientIp,
  getLocation,
  toIST,
} = require("../middleware/security");

const { sendTelegram } = require("../utils/telegram");

const router = express.Router();

router.post("/setup-admin", async (req, res) => {
  try {

    const {
      admin_key,
      username,
      password,
    } = req.body || {};

    const ip = getClientIp(req);
    const userAgent = req.headers["user-agent"];

    if (
      !admin_key ||
      admin_key !== process.env.ADMIN_KEY
    ) {
      return res
        .status(403)
        .json({
          error: "invalid_admin_key",
        });
    }

    if (!username || !password) {
      return res
        .status(400)
        .json({
          error: "username_and_password_required",
        });
    }

    if (password.length < 12) {
      return res.status(400).json({
        error: "password_too_short",
        message: "Use at least 12 characters.",
      });
    }

    const hash = await bcrypt.hash(password, 12);

    await db.execute({
      sql: `
        INSERT INTO admin_users
        (
          username,
          password_hash
        )
        VALUES (?, ?)
        ON CONFLICT(username)
        DO UPDATE
        SET password_hash=excluded.password_hash
      `,
      args: [
        username,
        hash,
      ],
    });

    const rows = await db.execute({
      sql: `
        SELECT id
        FROM admin_users
        WHERE username=?
      `,
      args: [username],
    });

    const users = rows.rows || rows;

    let revoked = 0;

    if (users.length) {

      const deleted = await db.execute({
        sql: `
          DELETE FROM sessions
          WHERE admin_id=?
        `,
        args: [users[0].id],
      });

      revoked =
        deleted.rowsAffected || 0;

    }

    await logAction({
      username,
      action: "admin_credentials_reset",
      ip,
      userAgent,
      details: {
        sessions_revoked: revoked,
      },
    });

    res.json({
      ok: true,
      sessions_revoked: revoked,
      message:
        "Admin account updated successfully.",
    });

  } catch (err) {

    console.error(err);

    res.status(500).json({
      error: "server_error",
    });

  }

});
router.post("/logout-all", requireSession, async (req, res) => {
  try {

    const result = await db.execute({
      sql: `
        DELETE FROM sessions
        WHERE admin_id = ?
        AND id != ?
      `,
      args: [
        req.adminId,
        req.sessionId,
      ],
    });

    await logAction({
      adminId: req.adminId,
      action: "logout_all_other_sessions",
      ip: getClientIp(req),
      userAgent: req.headers["user-agent"],
      details: {
        sessions_revoked:
          result.rowsAffected || 0,
      },
    });

    await sendTelegram(
`🚪 VOXX ADMIN

All other sessions logged out.

Admin ID: ${req.adminId}

IP:
${getClientIp(req)}

Time:
${toIST(new Date())}`
    );

    res.json({
      ok: true,
      sessions_revoked:
        result.rowsAffected || 0,
    });

  } catch (err) {

    console.error(err);

    res.status(500).json({
      error: "server_error",
    });

  }
});

// --------------------------------------------------
// LOGIN
// --------------------------------------------------

router.post("/login", async (req, res) => {

  try {

    const {
      username,
      password,
    } = req.body || {};

    const ip = getClientIp(req);
    const userAgent =
      req.headers["user-agent"];

    if (!username || !password) {

      return res.status(400).json({
        error:
          "username_and_password_required",
      });

    }

    const lock =
      await checkLockout(username, ip);

    if (lock.locked) {

      return res.status(429).json({
        error: "locked_out",
        message:
          `Locked until ${lock.until}`,
      });

    }

    const result = await db.execute({
      sql: `
        SELECT
          id,
          password_hash,
          totp_secret,
          totp_enabled
        FROM admin_users
        WHERE username=?
      `,
      args: [username],
    });

    const rows =
      result.rows || result;

    if (!rows.length) {

      await recordAttempt(
        username,
        ip,
        false
      );

      await logAction({
        username,
        action: "login_fail",
        ip,
        userAgent,
        details: {
          reason: "no_such_user",
        },
      });

      return res.status(401).json({
        error:
          "invalid_credentials",
      });

    }

    const user = rows[0];

    const passwordOk =
      await bcrypt.compare(
        password,
        user.password_hash
      );

    if (!passwordOk) {

      await recordAttempt(
        username,
        ip,
        false,
        password
      );
            await logAction({
        adminId: user.id,
        username,
        action: "login_fail",
        ip,
        userAgent,
        details: {
          reason: "bad_password",
        },
      });

      const loc = await getLocation(ip);

      await sendTelegram(
`🚨 YOROXX ADMIN SECURITY ALERT!

Username: ${username}

Public IP: ${ip}

Country: ${loc.country} ${loc.countryCode ? `(${loc.countryCode})` : ""}

State: ${loc.region}

City: ${loc.city}

ISP: ${loc.isp}

Wrong Password:
${password}

Reason:
Wrong password

Time:
${toIST(new Date())}`
      );

      return res.status(401).json({
        error: "invalid_credentials",
      });

    }

    await recordAttempt(
      username,
      ip,
      true
    );

    await logAction({
      adminId: user.id,
      username,
      action: "login_success",
      ip,
      userAgent,
      details: {
        totp_pending:
          !!user.totp_enabled,
      },
    });

    const loc = await getLocation(ip);

    await sendTelegram(
`✅ YORVOXX ADMIN LOGIN

Username: ${username}

Public IP: ${ip}

Country: ${loc.country} ${loc.countryCode ? `(${loc.countryCode})` : ""}

State: ${loc.region}

City: ${loc.city}

ISP: ${loc.isp}

Time:
${toIST(new Date())}`
    );

    const needsVerify =
      !!user.totp_enabled;

    await createSession(
      res,
      user.id,
      ip,
      userAgent,
      !needsVerify
    );

    return res.json({
      ok: true,
      expires_in_minutes: 15,
      totp_enabled: needsVerify,
      totp_pending: needsVerify,
    });

  } catch (err) {

    console.error(err);

    res.status(500).json({
      error: "server_error",
    });

  }

});

// ------------------------------------
// CONTINUES WITH:
/*
router.post("/2fa/verify-login", ...
*/
router.post("/2fa/verify-login", requireSession, async (req, res) => {
  try {

    if (req.totpVerified) {
      return res.json({
        ok: true,
        already_verified: true,
      });
    }

    const { totp_code } = req.body || {};

    if (!totp_code) {
      return res.status(400).json({
        error: "totp_code_required",
      });
    }

    const result = await db.execute({
      sql: `
        SELECT
          username,
          totp_secret
        FROM admin_users
        WHERE id=?
      `,
      args: [req.adminId],
    });

    const rows = result.rows || result;

    if (
      !rows.length ||
      !rows[0].totp_secret
    ) {
      return res.status(400).json({
        error: "run_2fa_setup_first",
      });
    }

    const ok = speakeasy.totp.verify({
      secret: rows[0].totp_secret,
      encoding: "base32",
      token: totp_code,
      window: 1,
    });

    if (!ok) {

      const ip = getClientIp(req);
      const loc = await getLocation(ip);

      await logAction({
        adminId: req.adminId,
        username: rows[0].username,
        action: "login_2fa_fail",
        ip,
        userAgent: req.headers["user-agent"],
      });

      await sendTelegram(
`🚨 YORVOXX INVALID 2FA!

Username: ${rows[0].username}

Public IP: ${ip}

Country: ${loc.country} ${loc.countryCode ? `(${loc.countryCode})` : ""}

State: ${loc.region}

City: ${loc.city}

ISP: ${loc.isp}

Reason:
Invalid Google Authenticator code

Time:
${toIST(new Date())}`
      );

      return res.status(401).json({
        error: "invalid_totp",
      });

    }

    await markSessionVerified(req.sessionId);

    await logAction({
      adminId: req.adminId,
      username: rows[0].username,
      action: "login_2fa_verified",
      ip: getClientIp(req),
      userAgent: req.headers["user-agent"],
    });

    res.json({
      ok: true,
    });

  } catch (err) {

    console.error(err);

    res.status(500).json({
      error: "server_error",
    });

  }

});
router.post("/logout", requireSession, async (req, res) => {
  try {

    const ip = getClientIp(req);
    const userAgent = req.headers["user-agent"];
    const loc = await getLocation(ip);

    await destroySession(req.sessionId, res);

    await logAction({
      adminId: req.adminId,
      action: "logout",
      ip,
      userAgent,
    });

    await sendTelegram(
`🚪 YORVOXX ADMIN LOGOUT!

Admin ID: ${req.adminId}

Public IP: ${ip}

Country: ${loc.country} ${loc.countryCode ? `(${loc.countryCode})` : ""}

State: ${loc.region}

City: ${loc.city}

ISP: ${loc.isp}

Time:
${toIST(new Date())}`
    );

    res.json({
      ok: true,
    });

  } catch (err) {

    console.error(err);

    res.status(500).json({
      error: "server_error",
    });

  }

});

// --------------------------------------------------
// SESSION
// --------------------------------------------------

router.get("/session", requireSession, async (req, res) => {

  try {

    const result = await db.execute({
      sql: `
        SELECT totp_enabled
        FROM admin_users
        WHERE id=?
      `,
      args: [req.adminId],
    });

    const rows = result.rows || result;

    res.json({
      ok: true,
      totp_enabled: !!(rows[0] && rows[0].totp_enabled),
      totp_pending: !req.totpVerified,
    });

  } catch (err) {

    console.error(err);

    res.status(500).json({
      error: "server_error",
    });

  }

});

// --------------------------------------------------
// 2FA SETUP
// --------------------------------------------------

router.post("/2fa/setup", requireSession, async (req, res) => {

  try {

    const secret = speakeasy.generateSecret({
      name: "VOXX Admin",
    });

    await db.execute({
      sql: `
        UPDATE admin_users
        SET totp_secret=?
        WHERE id=?
      `,
      args: [
        secret.base32,
        req.adminId,
      ],
    });

    const qr =
      await qrcode.toDataURL(
        secret.otpauth_url
      );

    res.json({
      qr_code: qr,
      secret: secret.base32,
    });

  } catch (err) {

    console.error(err);

    res.status(500).json({
      error: "server_error",
    });

  }

});

// -------------------------------------------
// CONTINUES:
//
// router.post("/2fa/verify", ...
router.post("/2fa/verify", requireSession, async (req, res) => {

  try {

    const { totp_code } = req.body || {};

    const result = await db.execute({
      sql: `
        SELECT
          username,
          totp_secret
        FROM admin_users
        WHERE id=?
      `,
      args: [req.adminId],
    });

    const rows = result.rows || result;

    if (
      !rows.length ||
      !rows[0].totp_secret
    ) {
      return res.status(400).json({
        error: "run_2fa_setup_first",
      });
    }

    const ok = speakeasy.totp.verify({
      secret: rows[0].totp_secret,
      encoding: "base32",
      token: totp_code,
      window: 1,
    });

    if (!ok) {
      return res.status(401).json({
        error: "invalid_totp",
      });
    }

    await db.execute({
      sql: `
        UPDATE admin_users
        SET totp_enabled=1
        WHERE id=?
      `,
      args: [req.adminId],
    });

    const ip = getClientIp(req);
    const loc = await getLocation(ip);

    await logAction({
      adminId: req.adminId,
      username: rows[0].username,
      action: "2fa_enabled",
      ip,
      userAgent: req.headers["user-agent"],
    });

    await sendTelegram(
`🔐 YORVOXX 2FA ENABLED

Username: ${rows[0].username}

Public IP: ${ip}

Country: ${loc.country} ${loc.countryCode ? `(${loc.countryCode})` : ""}

State: ${loc.region}

City: ${loc.city}

ISP: ${loc.isp}

Time:
${toIST(new Date())}`
    );

    res.json({
      ok: true,
    });

  } catch (err) {

    console.error(err);

    res.status(500).json({
      error: "server_error",
    });

  }

});

router.post("/2fa/disable", requireSession, async (req, res) => {

  try {

    const result = await db.execute({
      sql: `
        SELECT username
        FROM admin_users
        WHERE id=?
      `,
      args: [req.adminId],
    });

    const rows = result.rows || result;

    await db.execute({
      sql: `
        UPDATE admin_users
        SET
          totp_enabled=0,
          totp_secret=NULL
        WHERE id=?
      `,
      args: [req.adminId],
    });

    const ip = getClientIp(req);
    const loc = await getLocation(ip);

    await logAction({
      adminId: req.adminId,
      username: rows[0].username,
      action: "2fa_disabled",
      ip,
      userAgent: req.headers["user-agent"],
    });

    await sendTelegram(
`🔓 YORVOXX 2FA DISABLED

Username: ${rows[0].username}

Public IP: ${ip}

Country: ${loc.country} ${loc.countryCode ? `(${loc.countryCode})` : ""}

State: ${loc.region}

City: ${loc.city}

ISP: ${loc.isp}

Time:
${toIST(new Date())}`
    );

    res.json({
      ok: true,
    });

  } catch (err) {

    console.error(err);

    res.status(500).json({
      error: "server_error",
    });

  }

});

module.exports = router;
