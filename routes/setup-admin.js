// TEMPORARY one-time route to create your admin account without needing
// local Node or shell access. DELETE THIS FILE (and its require/app.use line
// in server.js) immediately after you've successfully created your account.
//
// Usage: visit this URL once in your browser (replace the placeholders):
//   https://voxxstore.onrender.com/admin/setup-admin?key=YOUR_ADMIN_KEY&username=YOURNAME&password=YOURPASSWORD
//
// "key" must match the ADMIN_KEY environment variable already set on Render,
// so a stranger can't call this and create their own admin account.

const express = require('express');
const bcrypt = require('bcrypt');
const { db } = require('../db');

const router = express.Router();

router.get('/setup-admin', async (req, res) => {
  const { key, username, password } = req.query;

  if (!key || key !== process.env.ADMIN_KEY) {
    return res.status(403).json({ error: 'forbidden' });
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

  res.json({ ok: true, message: `Admin user "${username}" created/updated. Now DELETE this route and redeploy.` });
});

module.exports = router;
