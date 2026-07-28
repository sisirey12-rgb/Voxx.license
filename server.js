require('dotenv').config();
const express = require('express');
const cors = require('cors');

const { init } = require('./db');
const adminAuth = require('./middleware/adminAuth');
const authRoutes = require('./routes/auth');
const adminRoutes = require('./routes/admin');
const licenseRoutes = require('./routes/license');
const resellerRoutes = require('./routes/reseller');

const app = express();

app.set('trust proxy', 1); // needed on Render/Railway/Fly so req.ip is the real client IP

app.use(cors({
  origin: 'https://admicontrolvoxx.netlify.app',
}));
app.use(express.json());

app.get('/', (req, res) => {
  res.json({ ok: true, service: 'voxx-license-server' });
});

// SECOND LOCK: every single /admin/* route — including /admin/login itself —
// now requires a valid X-Admin-Key header first, checked against ADMIN_KEY
// stored in Render's env vars. A correct username+password (even with a
// valid TOTP code) is no longer enough on its own to reach the login
// endpoint, let alone the console: without the key, requests are rejected
// with 401 before username/password is ever looked at or lockout-tracked.
app.use('/admin', adminAuth);

// /admin/login (past the key gate above) is where you exchange
// username+password(+TOTP) for a session token. /admin/logout,
// /admin/session, /admin/2fa/* are each individually gated by requireSession
// inside auth.js, on top of the key gate above.
app.use('/admin', authRoutes);

// Key/reseller/topup management — every route here requires BOTH the
// X-Admin-Key header (checked above) AND a live session token
// (router.use(requireSession) inside admin.js).
app.use('/admin', adminRoutes);

app.use('/api', licenseRoutes);
app.use('/reseller', resellerRoutes);

const PORT = process.env.PORT || 3000;

init()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`voxx-license-server listening on port ${PORT}`);
    });
  })
  .catch(err => {
    console.error('Failed to initialize database:', err);
    process.exit(1);
  });
