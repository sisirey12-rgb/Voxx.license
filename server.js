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

// STEP 1 (login): /admin/login, /admin/logout, /admin/session, /admin/2fa/*
// need only a valid session — username+password(+TOTP) — with no
// dependency on ADMIN_KEY at all. /admin/setup-admin (bootstrap/reset) is
// also in here, gated by its own admin_key body check since there's no
// account to log into yet on a brand-new server.
app.use('/admin', authRoutes);

// STEP 2 (connect): every license/reseller/topup route requires BOTH a
// live session (requireSession, inside admin.js) AND the X-Admin-Key
// header (adminAuth, checked first here) — this is the second lock, and
// it only comes into play after a successful login, not before or during it.
app.use('/admin', adminAuth, adminRoutes);

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
