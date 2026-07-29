require('dotenv').config();
const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');

const { init } = require('./db');
const authRoutes = require('./routes/auth');
const adminRoutes = require('./routes/admin');
const licenseRoutes = require('./routes/license');
const resellerRoutes = require('./routes/reseller');

const app = express();

app.set('trust proxy', 1); // needed on Render/Railway/Fly so req.ip is the real client IP

app.use(cors({
  origin: 'https://admicontrolvoxx.netlify.app',
  credentials: true, // required so the browser sends/receives the session cookie
}));
app.use(cookieParser());
app.use(express.json());

app.get('/', (req, res) => {
  res.json({ ok: true, service: 'voxx-license-server' });
});

// Everything under /admin is now gated by ONE thing: a valid session
// cookie from username+password(+TOTP) login (requireSession, applied
// inside auth.js for /logout|/session|/2fa/* and inside admin.js for
// every license/reseller/topup route). There is no X-Admin-Key check on
// any of these routes anymore, and the browser is never given ADMIN_KEY —
// it stays server-side, used only as a manually-typed value for
// POST /setup-admin (bootstrap/reset), never stored or auto-sent.
app.use('/admin', authRoutes);
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
