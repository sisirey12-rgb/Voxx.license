require('dotenv').config();
const express = require('express');
const cors = require('cors');

const { init } = require('./db');
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

// /admin/login (public), /admin/logout, /admin/session, /admin/2fa/* —
// all gated internally by adminAuth (X-Admin-Key), same mechanism as adminRoutes.
app.use('/admin', authRoutes);

// Existing admin routes (keys, generate-key, revoke, etc.) — gated by
// adminAuth (X-Admin-Key) inside admin.js itself.
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
