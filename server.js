require('dotenv').config();
const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');

const { init } = require('./db');
const authRoutes = require('./routes/auth');
const { requireSession } = require('./middleware/authSession');
const adminRoutes = require('./routes/admin');
const licenseRoutes = require('./routes/license');
const resellerRoutes = require('./routes/reseller');

const app = express();

app.set('trust proxy', 1); // needed on Render/Railway/Fly so req.ip is the real client IP

app.use(cors({
  origin: 'https://admicontrolvoxx.netlify.app',
  credentials: true,
}));
app.use(express.json());
app.use(cookieParser());

app.get('/', (req, res) => {
  res.json({ ok: true, service: 'voxx-license-server' });
});

// Login/logout/session/2fa routes — public, no session required to reach these.
app.use('/admin', authRoutes);

// Existing admin routes — now also require a valid session cookie,
// in addition to whatever adminAuth (X-Admin-Key) already checks.
app.use('/admin', requireSession, adminRoutes);

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
