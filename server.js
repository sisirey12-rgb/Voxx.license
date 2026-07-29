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

app.set('trust proxy', 1);

app.use(cors({
  origin: 'https://admicontrolvoxx.netlify.app',
  credentials: true,
}));
app.use(cookieParser());
app.use(express.json());

app.get('/', (req, res) => {
  res.json({ ok: true, service: 'voxx-license-server' });
});

app.use('/admin', authRoutes);
app.use('/admin', adminRoutes);

app.use('/api', licenseRoutes);
app.use('/reseller', resellerRoutes);

// Catches any error passed via next(err), or thrown/rejected inside a route
// that was wrapped with asyncHandler (see helpers.js). Without this, an
// uncaught error in a route just returns nothing to the client and the
// process may still crash on the underlying unhandled rejection below —
// this middleware turns it into a clean JSON 500 instead.
app.use((err, req, res, next) => {
  console.error('Unhandled route error:', err);
  if (res.headersSent) return next(err);
  res.status(500).json({ error: 'server_error' });
});

// Last-resort safety net: if something *still* throws outside of Express's
// request/response cycle (e.g. a stray unawaited promise), log it instead
// of letting Node's default behavior kill the whole process — so one bad
// request can no longer take down every other user's session.
process.on('unhandledRejection', (reason) => {
  console.error('UNHANDLED REJECTION (server stayed up):', reason);
});
process.on('uncaughtException', (err) => {
  console.error('UNCAUGHT EXCEPTION (server stayed up):', err);
});

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
