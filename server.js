require('dotenv').config();
const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');

const { init } = require('./db');
const adminRoutes = require('./routes/admin');
const licenseRoutes = require('./routes/license');
const resellerRoutes = require('./routes/reseller');

const app = express();

app.use(cors({
  origin: 'https://YOUR-NETLIFY-SITE.netlify.app', // replace with your Netlify URL
  credentials: true,
}));

app.use(cookieParser());
app.use(express.json());

app.get('/', (req, res) => {
  res.json({ ok: true, service: 'voxx-license-server' });
});

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
