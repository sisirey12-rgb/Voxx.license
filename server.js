require('dotenv').config();
const express = require('express');
const cors = require('cors');

const { init } = require('./db');
const adminRoutes = require('./routes/admin');
const licenseRoutes = require('./routes/license');

const app = express();
app.use(cors()); // tighten with { origin: 'https://your-netlify-site.netlify.app' } once deployed
app.use(express.json());

app.get('/', (req, res) => {
  res.json({ ok: true, service: 'voxx-license-server' });
});

app.use('/admin', adminRoutes);
app.use('/api', licenseRoutes);

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
