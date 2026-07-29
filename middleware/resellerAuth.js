const { db } = require('../db');

async function resellerAuth(req, res, next) {
  try {
    const provided = req.header('X-Reseller-Token');
    if (!provided) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const result = await db.execute({
      sql: 'SELECT * FROM resellers WHERE token = ?',
      args: [provided],
    });
    const reseller = result.rows[0];

    if (!reseller) {
      return res.status(401).json({ error: 'Unauthorized' });
    }
    if (reseller.status !== 'active') {
      return res.status(403).json({ error: 'Reseller account is not active' });
    }

    req.reseller = reseller;
    next();
  } catch (e) {
    console.error('resellerAuth error:', e.message);
    res.status(500).json({ error: 'server_error' });
  }
}

module.exports = resellerAuth;
