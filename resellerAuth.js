const { db } = require('../db');

// Protects /reseller/* routes with a per-partner token.
// The partner's dashboard sends this in the X-Reseller-Token header.
// This is intentionally separate from ADMIN_KEY — a reseller token can only
// ever touch their own balance and their own generated keys.
async function resellerAuth(req, res, next) {
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
}

module.exports = resellerAuth;
