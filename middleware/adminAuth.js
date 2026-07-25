// Protects the /admin/* routes with a shared secret.
// The frontend console sends this in the X-Admin-Key header.
// Never expose ADMIN_KEY in client-side code shipped to end users —
// only the console you (the operator) use should hold it.
function adminAuth(req, res, next) {
  const provided = req.header('X-Admin-Key');
  const expected = process.env.ADMIN_KEY;

  if (!expected) {
    return res.status(500).json({ error: 'Server misconfigured: ADMIN_KEY not set' });
  }
  if (!provided || provided !== expected) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  next();
}

module.exports = adminAuth;
