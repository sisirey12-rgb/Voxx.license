// Protects EVERY /admin/* route (including /admin/login) with a shared
// secret — the first of two locks. The second lock is the normal
// username+password(+TOTP) login in auth.js, which only runs after this
// middleware passes. The frontend console sends this key in the
// X-Admin-Key header. Never expose ADMIN_KEY in client-side code shipped
// to end users — only the console you (the operator) use should hold it.
const { logAction, getClientIp } = require('./security');

function adminAuth(req, res, next) {
  const provided = req.header('X-Admin-Key');
  const expected = process.env.ADMIN_KEY;

  if (!expected) {
    return res.status(500).json({ error: 'Server misconfigured: ADMIN_KEY not set' });
  }
  if (!provided || provided !== expected) {
    logAction({
      action: 'admin_key_fail',
      ip: getClientIp(req),
      userAgent: req.headers['user-agent'],
      details: { path: req.originalUrl },
    }).catch(() => {}); // never let logging break the rejection response
    return res.status(401).json({ error: 'Unauthorized' });
  }
  next();
}

module.exports = adminAuth;
