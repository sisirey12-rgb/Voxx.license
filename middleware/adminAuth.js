// Protects the license/reseller/topup data routes (routes/admin.js) with a
// shared secret — the second lock, checked only after a session already
// exists from a normal username+password login. Does NOT guard
// /admin/login, /admin/logout, /admin/session, or /admin/2fa/* — those are
// plain session-based and never require this key. The frontend console
// sends this key in the X-Admin-Key header. Never expose ADMIN_KEY in
// client-side code shipped to end users — only the console you (the
// operator) use should hold it.
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
