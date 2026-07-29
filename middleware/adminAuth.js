// NOT CURRENTLY WIRED INTO server.js. Left here only as an optional
// break-glass tool if you ever want to protect a specific route with the
// static ADMIN_KEY in addition to a session — e.g. an emergency endpoint.
// The regular /admin/* routes now rely solely on the session cookie
// (middleware/authSession.js); ADMIN_KEY itself never travels to the
// browser and is only ever typed manually into POST /setup-admin.
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
