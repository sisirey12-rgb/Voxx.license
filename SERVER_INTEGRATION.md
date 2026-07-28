# Wiring this into server.js

## 1. Install new dependencies
```
npm install bcrypt cookie-parser speakeasy qrcode
```

## 2. In server.js, near the top (after `const express = require('express')`):
```js
const cookieParser = require('cookie-parser');
const authRoutes = require('./routes/auth');
const { requireSession } = require('./middleware/authSession');
const { logAction, getClientIp } = require('./middleware/security');

app.set('trust proxy', 1); // needed on Render/Railway/Fly so req.ip is the real client IP
app.use(cookieParser());
```

## 3. Restrict CORS to your actual frontend domain (your README already flags this —
now it's required, since cookies need a known origin):
```js
app.use(cors({
  origin: 'https://your-frontend.netlify.app',
  credentials: true, // required so the browser sends/receives the session cookie
}));
```

## 4. Mount the auth routes (public — no session required to reach /login):
```js
app.use('/admin', authRoutes);
```

## 5. Protect your existing /admin/* routes with the session middleware
instead of (or in addition to) the old X-Admin-Key check. Wherever you
currently have something like:
```js
router.use(checkAdminKey); // old middleware
```
replace or supplement it with:
```js
router.use(requireSession);
```
Do this for every existing admin route file (generate-key, revoke, reset-hwid,
extend, regenerate, keys, resellers, topups, delete-key). If those live in
`routes/`, just add `requireSession` to each router, or apply it once where
they're mounted in server.js, e.g.:
```js
app.use('/admin', requireSession, adminKeysRouter);
```
(Keep `/admin/login` mounted separately, before this line, so login itself
isn't blocked by the session check it's trying to create.)

## 6. Add audit logging to your existing key-management routes
In each handler (generate-key, revoke, reset-hwid, extend, regenerate,
delete-key), after the action succeeds, add:
```js
await logAction({
  adminId: req.adminId,
  action: 'key_create', // or 'key_revoke', etc.
  ip: getClientIp(req),
  userAgent: req.headers['user-agent'],
  details: { license_key: key },
});
```

## 7. Run the migration
```
turso db shell <your-db-name> < sql/002_auth_security.sql
```
or execute the statements manually if you have a different way of running
SQL against your Turso DB.

## 8. Create your admin account
```
node create-admin.js youradminname "a long random password"
```

## 9. Remove ADMIN_KEY from the frontend entirely
Once this is live, the browser should never hold or send ADMIN_KEY again —
only the session cookie. You can keep ADMIN_KEY server-side as a break-glass
option if you want, but it should no longer travel to the browser or
localStorage. See frontend-login-snippet.html for the replacement UI.
