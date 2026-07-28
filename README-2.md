# VOXX admin security add-on

Drop these into your existing Voxx.license repo, keeping the folder structure:

```
sql/002_auth_security.sql       → run once against your Turso DB
create-admin.js                 → run once to create your login (node create-admin.js user pass)
middleware/security.js          → lockout tracking (username + IP) + audit log helper
middleware/authSession.js       → session cookie creation/validation (15-min sliding expiry)
routes/auth.js                  → /admin/login, /admin/logout, /admin/session, /admin/2fa/*
SERVER_INTEGRATION.md           → exact server.js changes needed
frontend-login-snippet.html     → login screen + updated apiCall() for index.html
```

Order of operations:
1. `npm install bcrypt cookie-parser speakeasy qrcode`
2. Run the SQL migration against your Turso DB
3. Copy the 3 new JS files into your repo at the paths shown above
4. Follow SERVER_INTEGRATION.md to wire server.js
5. `node create-admin.js <username> <password>` to create your login
6. Merge frontend-login-snippet.html into index.html per the comments at its top
7. Deploy, then delete/rotate the old ADMIN_KEY usage from the browser side

What you get:
- bcrypt password login, no more raw admin key in the browser
- 5 wrong attempts → 1-hour lockout, tracked by username AND by IP independently,
  so rotating one doesn't bypass the other
- Optional TOTP 2FA (Google Authenticator / Authy compatible)
- Audit log of login, logout, 2FA changes, and (once you add the one-line calls
  shown in SERVER_INTEGRATION.md) key create/revoke actions
- HttpOnly + Secure + SameSite=Strict session cookie, 15-minute sliding expiry
