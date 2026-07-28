# 🔐 VOXX License Server

A lightweight backend API for managing APK license keys — generate, activate, validate, reset HWID, extend, regenerate, and revoke, all from a single service.

![Node](https://img.shields.io/badge/node-%3E%3D16-brightgreen)
![Status](https://img.shields.io/badge/status-active-success)
![License](https://img.shields.io/badge/license-private-lightgrey)

---
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

## ✨ Features

- 🔑 Generate and manage license keys with configurable validity and device limits
- 📱 Bind licenses to a device via hardware ID (HWID) on first activation
- ✅ Fast validation endpoint for on-launch checks
- 🔄 Reset, extend, regenerate, or revoke keys as needed
- 🛡️ Admin routes protected by a single shared secret key
- 🤝 Reseller portal with per-partner tokens, credit balances, and tiered pricing

---

## 🚀 Quick Start

```bash
npm install
cp .env.example .env
# edit .env and set ADMIN_KEY to a long random string
npm start
```

The server runs on **`http://localhost:3000`** by default.

---

## 📡 API Reference

### Public endpoints
*Called by your Android app — no admin key required.*

| Method | Endpoint | Body | Description |
|--------|----------|------|-------------|
| `POST` | `/api/activate` | `{ license_key, hwid }` | Binds the license to a device on first use |
| `POST` | `/api/validate` | `{ license_key, hwid }` | Call on every app launch to confirm the license is valid |

### Admin endpoints
*Require the header* `X-Admin-Key: <your ADMIN_KEY>`

| Method | Endpoint | Body | Description |
|--------|----------|------|-------------|
| `GET`  | `/admin/keys` | — | List all license keys |
| `POST` | `/admin/generate-key` | `{ validity_days, max_devices, label }` | Create a new license key |
| `POST` | `/admin/reset-hwid` | `{ license_key }` | Unbind a key from its device |

> More admin routes (extend, regenerate, revoke) follow the same pattern — see `Code` tab for the full list.

### Reseller endpoints
*Require the header* `X-Reseller-Token: <partner's token>`

Resellers can generate keys against their own credit balance without needing admin access. Each token maps to a single partner account and can only see or spend that partner's own credits and keys.

| Method | Endpoint | Body | Description |
|--------|----------|------|-------------|
| `GET`  | `/reseller/me` | — | Returns the partner's name, credit balance, and account status |
| `GET`  | `/reseller/pricing` | — | Returns the live duration → credit-cost table |
| `POST` | `/reseller/generate-key` | `{ validity_days, max_devices, label }` | Generates a key against the reseller's credit balance |
| `GET`  | `/reseller/sales` | — | Lists all keys the partner has generated |
| `POST` | `/reseller/topup-request` | `{ amount, note }` | Submits a credit top-up request for admin approval |
| `GET`  | `/reseller/topups` | — | Lists the partner's own top-up request history |

**Credit pricing tiers** (day → credits):

| Validity | Cost (credits) |
|----------|-----------------|
| 1 day    | 0.5 |
| 3 days   | 1.0 |
| 7 days   | 2.0 |
| 15 days  | 3.5 |
| 30 days  | 6.0 |

> `validity_days` must match one of the tiers above — arbitrary durations are rejected so pricing can't be bypassed. Unlike the admin route, resellers can't set a custom key string; all reseller-generated keys use the standard format.

---

## 🔒 Security Notes

- Keep your `ADMIN_KEY` secret and out of version control (`.env` is gitignored).
- Use a long, random value for `ADMIN_KEY` — treat it like a password.
- Reseller tokens (`X-Reseller-Token`) are separate from `ADMIN_KEY` and scope each partner strictly to their own balance and keys.
- Consider putting this service behind HTTPS before exposing it publicly.

---

## 🛠️ Tech Stack

- **Runtime:** Node.js
- **Distribution:** Single-service REST API, easy to self-host

---

## 📄 License

Private / internal use.
