# 🔐 VOXX License Server

A lightweight backend API for managing APK license keys — generate, activate, validate, reset HWID, extend, regenerate, and revoke, all from a single service.

![Node](https://img.shields.io/badge/node-%3E%3D16-brightgreen)
![Status](https://img.shields.io/badge/status-active-success)
![License](https://img.shields.io/badge/license-private-lightgrey)

---

## ✨ Features

- 🔑 Generate and manage license keys with configurable validity and device limits
- 📱 Bind licenses to a device via hardware ID (HWID) on first activation
- ✅ Fast validation endpoint for on-launch checks
- 🔄 Reset, extend, regenerate, or revoke keys as needed
- 🛡️ Admin routes protected by a single shared secret key

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

---

## 🔒 Security Notes

- Keep your `ADMIN_KEY` secret and out of version control (`.env` is gitignored).
- Use a long, random value for `ADMIN_KEY` — treat it like a password.
- Consider putting this service behind HTTPS before exposing it publicly.

---

## 🛠️ Tech Stack

- **Runtime:** Node.js
- **Distribution:** Single-service REST API, easy to self-host

---

## 📄 License

Private / internal use.
