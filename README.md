# VOXX License Server

Backend API for APK license key management: generate, activate, validate,
reset HWID, extend, regenerate, and revoke keys.

## Local setup

```bash
npm install
cp .env.example .env
# edit .env and set ADMIN_KEY to a long random string
npm start
```

Server runs on `http://localhost:3000` by default.

## Endpoints

### Public (called by your Android app — no admin key needed)
- `POST /api/activate` — body `{ license_key, hwid }`. Binds the device on first use.
- `POST /api/validate` — body `{ license_key, hwid }`. Call on every app launch.

### Admin (require header `X-Admin-Key: <your ADMIN_KEY>`)
- `GET /admin/keys` — list all keys
- `POST /admin/generate-key` — body `{ validity_days, max_devices, label }`
- `POST /admin/reset-hwid` — body `{ license_key }`
- `POST /admin/extend` — body `{ license_key, days }`
- `POST /admin/regenerate` — body `{ license_key }`
- `POST /admin/revoke` — body `{ license_key }`

## Deploying (Render — free tier)

1. Push this folder to a GitHub repo.
2. On [render.com](https://render.com), New → Web Service → connect the repo.
3. Build command: `npm install`. Start command: `npm start`.
4. Add environment variable `ADMIN_KEY` (same random string as your `.env`).
5. Add a **persistent disk** mounted at `/opt/render/project/src` (or wherever
   the repo lives) so `licenses.db` survives restarts/deploys — SQLite is a
   single file and Render's default filesystem is ephemeral otherwise.
6. Deploy. Your API is now live at `https://your-service.onrender.com`.

Railway and Fly.io work the same way — just make sure you attach persistent
storage for `licenses.db`, or swap `db.js` to Postgres if you outgrow SQLite
(multiple server instances, high write volume, etc).

## Connecting the frontend (Netlify)

Deploy `voxx-license-server-frontend.html` (in the parent folder) to Netlify
as-is — it's a static file with no build step. Open it, click **Server**,
and enter:
- API base URL: `https://your-service.onrender.com`
- Admin key: the same `ADMIN_KEY` value

It's saved in your browser's local storage from then on.

## Connecting the Android app

In your activation screen, POST to `/api/activate` with the entered key and
the device's HWID. On every app launch, POST to `/api/validate`. See the
earlier conversation for the Kotlin client code — it points at whatever
`API_BASE_URL` you deploy this to.

## Notes

- CORS is wide open (`cors()`) by default — restrict it to your Netlify
  domain in `server.js` once you're live.
- `max_devices` is enforced: activation is rejected once the limit is hit,
  until you reset HWID or extend the limit.
- Never ship `ADMIN_KEY` inside the Android APK — only the frontend console
  you personally use should hold it.
