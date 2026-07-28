# VOXX Admin Panel (PHP)

A PHP front-end for your VOXX license server (Render/Node API + Turso). Calls
your existing `/admin/*` endpoints using `X-Admin-Key`, same as documented in
your server's README.

## Setup

1. Upload this folder to any PHP host (shared hosting, a VPS, etc. — needs
   PHP 7.4+ with the `curl` extension, which almost all hosts have).
2. Generate your panel login password hash:
   ```
   php generate_password_hash.php
   ```
3. Set these as environment variables on your host (preferred), or edit
   `config.php` directly:
   - `VOXX_API_BASE_URL` — your Render URL, e.g. `https://voxx-license.onrender.com`
   - `VOXX_ADMIN_KEY` — the same `ADMIN_KEY` your Node server uses
   - `VOXX_PANEL_PASSWORD_HASH` — output from step 2
4. Make sure `data/` is writable by the web server (`chmod 700 data`).
5. Visit `login.php`, log in, and you're in.

## Why a separate panel password?

Your Node server's `ADMIN_KEY` is the master key — it never touches the
browser and lives only in `config.php`/env vars on the PHP host. The panel
login password is a second, independent secret you type in to reach the
panel at all. If one leaks, the other still protects you.

## Security features already built in

- Panel password stored as a bcrypt hash (`password_hash`/`password_verify`),
  never in plaintext
- Login attempts rate-limited: 5 tries, then a 15-minute lockout per IP
- CSRF tokens on every form (login + all key actions)
- Session cookies are `HttpOnly`, `SameSite=Strict`, and `Secure` over HTTPS
- 30-minute idle auto-logout
- `ADMIN_KEY` and config never sent to the browser — only used server-side
  via cURL
- `.htaccess` blocks direct access to `config.php`, `includes/`, and `data/`,
  and forces HTTPS
- Security headers (`X-Frame-Options`, `X-Content-Type-Options`, no-referrer)

## Things you still need to do yourself

- **Restrict CORS on your Render API** to just this panel's domain (and your
  Netlify frontend), per the note already in your server's README.
- **Use HTTPS** on wherever you host this panel — session cookies rely on it.
- Consider adding **IP allowlisting** at the host/firewall level if you're
  the only one who should ever reach this panel (Cloudflare Access or your
  host's firewall rules both work well for this).
- Rotate `ADMIN_KEY` and the panel password periodically, and immediately if
  you ever suspect either leaked.
- If you deploy on shared hosting, verify `data/` truly isn't web-reachable
  (`https://yoursite/admin/data/login_attempts.json` should 403).
