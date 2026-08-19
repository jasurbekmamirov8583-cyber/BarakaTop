# BarakaTop Control Plane

The control plane is a separate online application for Render + Supabase. It stores only control metadata: shops and device limits, Telegram administrators, one-time activation-key/password hashes, allowed IP/CIDR ranges, device status/mode/permissions, alert rules, and audit events. POS products, receipts, stock, customers, and report results remain on the shop computer.

Live reports use an in-memory WebSocket relay:

```text
Telegram Mini App ⇄ Render ASGI relay ⇄ outbound BarakaTop desktop agent ⇄ local database
```

Report payloads are never inserted into Supabase. If either endpoint disconnects, the request expires and must be retried.

## Environment

Copy `.env.example` values into Render environment variables. Use the Supabase **Session Pooler** connection string on port 5432 for the persistent Render service. Run migrations, then create the first superuser with the one-time `BOOTSTRAP_ADMIN_*` variables and `python manage.py bootstrap_admin`.

`BOOTSTRAP_ADMIN_PASSWORD` accepts passwords from 4 characters, although 8 or more is strongly recommended. Invalid or missing bootstrap credentials are reported in the deploy log without stopping Gunicorn, so configuration mistakes cannot take the entire service offline. An existing superadmin password is never changed automatically.

Render's `RENDER_EXTERNAL_URL` and `RENDER_EXTERNAL_HOSTNAME` values are detected automatically for `PUBLIC_BASE_URL`, `ALLOWED_HOSTS`, CSRF, Telegram links, and WebSocket origin checks. Explicit environment values can still add a custom domain. To recover an existing superadmin password, temporarily set `BOOTSTRAP_ADMIN_RESET_PASSWORD=1` for one deploy, then set it back to `0`.

`SUPERADMIN_TOTP_SECRET` is optional. Leave it empty to use superadmin login and password only. To enable 2FA, set a private Base32 secret of at least 16 characters and add the same secret manually to an authenticator application under the account name `BarakaTop`. Never commit that secret to GitHub.

This directory is a complete, standalone GitHub/Render application. Create a repository whose root contains these files (including this directory's `render.yaml`), then create a Render Blueprint from that repository. Do not upload the local POS source code to that repository.

After the environment variables are set, open the super-admin dashboard and press **Telegramni sozlash**. That action registers both the signed webhook and the Mini App menu button through Telegram's Bot API.

Never expose `TELEGRAM_BOT_TOKEN`, `DATABASE_URL`, or `DJANGO_SECRET_KEY` to frontend JavaScript.

Render Free can sleep after inactivity. The desktop relay heartbeat keeps an active connection awake, but after a restart or deploy the desktop and Telegram Mini App reconnect automatically; in-flight live report requests are intentionally not stored.
