# BarakaTop Control Plane

The control plane is a separate online application for Render + Supabase. It stores only control metadata: shops and device limits, Telegram administrators, one-time activation-key/password hashes, allowed IP/CIDR ranges, device status/mode/permissions, alert rules, and audit events. POS products, receipts, stock, customers, and report results remain on the shop computer.

Live reports use an in-memory WebSocket relay:

```text
Telegram Mini App ⇄ Render ASGI relay ⇄ outbound BarakaTop desktop agent ⇄ local database
```

Report payloads are never inserted into Supabase. If either endpoint disconnects, the request expires and must be retried.

## Environment

Copy `.env.example` values into Render environment variables. Use the Supabase **Session Pooler** connection string on port 5432 for the persistent Render service. Run migrations, then create the first superuser with the one-time `BOOTSTRAP_ADMIN_*` variables and `python manage.py bootstrap_admin`.

Deploy from this folder with `render.yaml`. After the environment variables are set, open the super-admin dashboard and press **Telegramni sozlash**. That action registers both the signed webhook and the Mini App menu button through Telegram's Bot API.

Never expose `TELEGRAM_BOT_TOKEN`, `DATABASE_URL`, or `DJANGO_SECRET_KEY` to frontend JavaScript.
