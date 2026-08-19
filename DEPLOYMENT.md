# Render + Supabase + Telegram deployment

1. Create a Supabase Free project and save the database password safely.
2. In **Connect**, copy the Shared Pooler **session mode** URL on port 5432. Use it as Render's `DATABASE_URL`.
3. Upload only the contents of `web_control/` to a separate GitHub repository. Its `render.yaml` must be at the repository root, then create a Render Blueprint from that repository.
4. Add every variable from `.env.example`. `PUBLIC_BASE_URL` must be the final HTTPS Render URL without a trailing slash. `SUPERADMIN_TOTP_SECRET` is optional: leave it empty for login-password access, or set a private Base32 secret of at least 16 characters to enable authenticator 2FA.
5. Deploy. The build installs dependencies and collects static assets. Each service start safely applies migrations, creates the first superuser once, then launches Uvicorn/ASGI.
6. Log in at `/panel/login/`. Immediately rotate/remove `BOOTSTRAP_ADMIN_PASSWORD` from Render after verifying the first login; existing passwords are never overwritten by later deploys.
7. In BotFather create a bot. Put its token in `TELEGRAM_BOT_TOKEN`.
8. Open `/panel/` and click **Telegramni sozlash**. The server registers the signed webhook and the default Mini App menu button through the Bot API.
9. Create a shop, set its maximum device count, add the owner's numeric Telegram ID, choose the report/alert scopes, then generate an activation account. Copy the one-time key or login/password before leaving the page.
10. Put the final Render URL into `desktop/orbit-config.json`, set `cloud_required` to `true`, and build the installer. Give the one-time enrollment values to the shop operator.

For public-IP changes, the device becomes unauthorized. Open the pending/blocked device in the super-admin panel, review the newly observed IP and approve a precise `/32` or a carefully chosen ISP CIDR. Avoid broad ranges such as `0.0.0.0/0`.

Use the owner/server workstation as the reporting source when a store has multiple installations. The Mini App allows the owner to select another active device explicitly. Statistics are never merged or copied into Supabase.
