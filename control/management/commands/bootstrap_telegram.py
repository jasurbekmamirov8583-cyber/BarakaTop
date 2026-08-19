from django.conf import settings
from django.core.management.base import BaseCommand

from control.telegram import TelegramAPIError, configure_bot


class Command(BaseCommand):
    help = "Configure the Telegram webhook without blocking service startup"

    def handle(self, *args, **options):
        if not settings.TELEGRAM_BOT_TOKEN:
            self.stdout.write("TELEGRAM_BOT_TOKEN is not set; Telegram bootstrap skipped.")
            return
        if not settings.TELEGRAM_WEBHOOK_SECRET:
            self.stderr.write(self.style.WARNING("TELEGRAM_WEBHOOK_SECRET is not set; Telegram bootstrap skipped."))
            return
        if not settings.PUBLIC_BASE_URL.startswith("https://"):
            self.stderr.write(self.style.WARNING("PUBLIC_BASE_URL must use HTTPS; Telegram bootstrap skipped."))
            return
        try:
            result = configure_bot()
            info = result.get("webhook_info") or {}
            self.stdout.write(self.style.SUCCESS(
                f"Telegram bot @{result['username'] or 'unknown'} webhook configured: {info.get('url', 'unknown URL')}"
            ))
            if info.get("last_error_message"):
                self.stderr.write(self.style.WARNING(f"Telegram last webhook error: {info['last_error_message']}"))
        except TelegramAPIError as exc:
            self.stderr.write(self.style.WARNING(f"Telegram bootstrap skipped: {exc}"))
