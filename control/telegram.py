from __future__ import annotations

import json
import urllib.request

from django.conf import settings


def bot_call(method: str, payload: dict):
    if not settings.TELEGRAM_BOT_TOKEN:
        return None
    request = urllib.request.Request(
        f"https://api.telegram.org/bot{settings.TELEGRAM_BOT_TOKEN}/{method}",
        data=json.dumps(payload).encode(), headers={"Content-Type": "application/json"}, method="POST",
    )
    with urllib.request.urlopen(request, timeout=12) as response:
        return json.loads(response.read())


def send_webapp_button(chat_id: int):
    return bot_call("sendMessage", {
        "chat_id": chat_id,
        "text": "BarakaTop boshqaruv paneliga xush kelibsiz. Do‘kon hisobotlarini ochish uchun tugmani bosing.",
        "reply_markup": {"inline_keyboard": [[{"text": "📊 Do‘kon boshqaruvi", "web_app": {"url": f"{settings.PUBLIC_BASE_URL}/app/"}}]]},
    })


def send_alert(chat_id: int, store_name: str, text: str):
    return bot_call("sendMessage", {"chat_id": chat_id, "text": f"⚠️ {store_name}\n\n{text}", "disable_web_page_preview": True})


def configure_bot():
    webhook = bot_call("setWebhook", {
        "url": f"{settings.PUBLIC_BASE_URL}/telegram/webhook/",
        "secret_token": settings.TELEGRAM_WEBHOOK_SECRET,
        "allowed_updates": ["message"],
    })
    menu = bot_call("setChatMenuButton", {
        "menu_button": {"type": "web_app", "text": "Do‘kon boshqaruvi", "web_app": {"url": f"{settings.PUBLIC_BASE_URL}/app/"}},
    })
    return webhook, menu
