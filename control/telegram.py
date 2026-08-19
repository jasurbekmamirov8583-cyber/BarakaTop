from __future__ import annotations

import json
import urllib.error
import urllib.request

from django.conf import settings


class TelegramAPIError(RuntimeError):
    pass


def bot_call(method: str, payload: dict | None = None):
    if not settings.TELEGRAM_BOT_TOKEN:
        raise TelegramAPIError("TELEGRAM_BOT_TOKEN kiritilmagan.")
    request = urllib.request.Request(
        f"https://api.telegram.org/bot{settings.TELEGRAM_BOT_TOKEN}/{method}",
        data=json.dumps(payload or {}).encode(), headers={"Content-Type": "application/json"}, method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            result = json.loads(response.read())
    except urllib.error.HTTPError as exc:
        try:
            description = json.loads(exc.read()).get("description", "Telegram API xatosi")
        except (json.JSONDecodeError, AttributeError):
            description = "Telegram API xatosi"
        raise TelegramAPIError(description) from exc
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        raise TelegramAPIError("Telegram serveriga ulanib bo‘lmadi.") from exc
    if not result.get("ok"):
        raise TelegramAPIError(result.get("description", "Telegram API so‘rovni qabul qilmadi."))
    return result.get("result")


def send_text(chat_id: int, text: str):
    return bot_call("sendMessage", {"chat_id": chat_id, "text": text, "disable_web_page_preview": True})


def send_webapp_button(chat_id: int):
    return bot_call("sendMessage", {
        "chat_id": chat_id,
        "text": "BarakaTop boshqaruv paneliga xush kelibsiz!\n\nDo‘kon qurilmalari, sotuvchilar va jonli hisobotlarni ochish uchun quyidagi tugmani bosing.",
        "reply_markup": {"inline_keyboard": [[{"text": "📊 Do‘kon boshqaruvini ochish", "web_app": {"url": f"{settings.PUBLIC_BASE_URL}/app/"}}]]},
    })


def send_alert(chat_id: int, store_name: str, text: str):
    return bot_call("sendMessage", {"chat_id": chat_id, "text": f"⚠️ {store_name}\n\n{text}", "disable_web_page_preview": True})


def configure_bot():
    profile = bot_call("getMe")
    webhook = bot_call("setWebhook", {
        "url": f"{settings.PUBLIC_BASE_URL}/telegram/webhook/",
        "secret_token": settings.TELEGRAM_WEBHOOK_SECRET,
        "allowed_updates": ["message"],
    })
    bot_call("setMyCommands", {"commands": [
        {"command": "start", "description": "BarakaTop boshqaruvini ochish"},
        {"command": "app", "description": "Do‘kon web-ilovasini ochish"},
        {"command": "id", "description": "Telegram ID raqamini ko‘rish"},
        {"command": "help", "description": "Yordam"},
    ]})
    menu = bot_call("setChatMenuButton", {
        "menu_button": {"type": "web_app", "text": "Do‘kon boshqaruvi", "web_app": {"url": f"{settings.PUBLIC_BASE_URL}/app/"}},
    })
    webhook_info = bot_call("getWebhookInfo")
    return {"username": profile.get("username", ""), "webhook": webhook, "menu": menu, "webhook_info": webhook_info}
