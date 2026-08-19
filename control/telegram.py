from __future__ import annotations

import json
import urllib.error
import urllib.request
from html import escape

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


def send_text(chat_id: int, text: str, *, reply_markup=None, parse_mode=None):
    payload = {"chat_id": chat_id, "text": text, "disable_web_page_preview": True}
    if reply_markup:
        payload["reply_markup"] = reply_markup
    if parse_mode:
        payload["parse_mode"] = parse_mode
    return bot_call("sendMessage", payload)


def webapp_url(*, section="reports", report="overview"):
    return f"{settings.PUBLIC_BASE_URL}/app/?section={section}&report={report}"


def main_menu_markup():
    return {
        "inline_keyboard": [
            [{"text": "📊 Jonli hisobotlar", "web_app": {"url": webapp_url()}}],
            [
                {"text": "🏪 Do‘konlarim", "callback_data": "stores"},
                {"text": "🆔 Mening ID", "callback_data": "my_id"},
            ],
            [{"text": "❓ Yordam", "callback_data": "help"}],
        ]
    }


def send_webapp_button(chat_id: int):
    return send_text(
        chat_id,
        "👋 <b>BarakaTop boshqaruviga xush kelibsiz!</b>\n\n"
        "📈 Jonli savdo hisobotlari\n🧑‍💼 Sotuvchilar\n📦 Ombor va qurilmalar\n⚙️ Do‘kon sozlamalari",
        reply_markup=main_menu_markup(),
        parse_mode="HTML",
    )


def send_report_menu(chat_id: int):
    rows = [
        [("📈 Bugungi savdo", "overview"), ("🧾 Kunlik", "sales_daily")],
        [("🏆 Top mahsulotlar", "top_products"), ("💳 To‘lovlar", "payment_mix")],
        [("👥 Sotuvchilar", "cashier_summary"), ("📦 Kam qoldiq", "low_stock")],
    ]
    markup = {
        "inline_keyboard": [
            [{"text": label, "web_app": {"url": webapp_url(report=report)}} for label, report in row]
            for row in rows
        ]
    }
    return send_text(chat_id, "📊 <b>Kerakli hisobotni tanlang:</b>", reply_markup=markup, parse_mode="HTML")


def answer_callback(callback_id: str, text=""):
    return bot_call("answerCallbackQuery", {"callback_query_id": callback_id, "text": text[:180]})


def sanitize_sale_notification_payload(payload: dict) -> dict:
    """Allow only receipt fields needed for the transient Telegram message."""
    payload = payload if isinstance(payload, dict) else {}
    scalar_limits = {
        "number": 80, "cashier": 160, "customer": 160,
        "currency": 12, "discount": 40, "total": 40,
    }
    sanitized = {
        key: str(payload.get(key, ""))[:limit]
        for key, limit in scalar_limits.items()
        if key in payload
    }
    sanitized["items"] = [
        {
            "name": str(item.get("name", ""))[:160],
            "quantity": str(item.get("quantity", ""))[:40],
            "unit": str(item.get("unit", ""))[:24],
            "total": str(item.get("total", ""))[:40],
        }
        for item in list(payload.get("items") or [])[:100]
        if isinstance(item, dict)
    ]
    sanitized["payments"] = [
        {
            "method": str(row.get("method", ""))[:40],
            "amount": str(row.get("amount", ""))[:40],
        }
        for row in list(payload.get("payments") or [])[:20]
        if isinstance(row, dict)
    ]
    return sanitized


def send_sale_notification(chat_id: int, store_name: str, payload: dict):
    payload = sanitize_sale_notification_payload(payload)
    items = list(payload.get("items") or [])
    item_lines = [
        f"  • {escape(str(item.get('name', ''))[:80])} — {escape(str(item.get('quantity', '')))} "
        f"{escape(str(item.get('unit', '')))} · {escape(str(item.get('total', '')))}"
        for item in items[:12]
    ]
    if len(items) > 12:
        item_lines.append(f"  … yana {len(items) - 12} ta mahsulot")
    payment_lines = [
        f"  • {escape(str(row.get('method', '')))}: {escape(str(row.get('amount', '')))}"
        for row in list(payload.get("payments") or [])[:8]
    ]
    currency = escape(str(payload.get("currency", "UZS")))
    text = "\n".join(
        [
            "🧾 <b>YANGI SAVDO</b>",
            f"🏪 <b>{escape(store_name)}</b>",
            f"🔢 Chek: <code>{escape(str(payload.get('number', '')))}</code>",
            f"👤 Kassir: {escape(str(payload.get('cashier', '—')))}",
            f"🧑 Mijoz: {escape(str(payload.get('customer', 'Oddiy mijoz')))}",
            "",
            "🛒 <b>Mahsulotlar:</b>",
            *(item_lines or ["  • Tafsilot mavjud emas"]),
            "",
            "💳 <b>To‘lov:</b>",
            *(payment_lines or ["  • Tafsilot mavjud emas"]),
            "",
            f"🏷 Chegirma: {escape(str(payload.get('discount', '0')))} {currency}",
            f"💰 <b>JAMI: {escape(str(payload.get('total', '0')))} {currency}</b>",
        ]
    )
    return send_text(chat_id, text, reply_markup=main_menu_markup(), parse_mode="HTML")


def send_alert(chat_id: int, store_name: str, text: str):
    return bot_call("sendMessage", {"chat_id": chat_id, "text": f"⚠️ {store_name}\n\n{text}", "disable_web_page_preview": True})


def configure_bot():
    profile = bot_call("getMe")
    webhook = bot_call("setWebhook", {
        "url": f"{settings.PUBLIC_BASE_URL}/telegram/webhook/",
        "secret_token": settings.TELEGRAM_WEBHOOK_SECRET,
        "allowed_updates": ["message", "callback_query"],
    })
    bot_call("setMyCommands", {"commands": [
        {"command": "start", "description": "BarakaTop boshqaruvini ochish"},
        {"command": "app", "description": "Do‘kon web-ilovasini ochish"},
        {"command": "id", "description": "Telegram ID raqamini ko‘rish"},
        {"command": "reports", "description": "Jonli hisobotlarni ochish"},
        {"command": "help", "description": "Yordam"},
    ]})
    menu = bot_call("setChatMenuButton", {
        "menu_button": {"type": "web_app", "text": "Do‘kon boshqaruvi", "web_app": {"url": f"{settings.PUBLIC_BASE_URL}/app/"}},
    })
    webhook_info = bot_call("getWebhookInfo")
    return {"username": profile.get("username", ""), "webhook": webhook, "menu": menu, "webhook_info": webhook_info}
