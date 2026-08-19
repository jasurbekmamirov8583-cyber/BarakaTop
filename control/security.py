from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import json
import logging
import secrets
import time
from datetime import timedelta
from urllib.parse import parse_qsl, urlsplit

from django.conf import settings
from django.core import signing
from django.core.exceptions import PermissionDenied, ValidationError
from django.db import transaction
from django.utils import timezone

log = logging.getLogger("control.telegram_auth")


class TelegramInitDataError(PermissionDenied):
    def __init__(self, message: str, code: str):
        super().__init__(message)
        self.code = code


def client_ip(request) -> str:
    forwarded = request.META.get("HTTP_X_FORWARDED_FOR", "")
    # Render appends the actual peer to X-Forwarded-For. Taking the last hop
    # prevents a client-supplied first value from bypassing IP restrictions.
    return (forwarded.split(",")[-1].strip() if forwarded else request.META.get("REMOTE_ADDR", "")) or "127.0.0.1"


def signed_device_lease(token: str, device) -> tuple[dict, str]:
    now = int(time.time())
    other_devices = list(device.store.devices.exclude(status="revoked").exclude(pk=device.pk).only("lan_clients"))
    other_slots = len(other_devices) + sum(len(item.lan_clients or []) for item in other_devices)
    max_lan_clients = max(0, int(device.store.max_devices) - 1 - other_slots)
    payload = {
        "device_id": str(device.pk),
        "store_id": str(device.store_id),
        "status": device.status,
        "mode": device.mode,
        "permissions": list(device.permissions or []),
        "features": list(device.store.active_features),
        "timezone": device.store.timezone,
        "session_unlimited": bool(device.store.pos_session_unlimited),
        "session_expires_on": (
            device.store.pos_session_expires_on.isoformat()
            if device.store.pos_session_expires_on else None
        ),
        "max_devices": device.store.max_devices,
        "max_lan_clients": max_lan_clients,
        "issued_at": now,
        "expires_at": now + int(getattr(settings, "DEVICE_LEASE_SECONDS", 7 * 86400)),
    }
    canonical = json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode()
    signature = hmac.new(token.encode(), b"orbit-device-lease-v1:" + canonical, hashlib.sha256).hexdigest()
    return payload, signature


def verify_totp(code: str, secret: str, window=1) -> bool:
    value = "".join(character for character in str(code or "") if character.isdigit())
    if len(value) != 6 or not secret:
        return False
    try:
        key = base64.b32decode(secret + "=" * ((8 - len(secret) % 8) % 8), casefold=True)
    except (ValueError, TypeError):
        return False
    counter = int(time.time()) // 30
    for offset in range(-window, window + 1):
        digest = hmac.new(key, (counter + offset).to_bytes(8, "big"), hashlib.sha1).digest()
        index = digest[-1] & 15
        expected = str((int.from_bytes(digest[index:index + 4], "big") & 0x7FFFFFFF) % 1_000_000).zfill(6)
        if hmac.compare_digest(value, expected):
            return True
    return False


def require_same_origin(request) -> None:
    if request.method in {"GET", "HEAD", "OPTIONS"}:
        return
    expected = urlsplit(settings.PUBLIC_BASE_URL).netloc.lower()
    origin = request.META.get("HTTP_ORIGIN", "")
    fetch_site = request.META.get("HTTP_SEC_FETCH_SITE", "")
    if origin:
        if urlsplit(origin).netloc.lower() != expected:
            raise PermissionDenied("Cross-origin request denied.")
    elif fetch_site not in {"same-origin", "none"}:
        raise PermissionDenied("Request origin could not be verified.")


def _throttle_key(scope: str, identity: str) -> str:
    return hashlib.sha256((settings.DEVICE_TOKEN_PEPPER + ":throttle:" + scope + ":" + identity).encode()).hexdigest()


def throttle_blocked(scope: str, identity: str) -> bool:
    from .models import SecurityThrottle

    row = SecurityThrottle.objects.filter(key=_throttle_key(scope, identity)).only("blocked_until").first()
    return bool(row and row.blocked_until and row.blocked_until > timezone.now())


@transaction.atomic
def throttle_failure(scope: str, identity: str, *, limit=8, window_seconds=600) -> None:
    from .models import SecurityThrottle

    now = timezone.now()
    row, _ = SecurityThrottle.objects.select_for_update().get_or_create(key=_throttle_key(scope, identity), defaults={"scope": scope, "window_started_at": now})
    if row.window_started_at < now - timedelta(seconds=window_seconds):
        row.attempts, row.window_started_at = 0, now
    row.attempts += 1
    if row.attempts >= limit:
        row.blocked_until = now + timedelta(seconds=window_seconds)
    row.save(update_fields=("attempts", "window_started_at", "blocked_until"))


def throttle_clear(scope: str, identity: str) -> None:
    from .models import SecurityThrottle

    SecurityThrottle.objects.filter(key=_throttle_key(scope, identity)).delete()


def valid_cidrs(text_or_list) -> list[str]:
    values = text_or_list if isinstance(text_or_list, list) else str(text_or_list or "").replace(",", "\n").splitlines()
    result = []
    for raw in values:
        value = str(raw).strip()
        if not value:
            continue
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError as exc:
            raise ValidationError(f"IP/CIDR noto‘g‘ri: {value}") from exc
        result.append(str(network))
    return result


def ip_allowed(ip: str, cidrs: list[str]) -> bool:
    if not cidrs:
        return False
    try:
        address = ipaddress.ip_address(ip)
        return any(address in ipaddress.ip_network(value, strict=False) for value in cidrs)
    except ValueError:
        return False


def host_cidr(ip: str) -> str:
    address = ipaddress.ip_address(ip)
    return f"{address}/{32 if address.version == 4 else 128}"


def new_device_token() -> str:
    return secrets.token_urlsafe(48)


def new_activation_key() -> str:
    raw = secrets.token_hex(12).upper()
    return "ORBT-" + "-".join(raw[index:index + 4] for index in range(0, len(raw), 4))


def activation_key_hash(value: str) -> str:
    normalized = str(value or "").strip().upper().replace(" ", "")
    return hashlib.sha256((settings.DEVICE_TOKEN_PEPPER + ":activation:" + normalized).encode()).hexdigest()


def device_token_hash(token: str) -> str:
    return hashlib.sha256((settings.DEVICE_TOKEN_PEPPER + token).encode()).hexdigest()


def bearer_token(request) -> str:
    value = request.META.get("HTTP_AUTHORIZATION", "")
    if not value.startswith("Bearer "):
        raise PermissionDenied("Bearer token required.")
    return value[7:].strip()


def validate_telegram_init_data(raw: str, max_age=None) -> dict:
    if not raw or not settings.TELEGRAM_BOT_TOKEN:
        raise TelegramInitDataError(
            "Telegram orqali kirish ma’lumoti topilmadi. Web-ilovani bot tugmasidan oching.",
            "telegram_init_data_missing",
        )
    if len(raw) > 16_384:
        raise TelegramInitDataError("Telegram kirish ma’lumoti juda katta.", "telegram_init_data_invalid")
    try:
        parsed = parse_qsl(raw, keep_blank_values=True, strict_parsing=True, max_num_fields=32)
    except ValueError as exc:
        raise TelegramInitDataError("Telegram kirish ma’lumoti noto‘g‘ri.", "telegram_init_data_invalid") from exc
    if len({key for key, _ in parsed}) != len(parsed):
        raise TelegramInitDataError("Telegram kirish maydonlari takrorlangan.", "telegram_init_data_invalid")
    pairs = dict(parsed)
    received_hash = pairs.pop("hash", "")
    # Bot-token HMAC validation excludes only `hash`. Telegram clients added
    # `signature` in 2025; it must remain in this data-check-string. Excluding
    # it rejects genuine initData produced by current Telegram clients.
    check_string = "\n".join(f"{key}={value}" for key, value in sorted(pairs.items()))
    secret = hmac.new(b"WebAppData", settings.TELEGRAM_BOT_TOKEN.encode(), hashlib.sha256).digest()
    expected = hmac.new(secret, check_string.encode(), hashlib.sha256).hexdigest()
    valid_hash = (
        len(received_hash) == 64
        and all(character in "0123456789abcdefABCDEF" for character in received_hash)
        and hmac.compare_digest(received_hash.lower(), expected)
    )
    if not valid_hash:
        log.warning(
            "Telegram initData HMAC mismatch (bot_id=%s, fields=%s)",
            settings.TELEGRAM_BOT_TOKEN.partition(":")[0],
            ",".join(sorted(pairs)),
        )
        raise TelegramInitDataError(
            "Telegram imzosi tasdiqlanmadi. Bot tokeni yoki Mini App tugmasi sozlamasini tekshiring.",
            "telegram_signature_invalid",
        )
    try:
        auth_date = int(pairs.get("auth_date", "0"))
    except (TypeError, ValueError) as exc:
        raise TelegramInitDataError("Telegram kirish vaqti noto‘g‘ri.", "telegram_auth_date_invalid") from exc
    max_age = int(max_age if max_age is not None else settings.TELEGRAM_INIT_DATA_MAX_AGE)
    age = time.time() - auth_date
    if auth_date <= 0 or age < -120 or age > max_age:
        raise TelegramInitDataError(
            "Telegram kirish ma’lumoti eskirgan. Web-ilovani bot tugmasidan qayta oching.",
            "telegram_auth_expired",
        )
    try:
        user = json.loads(pairs.get("user", "{}"))
    except json.JSONDecodeError as exc:
        raise TelegramInitDataError("Telegram foydalanuvchi ma’lumoti noto‘g‘ri.", "telegram_user_invalid") from exc
    try:
        telegram_id = int(user.get("id"))
    except (TypeError, ValueError) as exc:
        raise TelegramInitDataError("Telegram foydalanuvchi ID si topilmadi.", "telegram_user_invalid") from exc
    if telegram_id <= 0:
        raise TelegramInitDataError("Telegram foydalanuvchi ID si topilmadi.", "telegram_user_invalid")
    user["id"] = telegram_id
    return user


def issue_miniapp_session(telegram_id: int) -> str:
    return signing.dumps({"telegram_id": int(telegram_id), "expires_at": int(time.time()) + settings.MINIAPP_SESSION_MAX_AGE}, salt="orbit-miniapp", compress=True)


def read_miniapp_session(token: str, with_remaining=False):
    try:
        payload = signing.loads(token, salt="orbit-miniapp", max_age=settings.MINIAPP_SESSION_MAX_AGE)
        remaining = int(payload["expires_at"]) - int(time.time())
        if remaining <= 0:
            raise signing.SignatureExpired("Mini App session expired.")
        telegram_id = int(payload["telegram_id"])
        return (telegram_id, remaining) if with_remaining else telegram_id
    except (signing.BadSignature, signing.SignatureExpired, KeyError, ValueError) as exc:
        raise PermissionDenied("Web-ilova seansi tugagan. Bot orqali qayta kiring.") from exc
