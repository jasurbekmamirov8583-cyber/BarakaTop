from __future__ import annotations

import asyncio
import json
import logging
import secrets
import time
from dataclasses import dataclass
from datetime import timedelta
from http.cookies import SimpleCookie
from urllib.parse import parse_qs

from asgiref.sync import sync_to_async
from django.conf import settings
from django.core.exceptions import PermissionDenied
from django.utils import timezone

from .models import AlertRule, ControlAudit, Device, Store, StoreAdmin
from .security import device_token_hash, ip_allowed, read_miniapp_session, signed_device_lease
from .telegram import send_alert

log = logging.getLogger("control.relay")
MAX_MESSAGE = 2_000_000
REPORT_PERMISSION = {
    "overview": "overview", "sales_daily": "sales", "sales_monthly": "sales", "sales_hourly": "sales",
    "top_products": "products", "low_stock": "inventory", "inventory_value": "inventory",
    "payment_mix": "finance", "cashier_summary": "sales",
}
COMMAND_PERMISSION = {
    "staff.list": "staff", "staff.create": "staff", "staff.toggle": "staff", "staff.password_reset": "staff", "staff.update_role": "staff", "staff.qr": "staff",
    "settings.get": "settings", "settings.update": "settings",
    "lan.list": "devices", "lan.update": "devices",
}


@dataclass
class Peer:
    peer_id: str
    send: object
    kind: str
    store_ids: set[str]
    permissions: dict[str, list[str]]
    device_id: str = ""
    expires_at: float = 0
    device_token: str = ""


class RelayHub:
    def __init__(self):
        self.devices: dict[str, Peer] = {}
        self.admins: dict[str, Peer] = {}
        self.pending: dict[str, tuple[str, str, str, float, str]] = {}
        self.command_pending: dict[str, tuple[str, str, str, float]] = {}
        self.lock = asyncio.Lock()

    async def add(self, peer):
        async with self.lock:
            (self.devices if peer.kind == "device" else self.admins)[peer.device_id or peer.peer_id] = peer
            targets = [admin for admin in self.admins.values() if peer.kind == "device" and admin.store_ids.intersection(peer.store_ids)]
        if targets:
            await asyncio.gather(*(self.send_json(target, {"type": "device_presence", "device_id": peer.device_id, "online": True}) for target in targets), return_exceptions=True)

    async def remove(self, peer):
        async with self.lock:
            peers = self.devices if peer.kind == "device" else self.admins
            key = peer.device_id or peer.peer_id
            removed = peers.get(key) is peer
            if removed:
                peers.pop(key, None)
            if peer.kind == "admin":
                self.pending = {key: value for key, value in self.pending.items() if value[0] != peer.peer_id}
                self.command_pending = {key: value for key, value in self.command_pending.items() if value[0] != peer.peer_id}
            targets = [admin for admin in self.admins.values() if removed and peer.kind == "device" and admin.store_ids.intersection(peer.store_ids)]
        if targets:
            await asyncio.gather(*(self.send_json(target, {"type": "device_presence", "device_id": peer.device_id, "online": False}) for target in targets), return_exceptions=True)

    async def send_json(self, peer, payload):
        await peer.send({"type": "websocket.send", "text": json.dumps(payload, ensure_ascii=False, separators=(",", ":"))})


hub = RelayHub()


def scope_ip(scope):
    headers = {key.decode().lower(): value.decode() for key, value in scope.get("headers", [])}
    forwarded = headers.get("x-forwarded-for", "")
    return (forwarded.split(",")[-1].strip() if forwarded else "") or (scope.get("client") or ("127.0.0.1", 0))[0]


def scope_headers(scope):
    return {key.decode().lower(): value.decode() for key, value in scope.get("headers", [])}


def cookie_value(scope, name):
    cookie = SimpleCookie(); cookie.load(scope_headers(scope).get("cookie", ""))
    return cookie[name].value if name in cookie else ""


@sync_to_async
def authenticate_device(token, install_id, ip):
    try:
        device = Device.objects.select_related("store").get(token_hash=device_token_hash(token), install_id=install_id)
    except (Device.DoesNotExist, ValueError) as exc:
        raise PermissionDenied("Invalid device credential.") from exc
    device.last_ip = ip
    device.save(update_fields=("last_ip", "updated_at"))
    if device.status != Device.Status.ACTIVE or device.owner_paused or device.store.status not in {Store.Status.TRIAL, Store.Status.ACTIVE}:
        raise PermissionDenied("Device is blocked.")
    if not ip_allowed(ip, device.allowed_ip_cidrs):
        ControlAudit.objects.create(store=device.store, action="device.ip_denied", entity_type="Device", entity_id=str(device.pk), ip_address=ip)
        raise PermissionDenied("IP address is not authorized.")
    device.last_seen_at = timezone.now()
    device.save(update_fields=("last_seen_at", "updated_at"))
    return str(device.pk), str(device.store_id), list(device.permissions)


@sync_to_async
def authenticate_admin(session_token):
    telegram_id, remaining = read_miniapp_session(session_token, with_remaining=True)
    rows = list(StoreAdmin.objects.filter(telegram_id=telegram_id, active=True, store__status__in=(Store.Status.TRIAL, Store.Status.ACTIVE)).values("store_id", "permissions"))
    if not rows:
        raise PermissionDenied("No active store access.")
    return telegram_id, {str(row["store_id"]): list(row["permissions"]) for row in rows}, remaining


@sync_to_async
def device_for_admin(device_id, telegram_id):
    device = Device.objects.filter(
        pk=device_id, status=Device.Status.ACTIVE, owner_paused=False,
        store__status__in=(Store.Status.TRIAL, Store.Status.ACTIVE),
        store__telegram_admins__telegram_id=telegram_id,
        store__telegram_admins__active=True,
    ).values("store_id", "permissions", "mode", "store__telegram_admins__permissions").first()
    if not device:
        raise PermissionDenied("Device is not available for this administrator.")
    return str(device["store_id"]), list(device["permissions"]), list(device["store__telegram_admins__permissions"]), device["mode"]


@sync_to_async
def device_still_authorized(device_id, ip, token):
    device = Device.objects.select_related("store").filter(pk=device_id).first()
    allowed = bool(device and device.status == Device.Status.ACTIVE and not device.owner_paused and device.store.status in {Store.Status.TRIAL, Store.Status.ACTIVE} and ip_allowed(ip, device.allowed_ip_cidrs))
    if allowed:
        device.last_seen_at = timezone.now()
        device.last_ip = ip
        device.save(update_fields=("last_seen_at", "last_ip", "updated_at"))
    if not allowed:
        return None
    lease, signature = signed_device_lease(token, device)
    return {"mode": device.mode, "permissions": list(device.permissions), "features": device.store.active_features, "lease": lease, "lease_signature": signature}


@sync_to_async
def record_report_audit(telegram_id, store_id, device_id, report):
    ControlAudit.objects.create(telegram_id=telegram_id, store_id=store_id, action="report.live", entity_type="Device", entity_id=device_id, metadata={"report": report})


@sync_to_async
def prepare_alert(store_id, event):
    rule, _ = AlertRule.objects.get_or_create(store_id=store_id, event=event)
    if not rule.enabled or (rule.last_sent_at and rule.last_sent_at > timezone.now() - timedelta(minutes=rule.cooldown_minutes)):
        return None
    store = Store.objects.get(pk=store_id)
    recipients = [admin.telegram_id for admin in store.telegram_admins.filter(active=True) if "alerts" in admin.permissions]
    if not recipients:
        return None
    return rule.pk, store.name, recipients


@sync_to_async
def mark_alert_sent(rule_id, recipient_count):
    rule = AlertRule.objects.select_related("store").get(pk=rule_id)
    rule.last_sent_at = timezone.now()
    rule.save(update_fields=("last_sent_at", "updated_at"))
    ControlAudit.objects.create(store=rule.store, action="alert.dispatched", entity_type="AlertRule", entity_id=str(rule.pk), metadata={"event": rule.event, "recipient_count": recipient_count})


async def send_device_alert(peer, message):
    if message.get("event") != "low_stock":
        return
    store_id = next(iter(peer.store_ids))
    if "alerts" not in peer.permissions.get(store_id, []):
        return
    items = message.get("items", [])[:30]
    if not items:
        return
    prepared = await prepare_alert(store_id, "low_stock")
    if not prepared:
        return
    rule_id, store_name, recipients = prepared
    lines = ["Omborda kam qolgan mahsulotlar:"] + [f"• {str(item.get('name', ''))[:80]} · {str(item.get('warehouse', ''))[:60]} — {item.get('quantity', 0)} {str(item.get('unit', ''))[:12]}" for item in items]
    text = "\n".join(lines)
    delivered = 0
    for telegram_id in recipients:
        try:
            await asyncio.to_thread(send_alert, telegram_id, store_name, text)
            delivered += 1
        except Exception:
            log.exception("Telegram alert failed")
    if delivered:
        await mark_alert_sent(rule_id, delivered)


async def websocket_application(scope, receive, send):
    connect_event = await receive()
    if connect_event["type"] != "websocket.connect":
        return
    params = {key: values[0] for key, values in parse_qs(scope.get("query_string", b"").decode()).items()}
    kind = params.get("kind", "")
    try:
        if kind == "device":
            headers = scope_headers(scope)
            authorization = headers.get("authorization", "")
            token = authorization[7:] if authorization.startswith("Bearer ") else ""
            device_id, store_id, permissions = await authenticate_device(token, headers.get("x-orbit-install-id", ""), scope_ip(scope))
            peer = Peer(secrets.token_urlsafe(10), send, "device", {store_id}, {store_id: permissions}, device_id, device_token=token)
        elif kind == "admin":
            origin = scope_headers(scope).get("origin", "").rstrip("/")
            if origin != settings.PUBLIC_BASE_URL:
                raise PermissionDenied("Invalid WebSocket origin.")
            telegram_id, permissions, remaining = await authenticate_admin(cookie_value(scope, "orbit_mini_session"))
            peer = Peer(str(telegram_id) + "-" + secrets.token_urlsafe(8), send, "admin", set(permissions), permissions, expires_at=time.monotonic() + remaining)
        else:
            raise PermissionDenied("Unknown peer type.")
    except PermissionDenied as exc:
        await send({"type": "websocket.close", "code": 4403, "reason": str(exc)[:120]})
        return
    await send({"type": "websocket.accept"})
    await hub.add(peer)
    await hub.send_json(peer, {"type": "ready", "peer": kind, "device_id": peer.device_id or None})
    try:
        while True:
            if peer.kind == "admin":
                remaining = peer.expires_at - time.monotonic()
                if remaining <= 0:
                    await send({"type": "websocket.close", "code": 4401, "reason": "Mini App session expired"})
                    break
                try:
                    event = await asyncio.wait_for(receive(), timeout=remaining)
                except asyncio.TimeoutError:
                    await send({"type": "websocket.close", "code": 4401, "reason": "Mini App session expired"})
                    break
            else:
                event = await receive()
            if event["type"] == "websocket.disconnect":
                break
            if event["type"] != "websocket.receive":
                continue
            raw = event.get("text", "")
            if len(raw) > MAX_MESSAGE:
                await send({"type": "websocket.close", "code": 4409, "reason": "Message too large"}); break
            try:
                message = json.loads(raw)
            except json.JSONDecodeError:
                await hub.send_json(peer, {"type": "error", "error": "Invalid JSON"}); continue
            if message.get("type") in {"ping", "heartbeat"}:
                policy = await device_still_authorized(peer.device_id, scope_ip(scope), peer.device_token) if peer.kind == "device" else None
                if peer.kind == "device" and not policy:
                    await send({"type": "websocket.close", "code": 4403, "reason": "Device authorization revoked"})
                    break
                if peer.kind == "device" and policy:
                    peer.permissions[next(iter(peer.store_ids))] = list(policy.get("permissions", []))
                await hub.send_json(peer, {"type": "pong", "time": timezone.now().isoformat(), **(policy or {})}); continue
            if peer.kind == "admin" and message.get("type") == "report_request":
                report, device_id = message.get("report", ""), message.get("device_id", "")
                required = REPORT_PERMISSION.get(report)
                try:
                    telegram_id = int(peer.peer_id.split("-", 1)[0])
                    store_id, device_permissions, admin_permissions, device_mode = await device_for_admin(device_id, telegram_id)
                    if not required or required not in admin_permissions or required not in device_permissions:
                        raise PermissionDenied("This report is not permitted.")
                    device_peer = hub.devices.get(device_id)
                    if not device_peer:
                        await hub.send_json(peer, {"type": "report_error", "request_id": message.get("request_id"), "error": "Do‘kon kompyuteri hozir online emas."}); continue
                    now = time.monotonic()
                    hub.pending = {key: value for key, value in hub.pending.items() if now - value[3] < 120}
                    if sum(1 for value in hub.pending.values() if value[0] == peer.peer_id) >= 5:
                        raise PermissionDenied("Too many live report requests. Please wait.")
                    upstream_id = secrets.token_urlsafe(18)
                    client_request_id = str(message.get("request_id", ""))[:80]
                    hub.pending[upstream_id] = (peer.peer_id, device_id, client_request_id, now, report)
                    forwarded = {"type": "report_request", "request_id": upstream_id, "report": report, "params": message.get("params", {})}
                    await hub.send_json(device_peer, forwarded)
                    await record_report_audit(telegram_id, store_id, device_id, report)
                except PermissionDenied as exc:
                    await hub.send_json(peer, {"type": "report_error", "request_id": message.get("request_id"), "error": str(exc)})
            elif peer.kind == "admin" and message.get("type") == "command_request":
                command, device_id = str(message.get("command", "")), str(message.get("device_id", ""))
                required = COMMAND_PERMISSION.get(command)
                try:
                    telegram_id = int(peer.peer_id.split("-", 1)[0])
                    store_id, device_permissions, admin_permissions, device_mode = await device_for_admin(device_id, telegram_id)
                    if not required or required not in admin_permissions or required not in device_permissions:
                        raise PermissionDenied("Bu boshqaruv amali uchun ruxsat yo‘q.")
                    if device_mode not in {"owner", "manager", "universal"}:
                        raise PermissionDenied("Xodim va printer sozlamalari Owner yoki Manager qurilmasi orqali boshqariladi.")
                    device_peer = hub.devices.get(device_id)
                    if not device_peer:
                        raise PermissionDenied("Do‘kon kompyuteri hozir online emas.")
                    now = time.monotonic()
                    hub.command_pending = {key: value for key, value in hub.command_pending.items() if now - value[3] < 120}
                    if sum(1 for value in hub.command_pending.values() if value[0] == peer.peer_id) >= 5:
                        raise PermissionDenied("Juda ko‘p so‘rov yuborildi. Biroz kuting.")
                    upstream_id = secrets.token_urlsafe(18)
                    client_request_id = str(message.get("request_id", ""))[:80]
                    hub.command_pending[upstream_id] = (peer.peer_id, device_id, client_request_id, now)
                    await hub.send_json(device_peer, {"type": "command_request", "request_id": upstream_id, "command": command, "payload": message.get("payload", {}), "actor_telegram_id": telegram_id})
                    await record_report_audit(telegram_id, store_id, device_id, "command:" + command)
                except PermissionDenied as exc:
                    await hub.send_json(peer, {"type": "command_error", "request_id": message.get("request_id"), "error": str(exc)})
            elif peer.kind == "device" and message.get("type") in {"report_result", "report_error"}:
                pending = hub.pending.pop(str(message.get("request_id", "")), None)
                if pending and pending[1] == peer.device_id:
                    target = hub.admins.get(pending[0])
                    if target and target.store_ids.intersection(peer.store_ids):
                        response = {"type": message["type"], "request_id": pending[2], "report": pending[4]}
                        if message["type"] == "report_result":
                            response["data"] = message.get("data", {})
                        else:
                            response["error"] = str(message.get("error", "Report failed."))[:300]
                        await hub.send_json(target, response)
            elif peer.kind == "device" and message.get("type") in {"command_result", "command_error"}:
                pending = hub.command_pending.pop(str(message.get("request_id", "")), None)
                if pending and pending[1] == peer.device_id:
                    target = hub.admins.get(pending[0])
                    if target and target.store_ids.intersection(peer.store_ids):
                        response = {"type": message["type"], "request_id": pending[2]}
                        if message["type"] == "command_result":
                            response["data"] = message.get("data", {})
                        else:
                            response["error"] = str(message.get("error", "Amal bajarilmadi."))[:300]
                        await hub.send_json(target, response)
            elif peer.kind == "device" and message.get("type") == "alert":
                await send_device_alert(peer, message)
    finally:
        await hub.remove(peer)
