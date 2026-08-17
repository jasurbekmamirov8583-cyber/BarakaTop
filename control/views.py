from __future__ import annotations

import json
import secrets
from datetime import timedelta
from functools import wraps
from uuid import UUID

from django.conf import settings
from django.contrib import messages
from django.contrib.auth import login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth.hashers import check_password, make_password
from django.core.exceptions import PermissionDenied, ValidationError
from django.core.cache import cache
from django.db import transaction
from django.http import JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_GET, require_http_methods, require_POST

from .forms import AlertRuleForm, DeviceForm, EnrollmentForm, StoreForm, TelegramAdminForm
from .models import AlertRule, ControlAudit, Device, DeviceEnrollment, FEATURE_CHOICES, Store, StoreAdmin
from .security import (
    activation_key_hash, bearer_token, client_ip, device_token_hash, host_cidr, ip_allowed,
    issue_miniapp_session, new_activation_key, new_device_token, read_miniapp_session,
    require_same_origin, signed_device_lease, throttle_blocked, throttle_clear, throttle_failure,
    validate_telegram_init_data, verify_totp,
)
from .telegram import configure_bot, send_webapp_button


def json_input(request):
    try:
        return json.loads(request.body or b"{}")
    except json.JSONDecodeError as exc:
        raise ValidationError("Invalid JSON.") from exc


def audit(request, action, entity, store=None, metadata=None, telegram_id=None):
    ControlAudit.objects.create(
        actor=request.user if getattr(request, "user", None) and request.user.is_authenticated else None,
        telegram_id=telegram_id, store=store, action=action,
        entity_type=entity.__class__.__name__, entity_id=str(entity.pk),
        ip_address=client_ip(request), metadata=metadata or {},
    )


def superadmin_required(view):
    @login_required
    @wraps(view)
    def wrapped(request, *args, **kwargs):
        if not request.user.is_superuser or timezone.now().timestamp() - request.session.get("superadmin_2fa_at", 0) > 12 * 3600:
            raise PermissionDenied
        return view(request, *args, **kwargs)
    return wrapped


def miniapp_admin(request, store_id, permission=None):
    require_same_origin(request)
    telegram_id = read_miniapp_session(request.COOKIES.get("orbit_mini_session", ""))
    try:
        admin = StoreAdmin.objects.select_related("store").get(
            telegram_id=telegram_id, store_id=store_id, active=True,
            store__status__in=(Store.Status.TRIAL, Store.Status.ACTIVE),
        )
    except StoreAdmin.DoesNotExist as exc:
        raise PermissionDenied("Bu do‘konni boshqarish huquqi yo‘q.") from exc
    if permission and permission not in admin.permissions:
        raise PermissionDenied(f"Ruxsat kerak: {permission}")
    return admin


@require_GET
def health(request):
    return JsonResponse({"ok": True, "service": "barakatop-control", "time": timezone.now().isoformat()})


@require_http_methods(["GET", "POST"])
def panel_login(request):
    if request.user.is_authenticated and request.user.is_superuser:
        if timezone.now().timestamp() - request.session.get("superadmin_2fa_at", 0) <= 12 * 3600:
            return redirect("panel_dashboard")
        logout(request)
    identity = client_ip(request)
    if throttle_blocked("panel-login", identity):
        return render(request, "control/login.html", {"form": AuthenticationForm(), "blocked": True}, status=429)
    form = AuthenticationForm(request, data=request.POST or None)
    if request.method == "POST" and form.is_valid() and form.get_user().is_superuser and verify_totp(request.POST.get("totp", ""), settings.SUPERADMIN_TOTP_SECRET):
        throttle_clear("panel-login", identity)
        login(request, form.get_user())
        request.session["superadmin_2fa_at"] = timezone.now().timestamp()
        return redirect("panel_dashboard")
    if request.method == "POST" and form.is_valid() and form.get_user().is_superuser:
        form.add_error(None, "Bir martalik 2FA kodi noto'g'ri.")
    if request.method == "POST" and form.is_valid():
        form.add_error(None, "Super administrator access is required.")
    if request.method == "POST":
        throttle_failure("panel-login", identity)
    return render(request, "control/login.html", {"form": form})


@require_POST
def panel_logout(request):
    logout(request)
    return redirect("panel_login")


@superadmin_required
def dashboard(request):
    stores = Store.objects.all()
    devices = Device.objects.all()
    return render(request, "control/dashboard.html", {
        "store_count": stores.count(), "active_stores": stores.filter(status=Store.Status.ACTIVE).count(),
        "device_count": devices.count(), "pending_devices": devices.filter(status=Device.Status.PENDING).count(),
        "recent_stores": stores.order_by("-created_at")[:8], "recent_audit": ControlAudit.objects.select_related("store", "actor")[:12],
    })


@superadmin_required
@require_POST
def telegram_configure(request):
    if not settings.TELEGRAM_BOT_TOKEN or not settings.TELEGRAM_WEBHOOK_SECRET or not settings.PUBLIC_BASE_URL.startswith("https://"):
        messages.error(request, "Telegram tokeni, webhook siri va HTTPS PUBLIC_BASE_URL sozlanishi kerak.")
    else:
        try:
            configure_bot()
            messages.success(request, "Telegram webhook va Mini App menyusi sozlandi.")
        except Exception as exc:
            messages.error(request, f"Telegram sozlanmadi: {str(exc)[:180]}")
    return redirect("panel_dashboard")


@superadmin_required
def stores(request):
    return render(request, "control/stores.html", {"stores": Store.objects.prefetch_related("devices", "telegram_admins")})


@superadmin_required
@require_http_methods(["GET", "POST"])
def store_edit(request, pk=None):
    store = get_object_or_404(Store, pk=pk) if pk else None
    form = StoreForm(request.POST or None, instance=store)
    if request.method == "POST" and form.is_valid():
        obj = form.save()
        AlertRule.objects.get_or_create(store=obj, event="low_stock")
        audit(request, "store.update" if store else "store.create", obj, obj)
        messages.success(request, "Do‘kon saqlandi.")
        return redirect("store_detail", pk=obj.pk)
    return render(request, "control/form.html", {"form": form, "title": "Do‘konni tahrirlash" if store else "Yangi do‘kon", "back_url": reverse("stores")})


@superadmin_required
def store_detail(request, pk):
    store = get_object_or_404(Store, pk=pk)
    credential_key = request.session.pop("created_credential_key", "")
    credential = cache.get(f"created-credential:{credential_key}") if credential_key else None
    if credential_key:
        cache.delete(f"created-credential:{credential_key}")
    alert_rule, _ = AlertRule.objects.get_or_create(store=store, event="low_stock")
    return render(request, "control/store_detail.html", {
        "store": store, "admins": store.telegram_admins.all(), "devices": store.devices.all(),
        "licensed_device_count": store.licensed_device_count,
        "enrollments": store.enrollments.order_by("-created_at")[:30], "credential": credential,
        "admin_form": TelegramAdminForm(), "enrollment_form": EnrollmentForm(),
        "alert_rule": alert_rule, "alert_form": AlertRuleForm(instance=alert_rule),
    })


@superadmin_required
@require_GET
def store_device_status(request, pk):
    store = get_object_or_404(Store, pk=pk)
    return JsonResponse({"ok": True, "devices": [{"id": str(device.pk), "online": device.online, "status": Device.Status.BLOCKED if device.owner_paused and device.status == Device.Status.ACTIVE else device.status, "central_status": device.status, "owner_paused": device.owner_paused, "last_ip": device.last_ip or "", "last_seen": timezone.localtime(device.last_seen_at).strftime("%d.%m.%Y %H:%M:%S") if device.last_seen_at else "—", "lan_clients": device.lan_clients} for device in store.devices.all()]})


@superadmin_required
@require_POST
def telegram_admin_add(request, pk):
    store = get_object_or_404(Store, pk=pk)
    form = TelegramAdminForm(request.POST)
    if form.is_valid():
        values = form.cleaned_data
        obj, _ = StoreAdmin.objects.update_or_create(store=store, telegram_id=values["telegram_id"], defaults={"display_name": values["display_name"], "permissions": values["permissions"], "active": values["active"]})
        audit(request, "telegram_admin.create", obj, store, {"telegram_id": obj.telegram_id})
        messages.success(request, "Telegram administrator biriktirildi.")
    else:
        messages.error(request, form.errors.as_text())
    return redirect("store_detail", pk=store.pk)


@superadmin_required
@require_POST
def telegram_admin_toggle(request, pk):
    obj = get_object_or_404(StoreAdmin, pk=pk)
    obj.active = not obj.active
    obj.save(update_fields=("active", "updated_at"))
    audit(request, "telegram_admin.toggle", obj, obj.store, {"active": obj.active, "telegram_id": obj.telegram_id})
    messages.success(request, "Telegram administrator holati yangilandi.")
    return redirect("store_detail", pk=obj.store_id)


@superadmin_required
@require_POST
def enrollment_add(request, pk):
    store = get_object_or_404(Store, pk=pk)
    form = EnrollmentForm(request.POST)
    if form.is_valid():
        password = form.cleaned_data["password"] or secrets.token_urlsafe(12)
        username = form.cleaned_data["username"] or f"{store.code}-{secrets.token_hex(3)}"
        while DeviceEnrollment.objects.filter(username__iexact=username).exists():
            username = f"{store.code}-{secrets.token_hex(3)}"
        activation_key = new_activation_key()
        enrollment = DeviceEnrollment.objects.create(
            store=store, username=username, password_hash=make_password(password),
            activation_key_hash=activation_key_hash(activation_key), activation_key_hint=activation_key[-9:],
            label=form.cleaned_data["label"], expected_ip_cidrs=form.cleaned_data["expected_ip_cidrs"],
            mode=form.cleaned_data["mode"], permissions=form.cleaned_data["permissions"],
            expires_at=form.expires_at(), max_uses=form.cleaned_data["max_uses"], created_by=request.user,
        )
        credential_key = secrets.token_urlsafe(24)
        cache.set(f"created-credential:{credential_key}", {"store_code": store.code, "username": enrollment.username, "password": password, "activation_key": activation_key}, 120)
        request.session["created_credential_key"] = credential_key
        audit(request, "enrollment.create", enrollment, store, {"mode": enrollment.mode, "expected_ip_cidrs": enrollment.expected_ip_cidrs})
        messages.success(request, "Aktivatsiya ma’lumoti yaratildi. Parol faqat bir marta ko‘rsatiladi.")
    else:
        messages.error(request, form.errors.as_text())
    return redirect("store_detail", pk=store.pk)


@superadmin_required
@require_POST
def enrollment_revoke(request, pk):
    enrollment = get_object_or_404(DeviceEnrollment, pk=pk)
    enrollment.active = False
    enrollment.save(update_fields=("active", "updated_at"))
    audit(request, "enrollment.revoke", enrollment, enrollment.store)
    messages.success(request, "Aktivatsiya ruxsati bekor qilindi.")
    return redirect("store_detail", pk=enrollment.store_id)


@superadmin_required
@require_POST
def enrollment_password_reset(request, pk):
    enrollment = get_object_or_404(DeviceEnrollment, pk=pk)
    password = secrets.token_urlsafe(12)
    enrollment.password_hash = make_password(password)
    enrollment.expires_at = max(enrollment.expires_at, timezone.now() + timedelta(days=7))
    enrollment.save(update_fields=("password_hash", "expires_at", "updated_at"))
    credential_key = secrets.token_urlsafe(24)
    cache.set(f"created-credential:{credential_key}", {"store_code": enrollment.store.code, "username": enrollment.username, "password": password}, 120)
    request.session["created_credential_key"] = credential_key
    audit(request, "enrollment.password_reset", enrollment, enrollment.store)
    messages.success(request, "Yangi login paroli yaratildi va faqat bir marta ko‘rsatiladi.")
    return redirect("store_detail", pk=enrollment.store_id)


@superadmin_required
@require_POST
def alert_rule_update(request, pk):
    store = get_object_or_404(Store, pk=pk)
    rule, _ = AlertRule.objects.get_or_create(store=store, event="low_stock")
    form = AlertRuleForm(request.POST, instance=rule)
    if form.is_valid():
        obj = form.save()
        audit(request, "alert_rule.update", obj, store, {"enabled": obj.enabled, "cooldown_minutes": obj.cooldown_minutes})
        messages.success(request, "Telegram ogohlantirish sozlamalari saqlandi.")
    else:
        messages.error(request, form.errors.as_text())
    return redirect("store_detail", pk=store.pk)


@superadmin_required
@require_http_methods(["GET", "POST"])
def device_edit(request, pk):
    device = get_object_or_404(Device, pk=pk)
    form = DeviceForm(request.POST or None, instance=device)
    if request.method == "POST" and form.is_valid():
        obj = form.save()
        if obj.status == Device.Status.ACTIVE and not obj.allowed_ip_cidrs and obj.last_ip:
            obj.allowed_ip_cidrs = [host_cidr(obj.last_ip)]; obj.save(update_fields=("allowed_ip_cidrs", "updated_at"))
        audit(request, "device.update", obj, obj.store, {"status": obj.status, "mode": obj.mode, "allowed_ip_cidrs": obj.allowed_ip_cidrs})
        messages.success(request, "Qurilma ruxsatlari yangilandi.")
        return redirect("store_detail", pk=obj.store_id)
    return render(request, "control/form.html", {"form": form, "title": device.name, "back_url": reverse("store_detail", args=(device.store_id,))})


@csrf_exempt
@require_POST
@transaction.atomic
def device_activate(request):
    try:
        data, ip = json_input(request), client_ip(request)
        if throttle_blocked("device-activate", ip):
            return JsonResponse({"ok": False, "error": "Ko‘p xato urinish. 10 daqiqadan so‘ng qayta urinib ko‘ring."}, status=429)
        supplied_key = str(data.get("activation_key", "")).strip()
        if supplied_key:
            enrollment = DeviceEnrollment.objects.select_for_update().select_related("store").get(activation_key_hash=activation_key_hash(supplied_key), store__code=data.get("store_code", ""))
            activation_method = Device.ActivationMethod.KEY
        else:
            enrollment = DeviceEnrollment.objects.select_for_update().select_related("store").get(username=data.get("username", ""), store__code=data.get("store_code", ""))
            activation_method = Device.ActivationMethod.PASSWORD
        install_id = UUID(str(data.get("install_id", "")))
        existing = Device.objects.select_for_update().filter(install_id=install_id).first()
        same_reservation = bool(existing and existing.enrollment_id == enrollment.pk)
        password_valid = activation_method == Device.ActivationMethod.PASSWORD and check_password(data.get("password", ""), enrollment.password_hash)
        key_valid = activation_method == Device.ActivationMethod.KEY and (not enrollment.key_used_at or same_reservation)
        if (not password_valid and not key_valid) or (not enrollment.usable and not same_reservation):
            raise PermissionDenied("Aktivatsiya ma’lumotlari noto‘g‘ri yoki muddati tugagan.")
        store = Store.objects.select_for_update().get(pk=enrollment.store_id)
        if store.status not in {Store.Status.TRIAL, Store.Status.ACTIVE}:
            raise PermissionDenied("Do‘kon faol emas.")
        current_devices = list(Device.objects.filter(store=store).exclude(status=Device.Status.REVOKED).only("lan_clients"))
        occupied_slots = len(current_devices) + sum(len(row.lan_clients or []) for row in current_devices)
        if not existing and occupied_slots >= store.max_devices:
            raise PermissionDenied(f"Do‘kon uchun ruxsat etilgan {store.max_devices} ta qurilma limiti tugagan.")
        raw_token = new_device_token()
        automatic = not enrollment.expected_ip_cidrs or ip_allowed(ip, enrollment.expected_ip_cidrs)
        allowed_ip_cidrs = enrollment.expected_ip_cidrs or [host_cidr(ip)]
        device, created = Device.objects.select_for_update().get_or_create(
            install_id=install_id,
            defaults={"store": store, "enrollment": enrollment, "name": data.get("device_name") or enrollment.label, "status": Device.Status.ACTIVE if automatic else Device.Status.PENDING, "mode": enrollment.mode, "permissions": enrollment.permissions, "token_hash": device_token_hash(raw_token), "allowed_ip_cidrs": allowed_ip_cidrs, "first_ip": ip, "last_ip": ip, "app_version": str(data.get("app_version", ""))[:32], "platform": str(data.get("platform", ""))[:160], "activation_method": activation_method},
        )
        if device.store_id != enrollment.store_id or device.enrollment_id != enrollment.pk:
            raise PermissionDenied("This installation belongs to another store.")
        if created:
            enrollment.used_count += 1
            if enrollment.used_count >= enrollment.max_uses:
                enrollment.active = False
        if activation_method == Device.ActivationMethod.KEY and not enrollment.key_used_at:
            enrollment.key_used_at = timezone.now()
        if created or activation_method == Device.ActivationMethod.KEY:
            enrollment.save(update_fields=("used_count", "active", "key_used_at", "updated_at"))
        if device.status in {Device.Status.BLOCKED, Device.Status.REVOKED} or device.owner_paused:
            raise PermissionDenied("This device was blocked by the super administrator.")
        device.last_ip, device.app_version, device.platform = ip, str(data.get("app_version", ""))[:32], str(data.get("platform", ""))[:160]
        if device.status == Device.Status.ACTIVE and ip_allowed(ip, device.allowed_ip_cidrs):
            device.token_hash = device_token_hash(raw_token)
            device.last_seen_at = timezone.now()
            device.save(update_fields=("token_hash", "last_ip", "last_seen_at", "app_version", "platform", "updated_at"))
            audit(request, "device.activate", device, device.store, {"automatic": automatic, "ip": ip, "method": device.activation_method})
            throttle_clear("device-activate", ip)
            lease, lease_signature = signed_device_lease(raw_token, device)
            return JsonResponse({"ok": True, "status": "active", "device_id": str(device.pk), "store_id": str(device.store_id), "store_name": device.store.name, "token": raw_token, "permissions": device.permissions, "mode": device.mode, "features": device.store.active_features, "activation_method": device.activation_method, "lease": lease, "lease_signature": lease_signature})
        device.save(update_fields=("last_ip", "app_version", "platform", "updated_at"))
        audit(request, "device.pending", device, device.store, {"ip": ip})
        return JsonResponse({"ok": False, "status": device.status, "device_id": str(device.pk), "message": "Qurilma super administrator tasdig‘ini kutmoqda.", "observed_ip": ip, "mode": device.mode, "activation_method": device.activation_method}, status=202)
    except DeviceEnrollment.DoesNotExist:
        throttle_failure("device-activate", client_ip(request))
        return JsonResponse({"ok": False, "error": "Aktivatsiya ma’lumotlari noto‘g‘ri."}, status=403)
    except (PermissionDenied, ValidationError, ValueError) as exc:
        throttle_failure("device-activate", client_ip(request))
        return JsonResponse({"ok": False, "error": str(exc)}, status=403)


def authenticate_device_request(request):
    token, install_id, ip = bearer_token(request), request.META.get("HTTP_X_ORBIT_INSTALL_ID", ""), client_ip(request)
    try:
        device = Device.objects.select_related("store").get(token_hash=device_token_hash(token), install_id=install_id)
    except (Device.DoesNotExist, ValueError) as exc:
        raise PermissionDenied("Invalid device credential.") from exc
    device.last_ip = ip; device.save(update_fields=("last_ip", "updated_at"))
    if device.status != Device.Status.ACTIVE or device.owner_paused or device.store.status not in {Store.Status.TRIAL, Store.Status.ACTIVE}:
        raise PermissionDenied("Device or store is not active.")
    if not ip_allowed(ip, device.allowed_ip_cidrs):
        ControlAudit.objects.create(store=device.store, action="device.ip_denied", entity_type="Device", entity_id=str(device.pk), ip_address=ip)
        raise PermissionDenied("Current public IP is not authorized.")
    return device, ip, token


@csrf_exempt
@require_POST
def device_verify(request):
    try:
        device, ip, token = authenticate_device_request(request)
        metadata = json_input(request)
        lan_clients = metadata.get("lan_clients", []) if isinstance(metadata, dict) else []
        if not isinstance(lan_clients, list):
            lan_clients = []
        allowed_modes = dict(DeviceEnrollment.Mode.choices)
        sanitized = [{"id": str(row.get("id", ""))[:64], "name": str(row.get("name", ""))[:160], "mode": str(row.get("mode", "")) if str(row.get("mode", "")) in allowed_modes else DeviceEnrollment.Mode.READ_ONLY, "last_ip": str(row.get("last_ip", ""))[:45], "online": bool(row.get("online"))} for row in lan_clients[:100] if isinstance(row, dict)]
        active_devices = device.store.devices.exclude(status=Device.Status.REVOKED)
        other_lan_count = sum(len(value or []) for value in active_devices.exclude(pk=device.pk).values_list("lan_clients", flat=True))
        if active_devices.count() + other_lan_count + len(sanitized) > device.store.max_devices:
            raise PermissionDenied("Store device limit is exceeded by LAN clients.")
        device.last_ip, device.last_seen_at = ip, timezone.now()
        device.lan_clients = sanitized
        device.save(update_fields=("last_ip", "last_seen_at", "lan_clients", "updated_at"))
        lease, lease_signature = signed_device_lease(token, device)
        return JsonResponse({"ok": True, "status": device.status, "store_id": str(device.store_id), "store_name": device.store.name, "permissions": device.permissions, "mode": device.mode, "features": device.store.active_features, "server_time": timezone.now().isoformat(), "lease": lease, "lease_signature": lease_signature})
    except (PermissionDenied, ValueError) as exc:
        return JsonResponse({"ok": False, "error": str(exc)}, status=403)


def miniapp(request):
    return render(request, "control/miniapp.html")


@csrf_exempt
@require_POST
def telegram_session(request):
    try:
        user = validate_telegram_init_data(json_input(request).get("init_data", ""))
        admins = StoreAdmin.objects.filter(telegram_id=user["id"], active=True, store__status__in=(Store.Status.TRIAL, Store.Status.ACTIVE))
        if not admins.exists():
            raise PermissionDenied("Sizga birorta do‘kon biriktirilmagan.")
        token = issue_miniapp_session(user["id"])
        response = JsonResponse({"ok": True, "user": {"id": user["id"], "name": user.get("first_name", "")}})
        response.set_cookie("orbit_mini_session", token, max_age=settings.MINIAPP_SESSION_MAX_AGE, httponly=True, secure=not settings.DEBUG, samesite="Lax")
        return response
    except (PermissionDenied, ValidationError) as exc:
        return JsonResponse({"ok": False, "error": str(exc)}, status=403)


@require_GET
def telegram_bootstrap(request):
    try:
        telegram_id = read_miniapp_session(request.COOKIES.get("orbit_mini_session", ""))
        admins = StoreAdmin.objects.filter(telegram_id=telegram_id, active=True).select_related("store").prefetch_related("store__devices")
        labels = dict(FEATURE_CHOICES)
        return JsonResponse({"ok": True, "feature_labels": labels, "stores": [{"id": str(a.store_id), "name": a.store.name, "permissions": a.permissions, "licensed_features": a.store.licensed_features, "enabled_features": a.store.active_features, "devices": [{"id": str(d.pk), "name": d.name, "mode": d.mode, "status": Device.Status.BLOCKED if d.owner_paused and d.status == Device.Status.ACTIVE else d.status, "central_status": d.status, "owner_paused": d.owner_paused, "online": d.online, "last_ip": d.last_ip or "", "last_seen": d.last_seen_at.isoformat() if d.last_seen_at else None, "lan_clients": d.lan_clients} for d in a.store.devices.all()]} for a in admins if a.store.status in {Store.Status.TRIAL, Store.Status.ACTIVE}]})
    except PermissionDenied as exc:
        return JsonResponse({"ok": False, "error": str(exc)}, status=403)


@csrf_exempt
@require_http_methods(["GET", "POST"])
def telegram_store_features(request, pk):
    try:
        admin = miniapp_admin(request, pk, "settings")
        if request.method == "POST":
            requested = json_input(request).get("features", [])
            if not isinstance(requested, list):
                raise ValidationError("Funksiyalar ro‘yxati noto‘g‘ri.")
            known = {code for code, _ in FEATURE_CHOICES}
            admin.store.enabled_features = [code for code in admin.store.licensed_features if code in requested and code in known]
            admin.store.save(update_fields=("enabled_features", "updated_at"))
            audit(request, "store.features", admin.store, admin.store, {"enabled": admin.store.active_features}, telegram_id=admin.telegram_id)
        return JsonResponse({"ok": True, "licensed_features": admin.store.licensed_features, "enabled_features": admin.store.active_features})
    except (PermissionDenied, ValidationError) as exc:
        return JsonResponse({"ok": False, "error": str(exc)}, status=403)


@csrf_exempt
@require_POST
def telegram_device_update(request, pk, device_id):
    try:
        admin = miniapp_admin(request, pk, "devices")
        device = get_object_or_404(Device, pk=device_id, store=admin.store)
        data = json_input(request)
        if "name" in data:
            device.name = str(data["name"]).strip()[:180] or device.name
        if data.get("mode") in dict(DeviceEnrollment.Mode.choices):
            device.mode = data["mode"]
        if data.get("status") in {Device.Status.ACTIVE, Device.Status.BLOCKED}:
            device.owner_paused = data["status"] == Device.Status.BLOCKED
        device.save(update_fields=("name", "mode", "owner_paused", "updated_at"))
        effective_status = Device.Status.BLOCKED if device.owner_paused and device.status == Device.Status.ACTIVE else device.status
        audit(request, "device.owner_update", device, admin.store, {"mode": device.mode, "owner_paused": device.owner_paused, "central_status": device.status}, telegram_id=admin.telegram_id)
        return JsonResponse({"ok": True, "device": {"id": str(device.pk), "name": device.name, "mode": device.mode, "status": effective_status, "central_status": device.status, "owner_paused": device.owner_paused, "online": device.online}})
    except (PermissionDenied, ValidationError) as exc:
        return JsonResponse({"ok": False, "error": str(exc)}, status=403)


@csrf_exempt
@require_POST
def telegram_webhook(request):
    if not settings.TELEGRAM_WEBHOOK_SECRET or request.META.get("HTTP_X_TELEGRAM_BOT_API_SECRET_TOKEN") != settings.TELEGRAM_WEBHOOK_SECRET:
        return JsonResponse({"ok": False}, status=403)
    try:
        update = json_input(request)
        message = update.get("message", {})
        if message.get("text", "").startswith("/start") and message.get("chat", {}).get("id"):
            send_webapp_button(message["chat"]["id"])
    except Exception:
        return JsonResponse({"ok": False}, status=400)
    return JsonResponse({"ok": True})
