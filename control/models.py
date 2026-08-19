from __future__ import annotations

import uuid
from datetime import timedelta

from django.contrib.auth.models import User
from django.db import models
from django.utils import timezone
from django.core.exceptions import ValidationError


def default_admin_permissions():
    return ["overview", "sales", "inventory", "products", "alerts", "devices", "staff", "settings"]


FEATURE_CHOICES = (
    ("pos", "Kassa va savdo"), ("inventory", "Ombor"), ("purchasing", "Xaridlar"),
    ("finance", "Moliya"), ("customers", "Mijozlar va qarz"), ("reports", "Hisobotlar"),
    ("labels", "Etiketka muharriri"), ("qr_receipt", "QR-kodli chek"),
    ("variants", "Mahsulot variantlari"), ("stock_count", "Skaner inventarizatsiyasi"),
    ("advanced_inventory", "FIFO/FEFO va xarid tavsiyasi"), ("promotions", "Aksiya va promo-kodlar"),
    ("seller_kpi", "Sotuvchi reja va komissiyasi"), ("hardware", "Tarozi va mijoz displeyi"),
    ("fiscal", "Asl Belgisi, IKPU va E-POS"),
    ("crm", "CRM"), ("loyalty", "Sodiqlik va bonus"), ("integrations", "Integratsiyalar"),
    ("automation", "Avtomatlashtirish"), ("marketing", "Marketing"),
    ("manufacturing", "Ishlab chiqarish"), ("restaurant", "Restoran"), ("employees", "Xodimlar"),
)

PERMISSION_CHOICES = (
    ("overview", "Umumiy ko‘rsatkichlar"), ("sales", "Savdo hisobotlari"),
    ("inventory", "Ombor qoldiqlari"), ("products", "Mahsulotlar tahlili"),
    ("finance", "Moliya"), ("alerts", "Ogohlantirishlar"),
    ("devices", "Qurilmalarni boshqarish"), ("staff", "Sotuvchilarni boshqarish"),
    ("settings", "Funksiya va printer sozlamalari"),
)

FEATURE_LABELS = dict(FEATURE_CHOICES)
PERMISSION_LABELS = dict(PERMISSION_CHOICES)


def default_store_features():
    return ["pos", "inventory", "purchasing", "finance", "customers", "reports", "labels", "qr_receipt"]


class Stamp(models.Model):
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True


class AuditQuerySet(models.QuerySet):
    def update(self, **kwargs):
        raise ValidationError("Control audit is append-only.")

    def delete(self):
        raise ValidationError("Control audit is append-only.")


class Store(Stamp):
    class Status(models.TextChoices):
        TRIAL = "trial", "Sinov muddati"
        ACTIVE = "active", "Faol"
        SUSPENDED = "suspended", "Vaqtincha to‘xtatilgan"
        CLOSED = "closed", "Yopilgan"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    code = models.SlugField(max_length=40, unique=True)
    name = models.CharField(max_length=180)
    owner_name = models.CharField(max_length=180, blank=True)
    owner_phone = models.CharField(max_length=40, blank=True)
    status = models.CharField(max_length=12, choices=Status.choices, default=Status.TRIAL, db_index=True)
    max_devices = models.PositiveSmallIntegerField(default=1)
    licensed_features = models.JSONField(default=default_store_features, blank=True)
    enabled_features = models.JSONField(default=default_store_features, blank=True)
    timezone = models.CharField(max_length=64, default="Asia/Tashkent")
    notes = models.TextField(blank=True)

    class Meta:
        ordering = ("name",)

    def __str__(self):
        return f"{self.name} ({self.code})"

    @property
    def licensed_device_count(self):
        devices = list(self.devices.exclude(status=Device.Status.REVOKED))
        return len(devices) + sum(len(device.lan_clients or []) for device in devices)

    @property
    def active_features(self):
        return [code for code in self.enabled_features if code in set(self.licensed_features)]

    @property
    def licensed_feature_labels(self):
        return [FEATURE_LABELS.get(code, code) for code in self.licensed_features]

    @property
    def active_feature_labels(self):
        return [FEATURE_LABELS.get(code, code) for code in self.active_features]


class StoreAdmin(Stamp):
    store = models.ForeignKey(Store, on_delete=models.CASCADE, related_name="telegram_admins")
    telegram_id = models.BigIntegerField(db_index=True)
    display_name = models.CharField(max_length=180, blank=True)
    active = models.BooleanField(default=True)
    permissions = models.JSONField(default=default_admin_permissions)

    class Meta:
        constraints = [models.UniqueConstraint(fields=("store", "telegram_id"), name="uq_store_telegram_admin")]

    @property
    def permission_labels(self):
        return [PERMISSION_LABELS.get(code, code) for code in self.permissions]


class DeviceEnrollment(Stamp):
    class Mode(models.TextChoices):
        OWNER = "owner", "Do‘kon egasi kompyuteri"
        POS = "pos", "Sotuvchi / Kassa"
        WAREHOUSE = "warehouse", "Omborchi"
        MANAGER = "manager", "Menejer"
        UNIVERSAL = "universal", "Universal / maqom almashtirish"
        READ_ONLY = "read_only", "Faqat ko‘rish"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    store = models.ForeignKey(Store, on_delete=models.CASCADE, related_name="enrollments")
    username = models.CharField(max_length=100, unique=True)
    password_hash = models.CharField(max_length=256)
    activation_key_hash = models.CharField(max_length=64, unique=True, null=True, blank=True)
    activation_key_hint = models.CharField(max_length=12, blank=True)
    key_used_at = models.DateTimeField(null=True, blank=True)
    label = models.CharField(max_length=160)
    expected_ip_cidrs = models.JSONField(default=list, blank=True)
    mode = models.CharField(max_length=20, choices=Mode.choices, default=Mode.POS)
    permissions = models.JSONField(default=list, blank=True)
    expires_at = models.DateTimeField()
    max_uses = models.PositiveSmallIntegerField(default=1)
    used_count = models.PositiveSmallIntegerField(default=0)
    active = models.BooleanField(default=True)
    created_by = models.ForeignKey(User, null=True, on_delete=models.SET_NULL)

    @property
    def usable(self):
        return self.active and self.used_count < self.max_uses and self.expires_at > timezone.now()


class Device(Stamp):
    class Status(models.TextChoices):
        PENDING = "pending", "Tasdiq kutilmoqda"
        ACTIVE = "active", "Faol"
        BLOCKED = "blocked", "Bloklangan"
        REVOKED = "revoked", "Ruxsati bekor qilingan"

    class ActivationMethod(models.TextChoices):
        PASSWORD = "password", "Login va parol"
        KEY = "key", "Aktivatsiya kaliti"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    store = models.ForeignKey(Store, on_delete=models.CASCADE, related_name="devices")
    enrollment = models.ForeignKey(DeviceEnrollment, null=True, on_delete=models.SET_NULL)
    install_id = models.UUIDField(unique=True)
    name = models.CharField(max_length=180)
    status = models.CharField(max_length=12, choices=Status.choices, default=Status.PENDING, db_index=True)
    owner_paused = models.BooleanField(default=False, db_index=True)
    mode = models.CharField(max_length=20, choices=DeviceEnrollment.Mode.choices)
    permissions = models.JSONField(default=list)
    token_hash = models.CharField(max_length=64, unique=True)
    allowed_ip_cidrs = models.JSONField(default=list, blank=True)
    first_ip = models.GenericIPAddressField(null=True, blank=True)
    last_ip = models.GenericIPAddressField(null=True, blank=True)
    last_seen_at = models.DateTimeField(null=True, blank=True, db_index=True)
    app_version = models.CharField(max_length=32, blank=True)
    platform = models.CharField(max_length=160, blank=True)
    activation_method = models.CharField(max_length=12, choices=ActivationMethod.choices, default=ActivationMethod.PASSWORD)
    lan_clients = models.JSONField(default=list, blank=True)
    notes = models.TextField(blank=True)

    class Meta:
        ordering = ("name",)

    @property
    def online(self):
        return bool(
            self.status == self.Status.ACTIVE
            and not self.owner_paused
            and self.store.status in {Store.Status.TRIAL, Store.Status.ACTIVE}
            and self.last_seen_at
            and self.last_seen_at >= timezone.now() - timedelta(minutes=3)
        )


class AlertRule(Stamp):
    store = models.ForeignKey(Store, on_delete=models.CASCADE, related_name="alert_rules")
    event = models.CharField(max_length=40, default="low_stock")
    enabled = models.BooleanField(default=True)
    cooldown_minutes = models.PositiveIntegerField(default=120)
    last_sent_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=("store", "event"), name="uq_store_alert_event")]


class ControlAudit(models.Model):
    objects = models.Manager.from_queryset(AuditQuerySet)()
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    actor = models.ForeignKey(User, null=True, blank=True, on_delete=models.SET_NULL)
    telegram_id = models.BigIntegerField(null=True, blank=True)
    store = models.ForeignKey(Store, null=True, blank=True, on_delete=models.SET_NULL)
    action = models.CharField(max_length=80)
    entity_type = models.CharField(max_length=80)
    entity_id = models.CharField(max_length=80)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    metadata = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ("-created_at",)

    @property
    def action_label(self):
        return {
            "store.create": "Do‘kon yaratildi", "store.update": "Do‘kon yangilandi",
            "telegram_admin.create": "Telegram admin biriktirildi",
            "telegram_admin.toggle": "Telegram admin holati o‘zgardi",
            "enrollment.create": "Aktivatsiya yaratildi", "enrollment.revoke": "Aktivatsiya bekor qilindi",
            "enrollment.password_reset": "Aktivatsiya paroli yangilandi",
            "device.update": "Qurilma ruxsatlari yangilandi", "device.activate": "Qurilma faollashtirildi",
            "device.pending": "Qurilma tasdiqqa yuborildi", "device.owner_update": "Qurilma egasi sozlamani o‘zgartirdi",
            "store.features": "Do‘kon funksiyalari yangilandi", "alert_rule.update": "Ogohlantirish sozlamasi yangilandi",
        }.get(self.action, self.action)

    def save(self, *args, **kwargs):
        if self.pk and type(self).objects.filter(pk=self.pk).exists():
            raise ValidationError("Control audit is append-only.")
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValidationError("Control audit is append-only.")


class SecurityThrottle(models.Model):
    key = models.CharField(max_length=64, unique=True)
    scope = models.CharField(max_length=40, db_index=True)
    attempts = models.PositiveSmallIntegerField(default=0)
    window_started_at = models.DateTimeField(default=timezone.now)
    blocked_until = models.DateTimeField(null=True, blank=True)

    class Meta:
        indexes = [models.Index(fields=("scope", "blocked_until"), name="control_sec_scope_5b8f12_idx")]
