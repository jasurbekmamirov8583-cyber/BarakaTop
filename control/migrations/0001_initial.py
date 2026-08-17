import control.models
import django.db.models.deletion
import uuid
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):
    initial = True
    dependencies = [migrations.swappable_dependency(settings.AUTH_USER_MODEL)]
    operations = [
        migrations.CreateModel(
            name="Store",
            fields=[
                ("created_at", models.DateTimeField(auto_now_add=True)), ("updated_at", models.DateTimeField(auto_now=True)),
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("code", models.SlugField(max_length=40, unique=True)), ("name", models.CharField(max_length=180)),
                ("owner_name", models.CharField(blank=True, max_length=180)), ("owner_phone", models.CharField(blank=True, max_length=40)),
                ("status", models.CharField(choices=[("trial", "Trial"), ("active", "Active"), ("suspended", "Suspended"), ("closed", "Closed")], db_index=True, default="trial", max_length=12)),
                ("timezone", models.CharField(default="Asia/Tashkent", max_length=64)), ("notes", models.TextField(blank=True)),
            ], options={"ordering": ("name",)},
        ),
        migrations.CreateModel(
            name="StoreAdmin",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("created_at", models.DateTimeField(auto_now_add=True)), ("updated_at", models.DateTimeField(auto_now=True)),
                ("telegram_id", models.BigIntegerField(db_index=True)), ("display_name", models.CharField(blank=True, max_length=180)),
                ("active", models.BooleanField(default=True)), ("permissions", models.JSONField(default=control.models.default_admin_permissions)),
                ("store", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="telegram_admins", to="control.store")),
            ],
        ),
        migrations.CreateModel(
            name="DeviceEnrollment",
            fields=[
                ("created_at", models.DateTimeField(auto_now_add=True)), ("updated_at", models.DateTimeField(auto_now=True)),
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("username", models.CharField(max_length=100, unique=True)), ("password_hash", models.CharField(max_length=256)),
                ("label", models.CharField(max_length=160)), ("expected_ip_cidrs", models.JSONField(blank=True, default=list)),
                ("mode", models.CharField(choices=[("owner", "Owner workstation"), ("pos", "POS register"), ("warehouse", "Warehouse"), ("manager", "Manager"), ("universal", "Universal / role switching"), ("read_only", "Read only")], default="pos", max_length=20)),
                ("permissions", models.JSONField(blank=True, default=list)), ("expires_at", models.DateTimeField()),
                ("max_uses", models.PositiveSmallIntegerField(default=1)), ("used_count", models.PositiveSmallIntegerField(default=0)),
                ("active", models.BooleanField(default=True)),
                ("created_by", models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, to=settings.AUTH_USER_MODEL)),
                ("store", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="enrollments", to="control.store")),
            ],
        ),
        migrations.CreateModel(
            name="Device",
            fields=[
                ("created_at", models.DateTimeField(auto_now_add=True)), ("updated_at", models.DateTimeField(auto_now=True)),
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("install_id", models.UUIDField(unique=True)), ("name", models.CharField(max_length=180)),
                ("status", models.CharField(choices=[("pending", "Pending approval"), ("active", "Active"), ("blocked", "Blocked"), ("revoked", "Revoked")], db_index=True, default="pending", max_length=12)),
                ("mode", models.CharField(choices=[("owner", "Owner workstation"), ("pos", "POS register"), ("warehouse", "Warehouse"), ("manager", "Manager"), ("universal", "Universal / role switching"), ("read_only", "Read only")], max_length=20)),
                ("permissions", models.JSONField(default=list)), ("token_hash", models.CharField(max_length=64, unique=True)),
                ("allowed_ip_cidrs", models.JSONField(blank=True, default=list)), ("first_ip", models.GenericIPAddressField(blank=True, null=True)),
                ("last_ip", models.GenericIPAddressField(blank=True, null=True)), ("last_seen_at", models.DateTimeField(blank=True, db_index=True, null=True)),
                ("app_version", models.CharField(blank=True, max_length=32)), ("platform", models.CharField(blank=True, max_length=160)),
                ("notes", models.TextField(blank=True)),
                ("enrollment", models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, to="control.deviceenrollment")),
                ("store", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="devices", to="control.store")),
            ], options={"ordering": ("name",)},
        ),
        migrations.CreateModel(
            name="AlertRule",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("created_at", models.DateTimeField(auto_now_add=True)), ("updated_at", models.DateTimeField(auto_now=True)),
                ("event", models.CharField(default="low_stock", max_length=40)), ("enabled", models.BooleanField(default=True)),
                ("cooldown_minutes", models.PositiveIntegerField(default=120)), ("last_sent_at", models.DateTimeField(blank=True, null=True)),
                ("store", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="alert_rules", to="control.store")),
            ],
        ),
        migrations.CreateModel(
            name="ControlAudit",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("created_at", models.DateTimeField(auto_now_add=True, db_index=True)), ("telegram_id", models.BigIntegerField(blank=True, null=True)),
                ("action", models.CharField(max_length=80)), ("entity_type", models.CharField(max_length=80)),
                ("entity_id", models.CharField(max_length=80)), ("ip_address", models.GenericIPAddressField(blank=True, null=True)),
                ("metadata", models.JSONField(blank=True, default=dict)),
                ("actor", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to=settings.AUTH_USER_MODEL)),
                ("store", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to="control.store")),
            ], options={"ordering": ("-created_at",)},
        ),
        migrations.AddConstraint(model_name="storeadmin", constraint=models.UniqueConstraint(fields=("store", "telegram_id"), name="uq_store_telegram_admin")),
        migrations.AddConstraint(model_name="alertrule", constraint=models.UniqueConstraint(fields=("store", "event"), name="uq_store_alert_event")),
    ]
