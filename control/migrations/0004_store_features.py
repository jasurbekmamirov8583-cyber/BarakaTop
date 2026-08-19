from django.db import migrations, models

import control.models

DEFAULT_FEATURES = ["pos", "inventory", "purchasing", "finance", "customers", "reports", "labels", "qr_receipt"]


def seed_features(apps, schema_editor):
    Store = apps.get_model("control", "Store")
    StoreAdmin = apps.get_model("control", "StoreAdmin")
    Store.objects.filter(licensed_features=[]).update(licensed_features=DEFAULT_FEATURES, enabled_features=DEFAULT_FEATURES)
    for admin in StoreAdmin.objects.all().iterator():
        permissions = list(admin.permissions or [])
        for code in ("devices", "staff", "settings"):
            if code not in permissions:
                permissions.append(code)
        admin.permissions = permissions
        admin.save(update_fields=("permissions",))


class Migration(migrations.Migration):
    dependencies = [("control", "0003_activation_keys_device_limit")]
    operations = [
        migrations.AddField(model_name="store", name="licensed_features", field=models.JSONField(blank=True, default=control.models.default_store_features)),
        migrations.AddField(model_name="store", name="enabled_features", field=models.JSONField(blank=True, default=control.models.default_store_features)),
        migrations.RunPython(seed_features, migrations.RunPython.noop),
    ]
