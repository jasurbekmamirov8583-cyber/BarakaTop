from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("control", "0002_harden_supabase")]
    operations = [
        migrations.AddField(model_name="store", name="max_devices", field=models.PositiveSmallIntegerField(default=1)),
        migrations.AddField(model_name="deviceenrollment", name="activation_key_hash", field=models.CharField(blank=True, max_length=64, null=True, unique=True)),
        migrations.AddField(model_name="deviceenrollment", name="activation_key_hint", field=models.CharField(blank=True, max_length=12)),
        migrations.AddField(model_name="deviceenrollment", name="key_used_at", field=models.DateTimeField(blank=True, null=True)),
        migrations.AddField(model_name="device", name="activation_method", field=models.CharField(choices=[("password", "Login and password"), ("key", "Activation key")], default="password", max_length=12)),
    ]
