from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("control", "0006_security_throttle")]

    operations = [
        migrations.AddField(model_name="device", name="lan_clients", field=models.JSONField(blank=True, default=list)),
    ]
