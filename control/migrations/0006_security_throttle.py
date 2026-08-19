import django.utils.timezone
from django.db import migrations, models


def harden_security_throttle(apps, schema_editor):
    if schema_editor.connection.vendor != "postgresql":
        return
    with schema_editor.connection.cursor() as cursor:
        cursor.execute("ALTER TABLE control_securitythrottle ENABLE ROW LEVEL SECURITY")
        cursor.execute("REVOKE ALL PRIVILEGES ON TABLE control_securitythrottle FROM PUBLIC")
        cursor.execute("REVOKE ALL PRIVILEGES ON SEQUENCE control_securitythrottle_id_seq FROM PUBLIC")
        for role in ("anon", "authenticated", "service_role"):
            cursor.execute(
                "SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = %s)", [role]
            )
            if cursor.fetchone()[0]:
                cursor.execute(f"REVOKE ALL PRIVILEGES ON TABLE control_securitythrottle FROM {role}")
                cursor.execute(f"REVOKE ALL PRIVILEGES ON SEQUENCE control_securitythrottle_id_seq FROM {role}")


class Migration(migrations.Migration):
    dependencies = [("control", "0005_device_owner_paused")]

    operations = [
        migrations.CreateModel(
            name="SecurityThrottle",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("key", models.CharField(max_length=64, unique=True)),
                ("scope", models.CharField(db_index=True, max_length=40)),
                ("attempts", models.PositiveSmallIntegerField(default=0)),
                ("window_started_at", models.DateTimeField(default=django.utils.timezone.now)),
                ("blocked_until", models.DateTimeField(blank=True, null=True)),
            ],
            options={"indexes": [models.Index(fields=["scope", "blocked_until"], name="control_sec_scope_5b8f12_idx")]},
        ),
        migrations.RunPython(harden_security_throttle, migrations.RunPython.noop),
    ]
