from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("control", "0004_store_features")]

    operations = [
        migrations.AddField(
            model_name="device",
            name="owner_paused",
            field=models.BooleanField(db_index=True, default=False),
        ),
    ]
