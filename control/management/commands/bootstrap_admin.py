import os
from django.contrib.auth.models import User
from django.core.management.base import BaseCommand, CommandError


class Command(BaseCommand):
    help = "Create the first super administrator from environment variables"

    def handle(self, *args, **options):
        username = os.environ.get("BOOTSTRAP_ADMIN_USERNAME", "").strip()
        password = os.environ.get("BOOTSTRAP_ADMIN_PASSWORD", "")
        email = os.environ.get("BOOTSTRAP_ADMIN_EMAIL", "").strip()
        if not username or not password:
            self.stdout.write("Bootstrap administrator variables are not set; skipped.")
            return
        if len(password) < 12:
            raise CommandError("BOOTSTRAP_ADMIN_PASSWORD must contain at least 12 characters.")
        user, created = User.objects.get_or_create(username=username, defaults={"email": email, "is_staff": True, "is_superuser": True})
        if created:
            user.set_password(password); user.save(update_fields=("password",))
            self.stdout.write(self.style.SUCCESS(f"Super administrator {username} created."))
        else:
            self.stdout.write(f"Super administrator {username} already exists; password unchanged.")
