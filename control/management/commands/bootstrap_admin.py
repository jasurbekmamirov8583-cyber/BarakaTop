import os
from django.contrib.auth.models import User
from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = "Create the first super administrator once without blocking service startup"

    def handle(self, *args, **options):
        username = os.environ.get("BOOTSTRAP_ADMIN_USERNAME", "").strip()
        password = os.environ.get("BOOTSTRAP_ADMIN_PASSWORD", "")
        email = os.environ.get("BOOTSTRAP_ADMIN_EMAIL", "").strip()
        reset_password = os.environ.get("BOOTSTRAP_ADMIN_RESET_PASSWORD", "0") == "1"
        if not username:
            self.stdout.write("BOOTSTRAP_ADMIN_USERNAME is not set; bootstrap skipped.")
            return
        if len(username) > User._meta.get_field("username").max_length:
            self.stderr.write(self.style.ERROR("BOOTSTRAP_ADMIN_USERNAME is too long; bootstrap skipped."))
            return
        existing = User.objects.filter(username=username).first()
        if existing:
            if existing.is_superuser and existing.is_staff:
                if reset_password:
                    if len(password) < 4:
                        self.stderr.write(self.style.ERROR(
                            "Password reset requested, but BOOTSTRAP_ADMIN_PASSWORD has fewer than 4 characters."
                        ))
                        return
                    existing.set_password(password)
                    existing.save(update_fields=("password",))
                    self.stdout.write(self.style.SUCCESS(f"Super administrator {username} password reset."))
                else:
                    self.stdout.write(f"Super administrator {username} already exists; password unchanged.")
            else:
                self.stderr.write(self.style.ERROR(
                    f"User {username} already exists but is not a super administrator; bootstrap skipped."
                ))
            return
        if not password:
            self.stderr.write(self.style.ERROR("BOOTSTRAP_ADMIN_PASSWORD is not set; administrator was not created."))
            return
        if len(password) < 4:
            self.stderr.write(self.style.ERROR(
                "BOOTSTRAP_ADMIN_PASSWORD must contain at least 4 characters; administrator was not created."
            ))
            return
        User.objects.create_superuser(username=username, email=email, password=password)
        self.stdout.write(self.style.SUCCESS(f"Super administrator {username} created."))
