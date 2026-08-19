from __future__ import annotations

import os
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

BASE_DIR = Path(__file__).resolve().parent.parent
SECRET_KEY = os.environ.get("DJANGO_SECRET_KEY", "unsafe-development-only-change-me")
DEBUG = os.environ.get("DEBUG", "0") == "1"
if not DEBUG and SECRET_KEY == "unsafe-development-only-change-me":
    raise RuntimeError("DJANGO_SECRET_KEY must be set outside development.")
ALLOWED_HOSTS = [v.strip() for v in os.environ.get("ALLOWED_HOSTS", "127.0.0.1,localhost").split(",") if v.strip()]
CSRF_TRUSTED_ORIGINS = [v.strip() for v in os.environ.get("CSRF_TRUSTED_ORIGINS", "").split(",") if v.strip()]
PUBLIC_BASE_URL = os.environ.get("PUBLIC_BASE_URL", "http://127.0.0.1:8000").rstrip("/")
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_WEBHOOK_SECRET = os.environ.get("TELEGRAM_WEBHOOK_SECRET", "")
DEVICE_TOKEN_PEPPER = os.environ.get("DEVICE_TOKEN_PEPPER", SECRET_KEY)

INSTALLED_APPS = [
    "django.contrib.admin", "django.contrib.auth", "django.contrib.contenttypes",
    "django.contrib.sessions", "django.contrib.messages", "django.contrib.staticfiles",
    "control.apps.ControlConfig",
]
MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware", "control_config.middleware.SecurityHeadersMiddleware", "whitenoise.middleware.WhiteNoiseMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware", "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware", "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware", "django.middleware.clickjacking.XFrameOptionsMiddleware",
]
ROOT_URLCONF = "control_config.urls"
TEMPLATES = [{"BACKEND": "django.template.backends.django.DjangoTemplates", "DIRS": [BASE_DIR / "templates"], "APP_DIRS": True, "OPTIONS": {"context_processors": ["django.template.context_processors.request", "django.contrib.auth.context_processors.auth", "django.contrib.messages.context_processors.messages", "control.context.control_context"]}}]
WSGI_APPLICATION = "control_config.wsgi.application"
ASGI_APPLICATION = "control_config.asgi.application"


def database_config(url: str):
    if not url:
        return {"ENGINE": "django.db.backends.sqlite3", "NAME": BASE_DIR / "control-dev.sqlite3"}
    parsed = urlparse(url)
    if parsed.scheme not in {"postgres", "postgresql"}:
        raise RuntimeError("DATABASE_URL must be PostgreSQL.")
    query = parse_qs(parsed.query)
    return {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": parsed.path.lstrip("/") or "postgres",
        "USER": unquote(parsed.username or ""), "PASSWORD": unquote(parsed.password or ""),
        "HOST": parsed.hostname or "", "PORT": parsed.port or 5432,
        "CONN_MAX_AGE": 60,
        "OPTIONS": {"sslmode": query.get("sslmode", ["require"])[0]},
    }


DATABASES = {"default": database_config(os.environ.get("DATABASE_URL", ""))}
AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator", "OPTIONS": {"min_length": 10}},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]
LANGUAGE_CODE = "uz-latn"
TIME_ZONE = "Asia/Tashkent"
USE_I18N = True
USE_TZ = True
STATIC_URL = "/static/"
STATIC_ROOT = BASE_DIR / "staticfiles"
STATICFILES_DIRS = [BASE_DIR / "static"]
STORAGES = {"staticfiles": {"BACKEND": "whitenoise.storage.CompressedManifestStaticFilesStorage"}}
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
LOGIN_URL = "panel_login"
LOGIN_REDIRECT_URL = "panel_dashboard"
LOGOUT_REDIRECT_URL = "panel_login"
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"
SESSION_COOKIE_SECURE = not DEBUG
CSRF_COOKIE_SECURE = not DEBUG
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
SECURE_SSL_REDIRECT = not DEBUG
SECURE_HSTS_SECONDS = 31_536_000 if not DEBUG else 0
SECURE_HSTS_INCLUDE_SUBDOMAINS = False
SECURE_HSTS_PRELOAD = False
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = "SAMEORIGIN"
DATA_UPLOAD_MAX_MEMORY_SIZE = 1_000_000
MINIAPP_SESSION_MAX_AGE = 43_200
SUPERADMIN_TOTP_SECRET = os.environ.get("SUPERADMIN_TOTP_SECRET", "").replace(" ", "").upper()
if not DEBUG and (
    len(SUPERADMIN_TOTP_SECRET) < 16
    or any(character not in "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567" for character in SUPERADMIN_TOTP_SECRET)
):
    raise RuntimeError("SUPERADMIN_TOTP_SECRET must be a valid Base32 secret of at least 16 characters.")
DEVICE_LEASE_SECONDS = max(3600, min(int(os.environ.get("DEVICE_LEASE_SECONDS", "604800")), 2_592_000))
