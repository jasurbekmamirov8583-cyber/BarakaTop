from __future__ import annotations

import os
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

BASE_DIR = Path(__file__).resolve().parent.parent
SECRET_KEY = os.environ.get("DJANGO_SECRET_KEY", "unsafe-development-only-change-me")
DEBUG = os.environ.get("DEBUG", "0") == "1"
if not DEBUG and SECRET_KEY == "unsafe-development-only-change-me":
    raise RuntimeError("DJANGO_SECRET_KEY must be set outside development.")
RENDER_EXTERNAL_HOSTNAME = os.environ.get("RENDER_EXTERNAL_HOSTNAME", "").strip()
RENDER_EXTERNAL_URL = os.environ.get("RENDER_EXTERNAL_URL", "").strip().rstrip("/")
PUBLIC_BASE_URL = (
    os.environ.get("PUBLIC_BASE_URL", "").strip()
    or RENDER_EXTERNAL_URL
    or (f"https://{RENDER_EXTERNAL_HOSTNAME}" if RENDER_EXTERNAL_HOSTNAME else "http://127.0.0.1:8000")
).rstrip("/")
public_url = urlparse(PUBLIC_BASE_URL)
configured_hosts = [value.strip() for value in os.environ.get("ALLOWED_HOSTS", "").split(",") if value.strip()]
ALLOWED_HOSTS = list(dict.fromkeys([
    "127.0.0.1", "localhost", *configured_hosts,
    *([RENDER_EXTERNAL_HOSTNAME] if RENDER_EXTERNAL_HOSTNAME else []),
    *([public_url.hostname] if public_url.hostname else []),
]))
configured_origins = [value.strip().rstrip("/") for value in os.environ.get("CSRF_TRUSTED_ORIGINS", "").split(",") if value.strip()]
public_origin = f"{public_url.scheme}://{public_url.netloc}" if public_url.scheme in {"http", "https"} and public_url.netloc else ""
CSRF_TRUSTED_ORIGINS = list(dict.fromkeys([*configured_origins, *([public_origin] if public_origin else [])]))
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
SUPERADMIN_TOTP_CONFIGURED = bool(SUPERADMIN_TOTP_SECRET)
SUPERADMIN_TOTP_ENABLED = SUPERADMIN_TOTP_CONFIGURED and not (
    len(SUPERADMIN_TOTP_SECRET) < 16
    or any(character not in "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567" for character in SUPERADMIN_TOTP_SECRET)
)
SUPERADMIN_TOTP_INVALID = SUPERADMIN_TOTP_CONFIGURED and not SUPERADMIN_TOTP_ENABLED
DEVICE_LEASE_SECONDS = max(3600, min(int(os.environ.get("DEVICE_LEASE_SECONDS", "604800")), 2_592_000))
