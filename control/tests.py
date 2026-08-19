import hashlib
import hmac
import json
import time
from datetime import timedelta
from urllib.parse import urlencode
from uuid import uuid4

from django.conf import settings
from django.contrib.auth.hashers import make_password
from django.test import TransactionTestCase, override_settings
from django.utils import timezone

from .models import Device, DeviceEnrollment, Store, StoreAdmin
from .security import activation_key_hash, device_token_hash, ip_allowed, issue_miniapp_session, validate_telegram_init_data


@override_settings(DEVICE_TOKEN_PEPPER="test-pepper", TELEGRAM_BOT_TOKEN="123456:test-token", SECURE_SSL_REDIRECT=False)
class DeviceActivationTests(TransactionTestCase):
    def setUp(self):
        self.store = Store.objects.create(code="shop-1", name="Shop 1", status=Store.Status.ACTIVE)
        self.enrollment = DeviceEnrollment.objects.create(store=self.store, username="device-user", password_hash=make_password("StrongDevicePass1"), label="Main POS", expected_ip_cidrs=["203.0.113.7/32"], mode=DeviceEnrollment.Mode.POS, permissions=["overview", "sales", "inventory", "products"], expires_at=timezone.now() + timedelta(days=1))

    def test_ip_cidr_matching(self):
        self.assertTrue(ip_allowed("203.0.113.7", ["203.0.113.0/24"]))
        self.assertFalse(ip_allowed("203.0.114.7", ["203.0.113.0/24"]))

    def test_one_time_activation_and_verify(self):
        install_id = str(uuid4())
        response = self.client.post("/api/v1/device/activate/", data=json.dumps({"store_code": "shop-1", "username": "device-user", "password": "StrongDevicePass1", "install_id": install_id, "device_name": "Till 1"}), content_type="application/json", HTTP_X_FORWARDED_FOR="203.0.113.7")
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertNotIn(payload["token"], Device.objects.get(install_id=install_id).token_hash)
        verified = self.client.post("/api/v1/device/verify/", data="{}", content_type="application/json", HTTP_AUTHORIZATION=f"Bearer {payload['token']}", HTTP_X_ORBIT_INSTALL_ID=install_id, HTTP_X_FORWARDED_FOR="203.0.113.7")
        self.assertEqual(verified.status_code, 200)

    def test_unlisted_ip_becomes_pending(self):
        response = self.client.post("/api/v1/device/activate/", data=json.dumps({"store_code": "shop-1", "username": "device-user", "password": "StrongDevicePass1", "install_id": str(uuid4()), "device_name": "Unknown"}), content_type="application/json", HTTP_X_FORWARDED_FOR="198.51.100.9")
        self.assertEqual(response.status_code, 202)
        self.assertEqual(response.json()["status"], Device.Status.PENDING)

    def test_one_time_activation_key_auto_binds_first_ip(self):
        store = Store.objects.create(code="key-shop", name="Key Shop", status=Store.Status.ACTIVE, max_devices=1)
        key = "ORBT-1234-5678-ABCD-EF90-1234-5678"
        enrollment = DeviceEnrollment.objects.create(store=store, username="key-login", password_hash=make_password("AnotherStrongPass1"), activation_key_hash=activation_key_hash(key), activation_key_hint="1234-5678", label="Owner PC", mode=DeviceEnrollment.Mode.OWNER, permissions=["overview"], expires_at=timezone.now() + timedelta(days=1))
        install_id = str(uuid4())
        response = self.client.post("/api/v1/device/activate/", data=json.dumps({"store_code": "key-shop", "activation_key": key, "install_id": install_id, "device_name": "Owner"}), content_type="application/json", HTTP_X_FORWARDED_FOR="198.51.100.15")
        self.assertEqual(response.status_code, 200)
        device = Device.objects.get(install_id=install_id)
        enrollment.refresh_from_db()
        self.assertEqual(device.allowed_ip_cidrs, ["198.51.100.15/32"])
        self.assertEqual(device.activation_method, Device.ActivationMethod.KEY)
        self.assertIsNotNone(enrollment.key_used_at)

    def test_store_device_limit_blocks_new_installation(self):
        first = self.client.post("/api/v1/device/activate/", data=json.dumps({"store_code": "shop-1", "username": "device-user", "password": "StrongDevicePass1", "install_id": str(uuid4()), "device_name": "First"}), content_type="application/json", HTTP_X_FORWARDED_FOR="203.0.113.7")
        self.assertEqual(first.status_code, 200)
        second_enrollment = DeviceEnrollment.objects.create(store=self.store, username="second-device", password_hash=make_password("SecondStrongPass1"), label="Second", expected_ip_cidrs=["203.0.113.7/32"], mode=DeviceEnrollment.Mode.POS, permissions=["sales"], expires_at=timezone.now() + timedelta(days=1))
        second = self.client.post("/api/v1/device/activate/", data=json.dumps({"store_code": "shop-1", "username": second_enrollment.username, "password": "SecondStrongPass1", "install_id": str(uuid4()), "device_name": "Second"}), content_type="application/json", HTTP_X_FORWARDED_FOR="203.0.113.7")
        self.assertEqual(second.status_code, 403)
        self.assertIn("limiti", second.json()["error"])

    def test_lan_clients_consume_store_device_slots(self):
        install_id = str(uuid4())
        first = self.client.post("/api/v1/device/activate/", data=json.dumps({"store_code": "shop-1", "username": "device-user", "password": "StrongDevicePass1", "install_id": install_id, "device_name": "Primary"}), content_type="application/json", HTTP_X_FORWARDED_FOR="203.0.113.7")
        self.assertEqual(first.status_code, 200)
        self.store.max_devices = 2; self.store.save(update_fields=("max_devices", "updated_at"))
        verified = self.client.post("/api/v1/device/verify/", data=json.dumps({"lan_clients": [{"id": "lan-1", "name": "Till 2", "mode": "pos", "last_ip": "192.168.1.8", "online": True}]}), content_type="application/json", HTTP_AUTHORIZATION=f"Bearer {first.json()['token']}", HTTP_X_ORBIT_INSTALL_ID=install_id, HTTP_X_FORWARDED_FOR="203.0.113.7")
        self.assertEqual(verified.status_code, 200)
        second_enrollment = DeviceEnrollment.objects.create(store=self.store, username="third-device", password_hash=make_password("ThirdStrongPass1"), label="Third", expected_ip_cidrs=["203.0.113.7/32"], mode=DeviceEnrollment.Mode.POS, permissions=["sales"], expires_at=timezone.now() + timedelta(days=1))
        second = self.client.post("/api/v1/device/activate/", data=json.dumps({"store_code": "shop-1", "username": second_enrollment.username, "password": "ThirdStrongPass1", "install_id": str(uuid4()), "device_name": "Third"}), content_type="application/json", HTTP_X_FORWARDED_FOR="203.0.113.7")
        self.assertEqual(second.status_code, 403)


@override_settings(TELEGRAM_BOT_TOKEN="123456:test-token", SECURE_SSL_REDIRECT=False)
class TelegramValidationTests(TransactionTestCase):
    def signed_data(self, telegram_id=998877):
        values = {"auth_date": str(int(time.time())), "query_id": "abc", "user": json.dumps({"id": telegram_id, "first_name": "Owner"}, separators=(",", ":"))}
        check = "\n".join(f"{key}={value}" for key, value in sorted(values.items()))
        secret = hmac.new(b"WebAppData", settings.TELEGRAM_BOT_TOKEN.encode(), hashlib.sha256).digest()
        values["hash"] = hmac.new(secret, check.encode(), hashlib.sha256).hexdigest()
        return urlencode(values)

    def test_valid_telegram_signature(self):
        self.assertEqual(validate_telegram_init_data(self.signed_data())["id"], 998877)

    def test_session_requires_assigned_store(self):
        store = Store.objects.create(code="telegram-shop", name="Telegram Shop", status=Store.Status.ACTIVE)
        StoreAdmin.objects.create(store=store, telegram_id=998877, display_name="Owner")
        response = self.client.post("/api/v1/telegram/session/", data=json.dumps({"init_data": self.signed_data()}), content_type="application/json")
        self.assertEqual(response.status_code, 200)
        self.assertIn("orbit_mini_session", response.cookies)

    def test_store_admin_can_only_enable_licensed_features(self):
        store = Store.objects.create(code="feature-shop", name="Feature Shop", status=Store.Status.ACTIVE, licensed_features=["pos", "inventory"], enabled_features=["pos"])
        StoreAdmin.objects.create(store=store, telegram_id=998877, display_name="Owner", permissions=["settings"])
        self.client.cookies["orbit_mini_session"] = issue_miniapp_session(998877)
        response = self.client.post(
            f"/api/v1/telegram/stores/{store.pk}/features/",
            data=json.dumps({"features": ["inventory", "finance"]}),
            content_type="application/json",
            HTTP_SEC_FETCH_SITE="same-origin",
        )
        self.assertEqual(response.status_code, 200)
        store.refresh_from_db()
        self.assertEqual(store.active_features, ["inventory"])
