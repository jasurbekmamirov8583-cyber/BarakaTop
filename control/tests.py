import hashlib
import hmac
import json
import time
from datetime import timedelta
from unittest.mock import patch
from urllib.parse import urlencode
from uuid import uuid4

from asgiref.sync import async_to_sync
from django.conf import settings
from django.contrib.auth.hashers import make_password
from django.contrib.auth.models import User
from django.core.exceptions import PermissionDenied
from django.test import TransactionTestCase, override_settings
from django.utils import timezone

from .forms import StoreForm
from .models import Device, DeviceEnrollment, NotificationReceipt, Store, StoreAdmin
from .privacy import audit_metadata, command_payload, report_params
from .relay import Peer, send_device_event
from .security import (
    activation_key_hash,
    ip_allowed,
    issue_miniapp_session,
    validate_telegram_init_data,
)


@override_settings(DEVICE_TOKEN_PEPPER="test-pepper", TELEGRAM_BOT_TOKEN="123456:test-token", SECURE_SSL_REDIRECT=False)
class DeviceActivationTests(TransactionTestCase):
    def setUp(self):
        self.store = Store.objects.create(code="shop-1", name="Shop 1", status=Store.Status.ACTIVE)
        self.enrollment = DeviceEnrollment.objects.create(store=self.store, username="device-user", password_hash=make_password("StrongDevicePass1"), label="Main POS", expected_ip_cidrs=["203.0.113.7/32"], mode=DeviceEnrollment.Mode.POS, permissions=["overview", "sales", "inventory", "products"], expires_at=timezone.now() + timedelta(days=1))

    def test_ip_cidr_matching(self):
        self.assertTrue(ip_allowed("203.0.113.7", ["203.0.113.0/24"]))
        self.assertFalse(ip_allowed("203.0.114.7", ["203.0.113.0/24"]))

    def test_one_time_activation_and_verify(self):
        self.store.pos_session_unlimited = False
        self.store.pos_session_expires_on = timezone.localdate() + timedelta(days=30)
        self.store.save(update_fields=("pos_session_unlimited", "pos_session_expires_on", "updated_at"))
        install_id = str(uuid4())
        response = self.client.post("/api/v1/device/activate/", data=json.dumps({"store_code": "shop-1", "username": "device-user", "password": "StrongDevicePass1", "install_id": install_id, "device_name": "Till 1"}), content_type="application/json", HTTP_X_FORWARDED_FOR="203.0.113.7")
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["enrollment_username"], "device-user")
        self.assertFalse(payload["lease"]["session_unlimited"])
        self.assertEqual(payload["lease"]["session_expires_on"], self.store.pos_session_expires_on.isoformat())
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
        self.store.max_devices = 2
        self.store.save(update_fields=("max_devices", "updated_at"))
        verified = self.client.post("/api/v1/device/verify/", data=json.dumps({"lan_clients": [{"id": "lan-1", "name": "Till 2", "mode": "pos", "last_ip": "192.168.1.8", "online": True}]}), content_type="application/json", HTTP_AUTHORIZATION=f"Bearer {first.json()['token']}", HTTP_X_ORBIT_INSTALL_ID=install_id, HTTP_X_FORWARDED_FOR="203.0.113.7")
        self.assertEqual(verified.status_code, 200)
        second_enrollment = DeviceEnrollment.objects.create(store=self.store, username="third-device", password_hash=make_password("ThirdStrongPass1"), label="Third", expected_ip_cidrs=["203.0.113.7/32"], mode=DeviceEnrollment.Mode.POS, permissions=["sales"], expires_at=timezone.now() + timedelta(days=1))
        second = self.client.post("/api/v1/device/activate/", data=json.dumps({"store_code": "shop-1", "username": second_enrollment.username, "password": "ThirdStrongPass1", "install_id": str(uuid4()), "device_name": "Third"}), content_type="application/json", HTTP_X_FORWARDED_FOR="203.0.113.7")
        self.assertEqual(second.status_code, 403)


@override_settings(TELEGRAM_BOT_TOKEN="123456:test-token", DEBUG=False, SECURE_SSL_REDIRECT=False)
class TelegramValidationTests(TransactionTestCase):
    def signed_data(self, telegram_id=998877, *, include_signature=True):
        values = {"auth_date": str(int(time.time())), "query_id": "abc", "user": json.dumps({"id": telegram_id, "first_name": "Owner"}, separators=(",", ":"))}
        if include_signature:
            values["signature"] = "telegram-ed25519-signature_v2"
        check = "\n".join(f"{key}={value}" for key, value in sorted(values.items()))
        secret = hmac.new(b"WebAppData", settings.TELEGRAM_BOT_TOKEN.encode(), hashlib.sha256).digest()
        values["hash"] = hmac.new(secret, check.encode(), hashlib.sha256).hexdigest()
        return urlencode(values)

    def test_valid_telegram_signature(self):
        self.assertEqual(validate_telegram_init_data(self.signed_data())["id"], 998877)

    def test_legacy_init_data_without_signature_is_still_valid(self):
        self.assertEqual(
            validate_telegram_init_data(self.signed_data(include_signature=False))["id"],
            998877,
        )

    def test_signature_field_is_part_of_bot_token_hmac(self):
        raw = self.signed_data().replace("signature=telegram-ed25519-signature_v2", "signature=changed")
        with self.assertRaises(PermissionDenied):
            validate_telegram_init_data(raw)

    def test_session_requires_assigned_store(self):
        store = Store.objects.create(code="telegram-shop", name="Telegram Shop", status=Store.Status.ACTIVE)
        StoreAdmin.objects.create(store=store, telegram_id=998877, display_name="Owner")
        response = self.client.post("/api/v1/telegram/session/", data=json.dumps({"init_data": self.signed_data()}), content_type="application/json")
        self.assertEqual(response.status_code, 200)
        self.assertIn("orbit_mini_session", response.cookies)
        self.assertEqual(response.cookies["orbit_mini_session"]["samesite"], "None")

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


@override_settings(SECURE_SSL_REDIRECT=False, TELEGRAM_WEBHOOK_SECRET="webhook-secret")
class ControlActionsTests(TransactionTestCase):
    def setUp(self):
        self.superuser = User.objects.create_superuser("root-admin", password="StrongAdminPass1")
        self.client.force_login(self.superuser)
        session = self.client.session
        session["superadmin_2fa_at"] = timezone.now().timestamp()
        session.save()

    def test_superadmin_can_delete_store(self):
        store = Store.objects.create(code="delete-me", name="Delete Me", status=Store.Status.ACTIVE)
        response = self.client.post(f"/panel/stores/{store.pk}/delete/")
        self.assertEqual(response.status_code, 302)
        self.assertFalse(Store.objects.filter(pk=store.pk).exists())

    def test_store_edit_shows_unlimited_and_calendar_controls(self):
        store = Store.objects.create(code="session-ui", name="Session UI", status=Store.Status.ACTIVE)
        response = self.client.get(f"/panel/stores/{store.pk}/edit/")
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Sessiya cheksiz")
        self.assertContains(response, 'id="id_pos_session_expires_on"')
        self.assertContains(response, "kunlar soni avtomatik hisoblanadi")

    def test_store_detail_renders_all_admin_controls(self):
        store = Store.objects.create(code="detail-ui", name="Detail UI", status=Store.Status.ACTIVE)
        response = self.client.get(f"/panel/stores/{store.pk}/")
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Do‘konni o‘chirish")
        self.assertContains(response, "POS sessiyasi")
        self.assertContains(response, "Aktivatsiya yaratish")

    @patch("control.views.send_webapp_button")
    def test_start_command_replies_for_registered_admin(self, send_button):
        store = Store.objects.create(code="bot-shop", name="Bot Shop", status=Store.Status.ACTIVE)
        StoreAdmin.objects.create(store=store, telegram_id=445566, display_name="Owner")
        response = self.client.post(
            "/telegram/webhook/",
            data=json.dumps({"message": {"chat": {"id": 445566}, "from": {"id": 445566}, "text": "/start"}}),
            content_type="application/json",
            HTTP_X_TELEGRAM_BOT_API_SECRET_TOKEN="webhook-secret",
        )
        self.assertEqual(response.status_code, 200)
        send_button.assert_called_once_with(445566)

    @patch("control.relay.send_sale_notification")
    def test_sale_event_is_delivered_once_and_acknowledged(self, send_sale):
        store = Store.objects.create(code="notice-shop", name="Notice Shop", status=Store.Status.ACTIVE)
        StoreAdmin.objects.create(store=store, telegram_id=778899, display_name="Owner")
        messages = []

        async def capture(message):
            messages.append(message)

        peer = Peer("device-peer", capture, "device", {str(store.pk)}, {str(store.pk): ["sales"]}, "device-id")
        event_id = str(uuid4())
        payload = {"number": "POS-1", "total": "10000", "currency": "UZS", "items": [], "payments": []}
        async_to_sync(send_device_event)(peer, {"event_id": event_id, "event": "sale.completed", "payload": payload})
        async_to_sync(send_device_event)(peer, {"event_id": event_id, "event": "sale.completed", "payload": payload})

        send_sale.assert_called_once_with(778899, "Notice Shop", payload)
        self.assertTrue(NotificationReceipt.objects.get(event_id=event_id).completed_at)
        self.assertEqual([json.loads(message["text"])["type"] for message in messages], ["event_ack", "event_ack"])

    @patch("control.relay.send_sale_notification")
    def test_sale_event_drops_unapproved_payload_fields(self, send_sale):
        store = Store.objects.create(code="private-sale", name="Private Sale", status=Store.Status.ACTIVE)
        StoreAdmin.objects.create(store=store, telegram_id=112233, display_name="Owner")

        async def capture(_message):
            return None

        peer = Peer("private-device", capture, "device", {str(store.pk)}, {str(store.pk): ["sales"]}, "device-id")
        payload = {
            "number": "POS-2", "total": "20000", "currency": "UZS",
            "items": [], "payments": [],
            "internal_note": "SERVERDA SAQLANMASIN",
            "customer_phone": "+998000000000",
        }
        async_to_sync(send_device_event)(peer, {
            "event_id": str(uuid4()), "event": "sale.completed", "payload": payload,
        })
        forwarded = send_sale.call_args.args[2]
        self.assertNotIn("internal_note", forwarded)
        self.assertNotIn("customer_phone", forwarded)
        self.assertFalse(hasattr(NotificationReceipt, "payload"))


class StoreSessionPolicyFormTests(TransactionTestCase):
    def form_data(self, **overrides):
        data = {
            "code": "policy-shop",
            "name": "Policy Shop",
            "owner_name": "Owner",
            "owner_phone": "",
            "status": Store.Status.ACTIVE,
            "max_devices": 1,
            "licensed_features": ["pos", "inventory"],
            "timezone": "Asia/Tashkent",
            "notes": "",
            **overrides,
        }
        return data

    def test_unlimited_session_clears_calendar_date(self):
        form = StoreForm(data=self.form_data(
            pos_session_unlimited="on",
            pos_session_expires_on=(timezone.localdate() + timedelta(days=5)).isoformat(),
        ))
        self.assertTrue(form.is_valid(), form.errors)
        store = form.save()
        self.assertTrue(store.pos_session_unlimited)
        self.assertIsNone(store.pos_session_expires_on)

    def test_calendar_session_requires_future_or_today_date(self):
        missing = StoreForm(data=self.form_data(pos_session_unlimited=""))
        self.assertFalse(missing.is_valid())
        self.assertIn("pos_session_expires_on", missing.errors)

        expiry = timezone.localdate() + timedelta(days=9)
        valid = StoreForm(data=self.form_data(
            code="dated-policy-shop",
            pos_session_unlimited="",
            pos_session_expires_on=expiry.isoformat(),
        ))
        self.assertTrue(valid.is_valid(), valid.errors)
        store = valid.save()
        self.assertEqual(store.pos_session_days_remaining, 10)


class CloudDataBoundaryTests(TransactionTestCase):
    def test_audit_metadata_rejects_business_and_secret_payloads(self):
        cleaned = audit_metadata({
            "report": "overview",
            "payload": {"sales": 100000},
            "items": [{"name": "Mahsulot"}],
            "customer": "Mijoz",
            "password": "secret",
            "token": "secret-token",
        })
        self.assertEqual(cleaned, {"report": "overview"})

    def test_control_database_has_no_pos_business_models(self):
        from django.apps import apps

        model_names = {model.__name__.lower() for model in apps.get_app_config("control").get_models()}
        forbidden = {"sale", "saleline", "product", "stockbalance", "customer", "payment", "purchase"}
        self.assertFalse(model_names.intersection(forbidden))

    def test_relay_forwards_only_known_request_fields(self):
        self.assertEqual(
            report_params({"date_from": "2026-08-01", "date_to": "2026-08-19", "sql": "DROP"}),
            {"date_from": "2026-08-01", "date_to": "2026-08-19"},
        )
        self.assertEqual(
            command_payload("staff.toggle", {"member_id": 7, "password": "hidden", "extra": "no"}),
            {"member_id": 7},
        )
