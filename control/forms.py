from __future__ import annotations

from datetime import timedelta
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from django import forms
from django.utils import timezone

from .models import AlertRule, Device, DeviceEnrollment, FEATURE_CHOICES, PERMISSION_CHOICES, Store, StoreAdmin
from .security import valid_cidrs

class StoreForm(forms.ModelForm):
    licensed_features = forms.MultipleChoiceField(choices=FEATURE_CHOICES, widget=forms.CheckboxSelectMultiple, label="Do‘konga ruxsat etilgan funksiyalar")

    class Meta:
        model = Store
        fields = ("code", "name", "owner_name", "owner_phone", "status", "max_devices", "licensed_features", "timezone", "notes")
        labels = {
            "code": "Do‘kon kodi", "name": "Do‘kon nomi", "owner_name": "Egasi F.I.Sh.",
            "owner_phone": "Telefon raqami", "status": "Holati",
            "max_devices": "Ruxsat etilgan qurilmalar soni", "timezone": "Vaqt mintaqasi",
            "notes": "Izoh",
        }
        help_texts = {
            "code": "Takrorlanmaydigan qisqa kod. Masalan: olympic-01. Lotin harflari, raqam va chiziqcha ishlating.",
            "timezone": "O‘zbekiston uchun Asia/Tashkent qiymatini qoldiring.",
            "notes": "Faqat super-admin ko‘radigan ichki izoh.",
        }
        widgets = {"notes": forms.Textarea(attrs={"rows": 3, "placeholder": "Ixtiyoriy izoh"})}

    def save(self, commit=True):
        adding = self.instance._state.adding
        store = super().save(False)
        licensed = list(self.cleaned_data["licensed_features"])
        store.licensed_features = licensed
        current = list(store.enabled_features or [])
        store.enabled_features = licensed if adding else [code for code in current if code in licensed]
        if commit:
            store.save()
        return store

    def clean_timezone(self):
        value = self.cleaned_data["timezone"].strip()
        try:
            ZoneInfo(value)
        except ZoneInfoNotFoundError as exc:
            raise forms.ValidationError("IANA vaqt zonasi noto‘g‘ri. Masalan: Asia/Tashkent") from exc
        return value


class TelegramAdminForm(forms.ModelForm):
    permissions = forms.MultipleChoiceField(choices=PERMISSION_CHOICES, widget=forms.CheckboxSelectMultiple, label="Ruxsatlar")

    class Meta:
        model = StoreAdmin
        fields = ("telegram_id", "display_name", "permissions", "active")
        labels = {"telegram_id": "Telegram ID", "display_name": "Ismi", "active": "Faol"}
        help_texts = {"telegram_id": "Foydalanuvchining raqamli Telegram ID si."}


class EnrollmentForm(forms.Form):
    label = forms.CharField(max_length=160, label="Qurilma nomi", help_text="Masalan: Asosiy kassa yoki Ombor kompyuteri.")
    username = forms.CharField(max_length=100, required=False, label="Login", help_text="Bo‘sh qoldirilsa avtomatik yaratiladi.")
    password = forms.CharField(required=False, min_length=4, label="Parol", widget=forms.PasswordInput, help_text="Bo‘sh qoldirilsa kuchli parol avtomatik yaratiladi.")
    mode = forms.ChoiceField(choices=DeviceEnrollment.Mode.choices, label="Ishlash maqomi")
    expected_ip_cidrs = forms.CharField(required=False, label="Ruxsat etilgan IP/CIDR", widget=forms.Textarea(attrs={"rows": 2}), help_text="Har qatorda bittadan IP/CIDR. Bo‘sh bo‘lsa birinchi ko‘rilgan IP avtomatik ruxsatga olinadi.")
    permissions = forms.MultipleChoiceField(choices=PERMISSION_CHOICES, widget=forms.CheckboxSelectMultiple, label="Ruxsatlar")
    expires_days = forms.IntegerField(min_value=1, max_value=90, initial=7, label="Amal qilish muddati (kun)")
    max_uses = forms.IntegerField(min_value=1, max_value=20, initial=1, label="Ulanishi mumkin bo‘lgan qurilmalar soni")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["permissions"].initial = ["overview", "sales", "inventory", "products", "alerts"]

    def clean_expected_ip_cidrs(self):
        return valid_cidrs(self.cleaned_data["expected_ip_cidrs"])

    def clean_username(self):
        username = self.cleaned_data["username"].strip()
        if username and DeviceEnrollment.objects.filter(username__iexact=username).exists():
            raise forms.ValidationError("Bu aktivatsiya logini avval yaratilgan.")
        return username

    def expires_at(self):
        return timezone.now() + timedelta(days=self.cleaned_data["expires_days"])


class DeviceForm(forms.ModelForm):
    allowed_ip_cidrs = forms.CharField(required=False, label="Ruxsat etilgan IP/CIDR", widget=forms.Textarea(attrs={"rows": 2}), help_text="Har qatorda bittadan IP yoki CIDR yozing.")
    permissions = forms.MultipleChoiceField(choices=PERMISSION_CHOICES, widget=forms.CheckboxSelectMultiple, label="Ruxsatlar")

    class Meta:
        model = Device
        fields = ("name", "status", "mode", "allowed_ip_cidrs", "permissions", "notes")
        labels = {"name": "Qurilma nomi", "status": "Holati", "mode": "Ishlash maqomi", "notes": "Izoh"}
        widgets = {"notes": forms.Textarea(attrs={"rows": 3})}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.instance.pk:
            self.initial["allowed_ip_cidrs"] = "\n".join(self.instance.allowed_ip_cidrs)

    def clean_allowed_ip_cidrs(self):
        return valid_cidrs(self.cleaned_data["allowed_ip_cidrs"])


class AlertRuleForm(forms.ModelForm):
    class Meta:
        model = AlertRule
        fields = ("enabled", "cooldown_minutes")
        labels = {"enabled": "Telegram ogohlantirishlari faol", "cooldown_minutes": "Takrorlash oralig‘i (daqiqa)"}

    def clean_cooldown_minutes(self):
        value = self.cleaned_data["cooldown_minutes"]
        if not 15 <= value <= 10080:
            raise forms.ValidationError("Oraliq 15 daqiqadan 7 kungacha bo‘lishi kerak.")
        return value
