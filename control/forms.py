from __future__ import annotations

from datetime import timedelta
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from django import forms
from django.utils import timezone

from .models import AlertRule, Device, DeviceEnrollment, FEATURE_CHOICES, Store, StoreAdmin
from .security import valid_cidrs

PERMISSIONS = (
    ("overview", "Overview"), ("sales", "Sales reports"), ("inventory", "Inventory"),
    ("products", "Product analytics"), ("finance", "Finance"), ("alerts", "Alerts"),
    ("devices", "Qurilmalarni boshqarish"), ("staff", "Sotuvchilarni boshqarish"),
    ("settings", "Funksiya va printer sozlamalari"),
)


class StoreForm(forms.ModelForm):
    licensed_features = forms.MultipleChoiceField(choices=FEATURE_CHOICES, widget=forms.CheckboxSelectMultiple, label="Do‘konga ruxsat etilgan funksiyalar")

    class Meta:
        model = Store
        fields = ("code", "name", "owner_name", "owner_phone", "status", "max_devices", "licensed_features", "timezone", "notes")
        labels = {"max_devices": "Ruxsat etilgan qurilmalar soni"}
        widgets = {"notes": forms.Textarea(attrs={"rows": 3})}

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
    permissions = forms.MultipleChoiceField(choices=PERMISSIONS, widget=forms.CheckboxSelectMultiple)

    class Meta:
        model = StoreAdmin
        fields = ("telegram_id", "display_name", "permissions", "active")


class EnrollmentForm(forms.Form):
    label = forms.CharField(max_length=160)
    username = forms.CharField(max_length=100, required=False, help_text="Bo‘sh qoldirilsa avtomatik yaratiladi.")
    password = forms.CharField(required=False, min_length=10, widget=forms.PasswordInput, help_text="Leave blank to generate a strong password.")
    mode = forms.ChoiceField(choices=DeviceEnrollment.Mode.choices)
    expected_ip_cidrs = forms.CharField(required=False, widget=forms.Textarea(attrs={"rows": 2}), help_text="Har qatorda IP/CIDR. Bo‘sh bo‘lsa birinchi ko‘rilgan IP avtomatik /32 ruxsatga olinadi.")
    permissions = forms.MultipleChoiceField(choices=PERMISSIONS, widget=forms.CheckboxSelectMultiple)
    expires_days = forms.IntegerField(min_value=1, max_value=90, initial=7)
    max_uses = forms.IntegerField(min_value=1, max_value=20, initial=1)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["permissions"].initial = ["overview", "sales", "inventory", "products", "alerts"]

    def clean_expected_ip_cidrs(self):
        return valid_cidrs(self.cleaned_data["expected_ip_cidrs"])

    def clean_username(self):
        username = self.cleaned_data["username"].strip()
        if username and DeviceEnrollment.objects.filter(username__iexact=username).exists():
            raise forms.ValidationError("This activation login already exists.")
        return username

    def expires_at(self):
        return timezone.now() + timedelta(days=self.cleaned_data["expires_days"])


class DeviceForm(forms.ModelForm):
    allowed_ip_cidrs = forms.CharField(required=False, widget=forms.Textarea(attrs={"rows": 2}))
    permissions = forms.MultipleChoiceField(choices=PERMISSIONS, widget=forms.CheckboxSelectMultiple)

    class Meta:
        model = Device
        fields = ("name", "status", "mode", "allowed_ip_cidrs", "permissions", "notes")
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
