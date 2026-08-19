from django.contrib import admin

from .models import AlertRule, ControlAudit, Device, DeviceEnrollment, Store, StoreAdmin

admin.site.register((Store, StoreAdmin, DeviceEnrollment, Device, AlertRule))


@admin.register(ControlAudit)
class ControlAuditAdmin(admin.ModelAdmin):
    list_display = ("created_at", "action", "store", "actor", "telegram_id", "ip_address")
    readonly_fields = tuple(field.name for field in ControlAudit._meta.fields)

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False
