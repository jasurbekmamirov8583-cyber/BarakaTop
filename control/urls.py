from django.urls import path

from . import views

urlpatterns = [
    path("", views.home, name="home"),
    path("favicon.ico", views.favicon, name="favicon"),
    path("health/", views.health, name="health"),
    path("panel/login/", views.panel_login, name="panel_login"),
    path("panel/logout/", views.panel_logout, name="panel_logout"),
    path("panel/", views.dashboard, name="panel_dashboard"),
    path("panel/telegram/configure/", views.telegram_configure, name="telegram_configure"),
    path("panel/stores/", views.stores, name="stores"),
    path("panel/stores/add/", views.store_edit, name="store_add"),
    path("panel/stores/<uuid:pk>/", views.store_detail, name="store_detail"),
    path("panel/stores/<uuid:pk>/device-status/", views.store_device_status, name="store_device_status"),
    path("panel/stores/<uuid:pk>/edit/", views.store_edit, name="store_edit"),
    path("panel/stores/<uuid:pk>/delete/", views.store_delete, name="store_delete"),
    path("panel/stores/<uuid:pk>/telegram-admin/", views.telegram_admin_add, name="telegram_admin_add"),
    path("panel/telegram-admins/<int:pk>/toggle/", views.telegram_admin_toggle, name="telegram_admin_toggle"),
    path("panel/stores/<uuid:pk>/enrollment/", views.enrollment_add, name="enrollment_add"),
    path("panel/enrollments/<uuid:pk>/revoke/", views.enrollment_revoke, name="enrollment_revoke"),
    path("panel/enrollments/<uuid:pk>/password-reset/", views.enrollment_password_reset, name="enrollment_password_reset"),
    path("panel/stores/<uuid:pk>/alerts/", views.alert_rule_update, name="alert_rule_update"),
    path("panel/devices/<uuid:pk>/", views.device_edit, name="device_edit"),
    path("api/v1/device/activate/", views.device_activate, name="device_activate"),
    path("api/v1/device/verify/", views.device_verify, name="device_verify"),
    path("api/v1/telegram/session/", views.telegram_session, name="telegram_session"),
    path("api/v1/telegram/bootstrap/", views.telegram_bootstrap, name="telegram_bootstrap"),
    path("api/v1/telegram/stores/<uuid:pk>/features/", views.telegram_store_features, name="telegram_store_features"),
    path("api/v1/telegram/stores/<uuid:pk>/devices/<uuid:device_id>/", views.telegram_device_update, name="telegram_device_update"),
    path("telegram/webhook/", views.telegram_webhook, name="telegram_webhook"),
    path("app/", views.miniapp, name="miniapp"),
]
