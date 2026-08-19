from django.conf import settings
from django.contrib import admin
from django.urls import include, path

urlpatterns = [path("", include("control.urls"))]
if settings.DEBUG:
    urlpatterns.insert(0, path("django-admin/", admin.site.urls))
