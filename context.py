from django.conf import settings


def control_context(request):
    return {"public_base_url": settings.PUBLIC_BASE_URL}

