import os

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "control_config.settings")

from django.core.asgi import get_asgi_application

django_application = get_asgi_application()

from control.relay import websocket_application


async def application(scope, receive, send):
    if scope["type"] == "websocket" and scope.get("path") == "/ws/relay/":
        return await websocket_application(scope, receive, send)
    if scope["type"] == "websocket":
        await send({"type": "websocket.close", "code": 4404})
        return
    return await django_application(scope, receive, send)

