class SecurityHeadersMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        miniapp_request = request.path == "/app/" or request.path.startswith("/api/v1/telegram/")
        frame_ancestors = "https://web.telegram.org https://*.telegram.org" if miniapp_request else "'none'"
        response.setdefault("Referrer-Policy", "same-origin")
        response.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
        response.setdefault("Content-Security-Policy", f"default-src 'self'; script-src 'self' 'unsafe-inline' https://telegram.org; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' wss:; frame-ancestors {frame_ancestors}; base-uri 'self'; form-action 'self'")
        if miniapp_request:
            response["Cache-Control"] = "no-store, private"
            response["Pragma"] = "no-cache"
        return response
