"""Security middleware: rate limiting, defensive headers, payload size guards,
and sensitive cache control.
"""

from fastapi import FastAPI, Request, Response
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from starlette.middleware.base import BaseHTTPMiddleware

# ---------------------------------------------------------------------------
# Rate Limiter
# ---------------------------------------------------------------------------

limiter = Limiter(key_func=get_remote_address)


def register_rate_limiter(app: FastAPI) -> None:
    """Attach the rate limiter to the FastAPI app and register the error handler."""
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


# ---------------------------------------------------------------------------
# Security Headers Middleware
# ---------------------------------------------------------------------------

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Inject defensive HTTP headers into every response and protect sensitive routes."""

    async def dispatch(self, request: Request, call_next) -> Response:
        response: Response = await call_next(request)

        # 1. Prevent MIME-type sniffing
        response.headers["X-Content-Type-Options"] = "nosniff"

        # 2. Prevent clickjacking / frame embedding
        response.headers["X-Frame-Options"] = "DENY"

        # 3. Enable legacy browser XSS filtering
        response.headers["X-XSS-Protection"] = "1; mode=block"

        # 4. Strict Referrer policy
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

        # 5. Restrictive browser features & hardware permissions
        response.headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=(), payment=(), usb=(), vr=(), accelerometer=()"
        )

        # 6. HTTP Strict Transport Security (HSTS)
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"

        # 7. Cross-Origin isolation policies
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"

        # 8. Content Security Policy (CSP)
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "img-src 'self' data:; "
            "connect-src 'self' http://localhost:8000 ws://localhost:8000 http://localhost:5173 ws://localhost:5173; "
            "frame-ancestors 'none'"
        )

        # 9. Server Banner Masking (Prevent version disclosure)
        response.headers["Server"] = "IntelliVAPT-SecureGateway"

        # 10. Cache Prevention for sensitive assessment data
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
            response.headers["Pragma"] = "no-cache"
            response.headers["Expires"] = "0"

        return response


# ---------------------------------------------------------------------------
# Request Payload Size Limiter Middleware (Anti-DoS)
# ---------------------------------------------------------------------------

class RequestSizeLimiterMiddleware(BaseHTTPMiddleware):
    """Enforce strict upper limit on HTTP request bodies to prevent memory exhaustion DoS."""

    def __init__(self, app: FastAPI, max_bytes: int = 5 * 1024 * 1024):  # 5MB ceiling
        super().__init__(app)
        self.max_bytes = max_bytes

    async def dispatch(self, request: Request, call_next) -> Response:
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                if int(content_length) > self.max_bytes:
                    return Response(
                        content='{"detail":"Payload Too Large: Maximum allowed request body size is 5MB"}',
                        status_code=413,
                        media_type="application/json",
                    )
            except ValueError:
                pass
        return await call_next(request)
