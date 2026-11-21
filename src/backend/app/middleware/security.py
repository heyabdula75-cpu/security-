"""
Enterprise Security Middleware:
- Sliding-window API Rate Limiter (protects against abuse/DoS)
- Security response headers (X-Content-Type-Options, X-Frame-Options, Referrer-Policy)
"""
from __future__ import annotations

import time
from collections import defaultdict, deque

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware


class EnterpriseSecurityMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, requests_per_minute: int = 300):
        super().__init__(app)
        self.limit = requests_per_minute
        self.window = 60.0
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    async def dispatch(self, request: Request, call_next):
        client_ip = request.client.host if request.client else "unknown"
        now = time.monotonic()

        # Apply rate limiting to API endpoints
        remaining = self.limit
        if request.url.path.startswith("/api/"):
            bucket = self._hits[client_ip]
            cutoff = now - self.window
            while bucket and bucket[0] < cutoff:
                bucket.popleft()
            if len(bucket) >= self.limit:
                return JSONResponse(
                    status_code=429,
                    content={"detail": "Rate limit exceeded. Retry shortly."},
                    headers={"Retry-After": "60"},
                )
            bucket.append(now)
            remaining = max(0, self.limit - len(bucket))

        response = await call_next(request)
        response.headers["X-RateLimit-Limit"] = str(self.limit)
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        if request.url.path == "/" or request.url.path.endswith((".js", ".html", ".css")):
            response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        return response
