"""Safe default security headers for a FastAPI or Starlette app.

Copy this file into your project, then add one line after creating the app:

    app.add_middleware(SecurityHeadersMiddleware)

Each header tells the browser to refuse one kind of attack:

- Content-Security-Policy: run scripts, styles, images and frames only from
  this site. If the site loads anything from another address, add that
  address to the matching directive, one source at a time.
- X-Frame-Options and frame-ancestors: no other site may show this one in a
  frame (stops click-jacking).
- X-Content-Type-Options: the browser trusts the declared file type instead
  of guessing (stops a file being run as a script).
- Referrer-Policy: other sites aren't told which page a visitor came from.
- Permissions-Policy: no camera, microphone or location access.
- Cross-Origin-Opener-Policy and Cross-Origin-Resource-Policy: other sites
  can't reach into this one's windows or load its responses.
- Strict-Transport-Security: browsers use HTTPS only, for two years. Remove
  `includeSubDomains` if any subdomain of your domain still needs plain HTTP.

The middleware works at the ASGI level, so streamed responses stay streamed.
A header the app already set on a response is left as the app set it.
"""

DEFAULT_HEADERS = {
    "content-security-policy": (
        "default-src 'self'; base-uri 'none'; form-action 'self'; "
        "frame-ancestors 'none'; object-src 'none'"
    ),
    "x-frame-options": "DENY",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
    "permissions-policy": "camera=(), microphone=(), geolocation=()",
    "cross-origin-opener-policy": "same-origin",
    "cross-origin-resource-policy": "same-origin",
    "strict-transport-security": "max-age=63072000; includeSubDomains",
}


class SecurityHeadersMiddleware:
    def __init__(self, app, headers: dict[str, str] | None = None):
        self.app = app
        chosen = DEFAULT_HEADERS if headers is None else headers
        self.headers = [(name.lower().encode("latin-1"), value.encode("latin-1")) for name, value in chosen.items()]

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_headers(message):
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                present = {name.lower() for name, _ in headers}
                headers.extend((name, value) for name, value in self.headers if name not in present)
                message["headers"] = headers
            await send(message)

        await self.app(scope, receive, send_with_headers)
