"""Local-only security middleware for the WeChatDataAnalysis backend.

This tool decrypts and serves WeChat databases, chat history, moments, and
encryption keys. The API must therefore be reachable **only** from the same
machine the user is running it on. This module enforces that invariant via:

* A strict allowlist of allowed CORS origins (loopback only by default)
* A ``Host``-header allowlist that defeats DNS-rebinding attacks (an attacker
  cannot make the browser send an attacker-controlled ``Host`` header)
* A loopback-IP allowlist that rejects any TCP peer that is not on the local
  machine, regardless of how the server happens to be bound

All three checks can be relaxed with explicit environment variables for users
who knowingly want remote access (e.g. running on a server they trust). They
default to "loopback only" so the safe path is the easy path.
"""

from __future__ import annotations

import ipaddress
import os
import re
from typing import Iterable

from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp


# Loopback hostnames a browser might use for the frontend dev server / desktop
# UI. Ports are validated separately, so we just need the host portion here.
_LOOPBACK_HOSTNAMES: frozenset[str] = frozenset(
    {"localhost", "127.0.0.1", "[::1]", "::1"}
)


def _split_csv_env(value: str) -> list[str]:
    return [item.strip() for item in (value or "").split(",") if item.strip()]


def _strip_brackets(host: str) -> str:
    if host.startswith("[") and host.endswith("]"):
        return host[1:-1]
    return host


def _is_loopback_ip(host: str) -> bool:
    """Return True iff ``host`` is unambiguously a loopback IP literal."""
    try:
        ip = ipaddress.ip_address(_strip_brackets(host))
    except ValueError:
        return False
    return ip.is_loopback


def _split_host_port(value: str) -> tuple[str, str]:
    """Split a ``Host`` header value into (host, port) without DNS lookup."""
    raw = (value or "").strip()
    if not raw:
        return "", ""
    if raw.startswith("["):
        end = raw.find("]")
        if end == -1:
            return raw, ""
        host = raw[: end + 1]
        rest = raw[end + 1 :]
        port = rest.lstrip(":") if rest.startswith(":") else ""
        return host, port
    if ":" in raw and raw.count(":") == 1:
        host, _, port = raw.partition(":")
        return host, port
    return raw, ""


def get_allowed_hosts() -> set[str]:
    """Return the set of ``Host`` header values allowed to reach this server.

    Defaults to the loopback set. Operators can extend it via
    ``WECHAT_TOOL_ALLOWED_HOSTS`` (CSV, e.g. ``my.lan,192.168.1.10``).
    """
    extra = _split_csv_env(os.environ.get("WECHAT_TOOL_ALLOWED_HOSTS", ""))
    return set(_LOOPBACK_HOSTNAMES) | {h.lower() for h in extra}


def _origin_pattern_for(host: str) -> str:
    """Build an origin regex for a host on any port."""
    return rf"http://{re.escape(host)}(:\d+)?"


def get_allowed_origin_regex() -> str:
    """Return a regex matching every CORS origin we are willing to accept.

    The regex covers ``http://`` on any port for each allowed host. The schema
    is intentionally restricted to ``http`` because the local backend does not
    serve TLS; an ``https://localhost:1234`` origin would imply a TLS-terminating
    proxy the user has set up, in which case they can also configure
    ``WECHAT_TOOL_ALLOWED_ORIGIN_REGEX`` directly.
    """
    override = (os.environ.get("WECHAT_TOOL_ALLOWED_ORIGIN_REGEX") or "").strip()
    if override:
        return override

    # Browsers always bracket IPv6 literals in Origin headers (``http://[::1]:80``)
    # so we only emit the bracketed form in the origin regex. Bare ``::1`` is
    # still kept in ``get_allowed_hosts`` because the ``Host`` header sometimes
    # appears unbracketed depending on the user agent.
    seen: set[str] = set()
    unique_hosts: list[str] = []
    for h in get_allowed_hosts():
        try:
            ip = ipaddress.ip_address(_strip_brackets(h))
        except ValueError:
            ip = None
        if ip is not None and isinstance(ip, ipaddress.IPv6Address):
            host = h if h.startswith("[") else f"[{h}]"
        else:
            host = h
        if host in seen:
            continue
        seen.add(host)
        unique_hosts.append(host)

    return r"^(" + "|".join(_origin_pattern_for(h) for h in unique_hosts) + r")$"


def _allow_remote_clients() -> bool:
    raw = (os.environ.get("WECHAT_TOOL_ALLOW_REMOTE", "") or "").strip().lower()
    return raw in {"1", "true", "yes", "on"}


def _allowed_extra_client_ips() -> set[str]:
    return set(_split_csv_env(os.environ.get("WECHAT_TOOL_ALLOWED_CLIENT_IPS", "")))


def _is_allowed_client_ip(client_host: str) -> bool:
    if _is_loopback_ip(client_host):
        return True
    if _allow_remote_clients():
        return True
    return client_host in _allowed_extra_client_ips()


def _is_allowed_host_header(value: str) -> bool:
    host, _ = _split_host_port(value)
    if not host:
        # Missing/empty Host header is suspicious; reject by default.
        return False
    if _allow_remote_clients():
        return True
    allowed = {h.lower() for h in get_allowed_hosts()}
    return host.lower() in allowed


class LocalOnlyAccessMiddleware:
    """Reject requests that are not from the local machine.

    Two checks are applied:

    1. The TCP peer (``request.client.host``) must be a loopback IP, unless the
       operator has explicitly opted in via ``WECHAT_TOOL_ALLOW_REMOTE=1`` or
       ``WECHAT_TOOL_ALLOWED_CLIENT_IPS=...``.
    2. The HTTP ``Host`` header must be on the allow-list (loopback hostnames
       by default). This stops DNS-rebinding attacks where a malicious site
       resolves an attacker-controlled domain to ``127.0.0.1``: the browser
       sends ``Host: evil.com``, which is not allow-listed, and is dropped
       before any route handler runs.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope, receive, send):  # type: ignore[override]
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        request = Request(scope, receive=receive)

        client_host = ""
        try:
            client = request.client
            if client and client.host:
                client_host = str(client.host)
        except Exception:
            client_host = ""

        if client_host and not _is_allowed_client_ip(client_host):
            response = JSONResponse(
                {"detail": "Access denied: requests must originate from this machine."},
                status_code=403,
            )
            await response(scope, receive, send)
            return

        host_header = request.headers.get("host", "")
        if not _is_allowed_host_header(host_header):
            response = JSONResponse(
                {"detail": "Access denied: unrecognized Host header."},
                status_code=403,
            )
            await response(scope, receive, send)
            return

        await self.app(scope, receive, send)


def is_loopback_request(request: Request) -> bool:
    """Helper for route handlers that want an extra defense-in-depth check."""
    try:
        client = request.client
        host = (client.host if client else "") or ""
    except Exception:
        host = ""
    return _is_loopback_ip(host) or host == ""


def resolve_safe_bind_host(default: str = "127.0.0.1") -> str:
    """Return the host the server should bind to, refusing risky values.

    The user may set ``WECHAT_TOOL_HOST`` to bind to a specific interface, but
    binding to a wildcard (``0.0.0.0`` or ``::``) exposes the unauthenticated
    decryption API to the local network and is rejected unless they also set
    ``WECHAT_TOOL_ALLOW_REMOTE=1`` to confirm they understand the risk.
    """
    raw = (os.environ.get("WECHAT_TOOL_HOST", "") or "").strip()
    if not raw:
        return default
    if raw in {"0.0.0.0", "::", "*"}:
        if _allow_remote_clients():
            return raw
        # Silently fall back to loopback to avoid surprising the user.
        return default
    # Any other explicit value is honored. If it is non-loopback, the
    # LocalOnlyAccessMiddleware still rejects clients unless the operator
    # opted into WECHAT_TOOL_ALLOW_REMOTE.
    return raw
