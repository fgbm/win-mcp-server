#!/usr/bin/env python3
"""Win-MCP Server — read-only Windows remote filesystem via WinRM."""

import hmac
import logging
import logging.handlers
import os
import sys

import uvicorn
from fastmcp import FastMCP
from fastmcp.server.http import create_streamable_http_app
from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from agent.session_manager import SessionRegistry, UserIdentity, current_user
from agent.prompts import register_prompts
from agent.tools import register_tools

LOG_DIR = os.environ.get("LOG_DIR", "/app/logs")
LOG_MAX_BYTES = int(os.environ.get("LOG_MAX_BYTES", 10 * 1024 * 1024))
LOG_BACKUP_COUNT = int(os.environ.get("LOG_BACKUP_COUNT", 5))
AD_PASSWORD_IDLE_TTL_SECONDS = int(
    os.environ.get("AD_PASSWORD_IDLE_TTL_SECONDS", "3600")
)


def _load_auth_token() -> str:
    """Read the shared secret every caller must present, or abort startup.

    X-AD-User only names the caller; it is also the key of the password and
    session cache, so without a secret anyone able to reach the port could
    claim another user's name and inherit that user's cached password and open
    WinRM sessions. Running without a token is therefore refused outright
    rather than silently accepted.
    """
    token = os.environ.get("MCP_AUTH_TOKEN", "").strip()
    if not token:
        raise SystemExit(
            "MCP_AUTH_TOKEN is not set. Generate a secret "
            "(python3 -c 'import secrets; print(secrets.token_urlsafe(32))') "
            "and pass it to the server; clients send it as "
            "'Authorization: Bearer <token>' or 'X-MCP-Token: <token>'."
        )
    return token


class AuthMiddleware(BaseHTTPMiddleware):
    """Authenticate the caller, then extract per-user AD credentials.

    Every request must carry the shared secret, as an Authorization: Bearer
    token or an X-MCP-Token header; it is checked before X-AD-User is trusted
    for anything.
    X-AD-User is required.
    X-AD-Password is optional: when supplied it authenticates the caller with
    no prompts; when omitted the password is collected through MCP elicitation.
    The password is kept only in the in-memory SessionRegistry cache and is
    never logged.
    """

    def __init__(self, app, auth_token: str) -> None:
        super().__init__(app)
        self._auth_token = auth_token

    def _token_ok(self, request: Request) -> bool:
        presented = request.headers.get("x-mcp-token", "").strip()
        if not presented:
            authorization = request.headers.get("authorization", "").strip()
            scheme, _, value = authorization.partition(" ")
            if scheme.lower() == "bearer":
                presented = value.strip()
        return bool(presented) and hmac.compare_digest(presented, self._auth_token)

    async def dispatch(self, request: Request, call_next):  # type: ignore[override]
        if not self._token_ok(request):
            return JSONResponse(
                {"error": "Valid bearer token required"},
                status_code=401,
                headers={"WWW-Authenticate": "Bearer"},
            )

        username = request.headers.get("x-ad-user", "").strip()

        if not username:
            return JSONResponse(
                {"error": "X-AD-User header required"},
                status_code=401,
            )

        password = request.headers.get("x-ad-password", "")

        token = current_user.set(UserIdentity(username=username, password=password))
        try:
            return await call_next(request)
        finally:
            current_user.reset(token)


LOG_DIR_MODE = 0o700
LOG_FILE_MODE = 0o600


class _PrivateRotatingFileHandler(logging.handlers.RotatingFileHandler):
    """RotatingFileHandler that keeps its file readable by its owner only.

    The logs hold command text and command output, so the mode is reapplied on
    every open — otherwise each rotation would create the new file with the
    process umask.
    """

    def _open(self):  # type: ignore[override]
        stream = super()._open()
        try:
            os.chmod(self.baseFilename, LOG_FILE_MODE)
        except OSError:
            pass
        return stream


def _setup_logging() -> None:
    log_level = os.environ.get("LOG_LEVEL", "INFO").upper()
    os.makedirs(LOG_DIR, mode=LOG_DIR_MODE, exist_ok=True)
    try:
        os.chmod(LOG_DIR, LOG_DIR_MODE)
    except OSError:
        pass

    root = logging.getLogger("win-mcp")
    root.setLevel(log_level)
    root.propagate = False

    stderr_fmt = logging.Formatter(
        "%(asctime)s [%(name)s] %(levelname)s %(message)s"
    )
    stderr_handler = logging.StreamHandler(sys.stderr)
    stderr_handler.setFormatter(stderr_fmt)
    root.addHandler(stderr_handler)

    file_fmt = logging.Formatter(
        "%(asctime)s [%(name)s] %(levelname)s %(message)s"
    )
    file_handler = _PrivateRotatingFileHandler(
        os.path.join(LOG_DIR, "win-mcp.log"),
        maxBytes=LOG_MAX_BYTES,
        backupCount=LOG_BACKUP_COUNT,
    )
    file_handler.setFormatter(file_fmt)
    root.addHandler(file_handler)

    audit = logging.getLogger("win-mcp.audit")
    audit.setLevel(logging.INFO)
    audit.propagate = False
    audit_fmt = logging.Formatter("%(message)s")
    audit_handler = _PrivateRotatingFileHandler(
        os.path.join(LOG_DIR, "win-mcp-audit.log"),
        maxBytes=LOG_MAX_BYTES,
        backupCount=LOG_BACKUP_COUNT,
    )
    audit_handler.setFormatter(audit_fmt)
    audit.addHandler(audit_handler)


def main() -> None:
    _setup_logging()
    logger = logging.getLogger("win-mcp")

    auth_token = _load_auth_token()
    port = int(os.environ.get("MCPO_PORT", "8005"))
    bind_host = os.environ.get("MCP_BIND_HOST", "127.0.0.1")

    logger.info("PORT=%d", port)

    registry = SessionRegistry(password_idle_ttl_seconds=AD_PASSWORD_IDLE_TTL_SECONDS)
    mcp = FastMCP(name="win-mcp-server")
    register_tools(mcp, registry)
    register_prompts(mcp)

    app = create_streamable_http_app(
        server=mcp,
        streamable_http_path="/mcp",
        middleware=[Middleware(AuthMiddleware, auth_token=auth_token)],
    )

    logger.info(
        "win-mcp-server starting (streamable-http on %s:%d)", bind_host, port
    )
    uvicorn.run(app, host=bind_host, port=port)


if __name__ == "__main__":
    main()
