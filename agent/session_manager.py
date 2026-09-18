"""WinRM session manager — thread-safe connection pool for Windows hosts."""

import contextvars
import logging
import os
import re
import threading
import time
from dataclasses import dataclass
from typing import Any

import winrm
from winrm.exceptions import InvalidCredentialsError


@dataclass(frozen=True)
class UserIdentity:
    username: str
    password: str = ""


current_user: contextvars.ContextVar[UserIdentity | None] = contextvars.ContextVar(
    "current_user", default=None
)

logger = logging.getLogger("win-mcp.sessions")
audit = logging.getLogger("win-mcp.audit")

MAX_OUTPUT_CHARS = 60_000

# The audit trail keeps a short excerpt, not the payload: command output can
# carry file contents, registry data, account lists and certificates, and the
# log lives in clear text on the control machine. The full output still goes
# to the agent in the tool response.
AUDIT_MAX_OUTPUT_CHARS = int(os.environ.get("AUDIT_MAX_OUTPUT_CHARS", "2000"))

# Set AUDIT_LOG_BODY=0 to record only the metadata fields of each call: no
# command text, no stdout, no stderr.
AUDIT_LOG_BODY = os.environ.get("AUDIT_LOG_BODY", "1").strip().lower() not in {
    "0",
    "false",
    "no",
    "off",
}

DEFAULT_HTTP_PORT = 5985
DEFAULT_HTTPS_PORT = 5986

CLIXML_RE = re.compile(
    r"#< CLIXML\r?\n<Objs.*?</Objs>",
    re.DOTALL,
)

SEPARATOR = "═" * 80

# WinRM runs powershell.exe with the console code page of the service, which on
# a localized Windows has no room for the system's own language: PowerShell
# replaces every unmappable character with "?" before the bytes ever leave the
# host, so "Диспетчер печати" arrives as "????????? ??????" and no decoding on
# this side can recover it. Switching the output encoding to UTF-8 first makes
# the host emit the real characters. Wrapped in try/catch because a host
# without a console attached raises on the assignment.
UTF8_PREAMBLE = (
    "try { [Console]::OutputEncoding = [Text.Encoding]::UTF8; "
    "$OutputEncoding = [Text.Encoding]::UTF8 } catch { }; "
)


@dataclass
class _CachedPassword:
    value: str
    last_used: float


def _truncate(text: str, limit: int = MAX_OUTPUT_CHARS) -> str:
    if len(text) <= limit:
        return text
    return (
        text[:limit]
        + f"\n\n--- truncated ({len(text):,} chars total, showing first {limit:,}) ---"
    )


def _is_auth_failure(exc: Exception) -> bool:
    """True when a connect error is a rejected-credentials failure, so the
    cached password can be invalidated and re-prompted on the next connect."""
    if isinstance(exc, InvalidCredentialsError):
        return True
    return "credentials were rejected" in str(exc).lower()


def _strip_clixml(stderr: str) -> str:
    """Remove PowerShell CLIXML progress noise from stderr."""
    cleaned = CLIXML_RE.sub("", stderr).strip()
    return cleaned


def _ts() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


def _audit_block(header: str, fields: dict[str, str], body: str = "") -> None:
    if not AUDIT_LOG_BODY:
        body = ""
    lines = [f"\n{SEPARATOR}", f"{_ts()}  {header}", "─" * 80]
    for k, v in fields.items():
        lines.append(f"  {k:<14}: {v}")
    if body:
        lines.append("")
        lines.append(body)
    lines.append(SEPARATOR)
    audit.info("\n".join(lines))


class _Session:
    __slots__ = ("host", "port", "winrm", "connected_at", "last_used", "command_count", "cmd_lock")

    def __init__(self, host: str, port: int, winrm_session: winrm.Session) -> None:
        self.host = host
        self.port = port
        self.winrm = winrm_session
        self.connected_at = time.time()
        self.last_used = self.connected_at
        self.command_count = 0
        self.cmd_lock = threading.Lock()


class SessionManager:
    def __init__(
        self,
        username: str,
        password: str,
        default_port: int = DEFAULT_HTTP_PORT,
    ) -> None:
        self._username = username
        self._password = password
        self._default_port = default_port
        self._sessions: dict[str, _Session] = {}
        self._lock = threading.Lock()

    def connect(
        self,
        host: str,
        port: int | None = None,
        use_ssl: bool | None = None,
        verify_cert: bool = True,
    ) -> dict[str, Any]:
        """Open a WinRM session.

        ``use_ssl`` selects the transport; when omitted it is derived from the
        port (5986 -> HTTPS, anything else -> HTTP). ``verify_cert`` maps to
        pywinrm's ``server_cert_validation`` and defaults to validating.
        """
        if use_ssl is None:
            use_ssl = (port or self._default_port) == DEFAULT_HTTPS_PORT
        if port is None:
            port = DEFAULT_HTTPS_PORT if use_ssl else self._default_port

        scheme = "https" if use_ssl else "http"
        cert_validation = "validate" if verify_cert else "ignore"
        session_id = host if port == self._default_port else f"{host}:{port}"

        with self._lock:
            if session_id in self._sessions:
                logger.info("Already connected to %s", session_id)
                return {
                    "session_id": session_id,
                    "status": "already_connected",
                    "host": host,
                    "port": port,
                }

        try:
            ws = winrm.Session(
                f"{scheme}://{host}:{port}/wsman",
                auth=(self._username, self._password),
                transport="ntlm",
                server_cert_validation=cert_validation,
                operation_timeout_sec=30,
                read_timeout_sec=35,
            )
            probe = (
                UTF8_PREAMBLE
                + "$os = Get-CimInstance Win32_OperatingSystem; "
                "\"$env:COMPUTERNAME|$($os.Caption)|$($os.Version)|"
                "$($os.LastBootUpTime.ToString('yyyy-MM-dd HH:mm:ss'))\""
            )
            result = ws.run_ps(probe)
            if result.status_code != 0:
                stderr = _strip_clixml(
                    result.std_err.decode("utf-8", errors="replace")
                )
                _audit_block("CONNECT FAILED", {
                    "user": self._username,
                    "host": host,
                    "port": str(port),
                    "transport": scheme,
                    "error": stderr[:200],
                })
                return {"error": f"Connection test failed: {stderr}"}

            raw = result.std_out.decode("utf-8", errors="replace").strip()
            parts = raw.split("|")

            with self._lock:
                self._sessions[session_id] = _Session(host, port, ws)

            info: dict[str, Any] = {
                "session_id": session_id,
                "status": "connected",
                "host": host,
                "port": port,
                "transport": scheme,
                "cert_validation": cert_validation,
                "computer_name": parts[0] if parts else raw,
            }
            if len(parts) >= 4:
                info["os"] = parts[1]
                info["os_version"] = parts[2]
                info["last_boot"] = parts[3]

            logger.info("Connected to %s (%s)", session_id, info.get("os", ""))
            _audit_block("CONNECT", {
                "user": self._username,
                "session": session_id,
                "host": host,
                "port": str(port),
                "transport": scheme,
                "cert_check": cert_validation,
                "computer": info.get("computer_name", ""),
                "os": info.get("os", ""),
                "os_version": info.get("os_version", ""),
                "last_boot": info.get("last_boot", ""),
            })
            return info
        except Exception as e:
            logger.warning("Connect failed for %s: %s", host, e)
            _audit_block("CONNECT ERROR", {
                "user": self._username,
                "host": host,
                "port": str(port),
                "transport": scheme,
                "error": str(e)[:300],
            })
            result: dict[str, Any] = {
                "error": str(e),
                "host": host,
                "port": port,
                "transport": scheme,
            }
            if _is_auth_failure(e):
                result["auth_failed"] = True
            return result

    def disconnect(self, session_id: str) -> dict[str, Any]:
        with self._lock:
            if session_id in self._sessions:
                s = self._sessions[session_id]
                cmd_count = s.command_count
                del self._sessions[session_id]
                logger.info("Disconnected %s (ran %d commands)", session_id, cmd_count)
                _audit_block("DISCONNECT", {
                    "user": self._username,
                    "session": session_id,
                    "commands_run": str(cmd_count),
                })
                return {"session_id": session_id, "status": "disconnected"}
        return {"error": f"Session not found: {session_id}"}

    def disconnect_all(self) -> dict[str, Any]:
        with self._lock:
            count = len(self._sessions)
            self._sessions.clear()
        logger.info("Disconnected all (%d sessions)", count)
        _audit_block("DISCONNECT ALL", {"user": self._username, "sessions_closed": str(count)})
        return {"status": "disconnected_all", "count": count}

    def list_sessions(self) -> dict[str, Any]:
        with self._lock:
            items = []
            for sid, s in self._sessions.items():
                items.append(
                    {
                        "session_id": sid,
                        "host": s.host,
                        "port": s.port,
                        "connected_at": time.strftime(
                            "%Y-%m-%d %H:%M:%S", time.localtime(s.connected_at)
                        ),
                        "last_used": time.strftime(
                            "%Y-%m-%d %H:%M:%S", time.localtime(s.last_used)
                        ),
                        "command_count": s.command_count,
                    }
                )
            return {"sessions": items, "count": len(items)}

    def run_ps(
        self,
        session_id: str,
        command: str,
        tool_name: str = "",
        redactions: list[str] | None = None,
    ) -> dict[str, Any]:
        def _redact(text: str) -> str:
            if redactions:
                for secret in redactions:
                    if secret:
                        text = text.replace(secret, "***")
            return text

        with self._lock:
            s = self._sessions.get(session_id)
            if not s:
                return {"error": f"Session not found: {session_id}. Use connect first."}
            s.last_used = time.time()
            s.command_count += 1
            ws = s.winrm
            cmd_num = s.command_count
            cmd_lock = s.cmd_lock

        label = f" [{tool_name}]" if tool_name else ""

        with cmd_lock:
            try:
                start = time.perf_counter()
                # The preamble is prepended for execution only; the audit log
                # keeps the command the tool actually asked for.
                result = ws.run_ps(UTF8_PREAMBLE + command)
                elapsed_ms = int((time.perf_counter() - start) * 1000)

                stdout = result.std_out.decode("utf-8", errors="replace")
                raw_stderr = result.std_err.decode("utf-8", errors="replace")
                stderr = _redact(_strip_clixml(raw_stderr))

                truncated_stdout = _redact(_truncate(stdout))
                audit_stdout = _truncate(truncated_stdout, AUDIT_MAX_OUTPUT_CHARS)
                audit_stderr = _truncate(stderr, AUDIT_MAX_OUTPUT_CHARS)

                _audit_block(
                    f"COMMAND #{cmd_num}{label}",
                    {
                        "user": self._username,
                        "session": session_id,
                        "tool": tool_name or "(direct)",
                        "elapsed_ms": str(elapsed_ms),
                        "status_code": str(result.status_code),
                        "stdout_bytes": str(len(stdout)),
                        "stderr_bytes": str(len(stderr)),
                    },
                    body=(
                        "  PS> " + _redact(command) + "\n"
                        "\n"
                        "  ── stdout ──\n"
                        + _indent(audit_stdout)
                        + (
                            "\n\n  ── stderr ──\n" + _indent(audit_stderr)
                            if audit_stderr
                            else ""
                        )
                    ),
                )

                return {
                    "status_code": result.status_code,
                    "stdout": truncated_stdout,
                    "stderr": stderr,
                    "elapsed_ms": elapsed_ms,
                }
            except Exception as e:
                logger.error("run_ps failed on %s: %s", session_id, _redact(str(e)))
                _audit_block(f"COMMAND ERROR{label}", {
                    "user": self._username,
                    "session": session_id,
                    "tool": tool_name or "(direct)",
                    "error": _redact(str(e))[:300],
                }, body="  PS> " + _redact(command))
                return {"error": _redact(str(e)), "session_id": session_id}


def _indent(text: str, prefix: str = "  ") -> str:
    if not text.strip():
        return prefix + "(empty)"
    return "\n".join(prefix + line for line in text.splitlines())


class SessionRegistry:
    """Per-user SessionManager pool.

    Reads the calling user's identity from the ``current_user`` context-var
    (set by the auth middleware). The AD password is resolved flexibly:
      * X-AD-User + X-AD-Password headers -> used as-is (no elicitation)
      * X-AD-User only                    -> password elicited once, cached

    Either way the password is cached in memory keyed by username with an idle
    TTL and is never logged.

    Exposes the same public interface as SessionManager so tools.py needs
    zero body changes — just swap the type hint.
    """

    def __init__(
        self,
        default_port: int = DEFAULT_HTTP_PORT,
        password_idle_ttl_seconds: int = 3600,
    ) -> None:
        self._managers: dict[str, SessionManager] = {}
        self._passwords: dict[str, _CachedPassword] = {}
        self._lock = threading.Lock()
        self._default_port = default_port
        self._password_idle_ttl_seconds = password_idle_ttl_seconds

    def current_username(self) -> str:
        user = current_user.get()
        if not user:
            raise RuntimeError("No user identity in request context")
        return user.username

    def _sync_header_password(self) -> bool:
        """Make a header-supplied X-AD-Password authoritative for this caller.

        When the request carried a password header, cache it (reusing
        ``cache_password``'s rotation handling, which drops a stale manager if
        the password changed) so no elicitation is needed. Returns True when a
        header password was present.
        """
        user = current_user.get()
        if not user or not user.password:
            return False
        self.cache_password(user.password)
        return True

    def _is_expired(self, cached: _CachedPassword, now: float) -> bool:
        ttl = self._password_idle_ttl_seconds
        return ttl > 0 and now - cached.last_used > ttl

    def has_cached_password(self) -> bool:
        if self._sync_header_password():
            return True

        username = self.current_username()
        expired_mgr: SessionManager | None = None
        now = time.monotonic()

        with self._lock:
            cached = self._passwords.get(username)
            if cached is None:
                return False
            if self._is_expired(cached, now):
                self._passwords.pop(username, None)
                expired_mgr = self._managers.pop(username, None)
                cached = None
            else:
                cached.last_used = now

        if expired_mgr is not None:
            expired_mgr.disconnect_all()

        return cached is not None

    def cache_password(self, password: str) -> None:
        username = self.current_username()
        now = time.monotonic()
        old_mgr: SessionManager | None = None

        with self._lock:
            existing = self._passwords.get(username)
            if existing is not None and existing.value != password:
                old_mgr = self._managers.pop(username, None)
            self._passwords[username] = _CachedPassword(
                value=password,
                last_used=now,
            )

        if old_mgr is not None:
            old_mgr.disconnect_all()

    def invalidate_password(self) -> None:
        """Drop the cached password and its manager so the next connect
        re-prompts. Called when a connect fails with rejected credentials."""
        username = self.current_username()
        old_mgr: SessionManager | None = None

        with self._lock:
            self._passwords.pop(username, None)
            old_mgr = self._managers.pop(username, None)

        if old_mgr is not None:
            old_mgr.disconnect_all()

    def _get(self) -> SessionManager:
        user = current_user.get()
        if not user:
            raise RuntimeError("No user identity in request context")

        self._sync_header_password()

        username = user.username
        now = time.monotonic()
        expired_mgr: SessionManager | None = None
        mgr: SessionManager | None = None
        missing_password = False

        with self._lock:
            cached = self._passwords.get(username)
            if cached is None or self._is_expired(cached, now):
                self._passwords.pop(username, None)
                expired_mgr = self._managers.pop(username, None)
                cached = None
            else:
                cached.last_used = now
                mgr = self._managers.get(username)

            if mgr is None:
                if cached is None:
                    missing_password = True
                else:
                    mgr = SessionManager(
                        username=username,
                        password=cached.value,
                        default_port=self._default_port,
                    )
                    self._managers[username] = mgr

        if expired_mgr is not None:
            expired_mgr.disconnect_all()

        if missing_password or mgr is None:
            raise RuntimeError(
                "AD password is not cached or has expired. Call connect to enter it again."
            )

        return mgr

    # ---- delegate every public method ----

    def connect(
        self,
        host: str,
        port: int | None = None,
        use_ssl: bool | None = None,
        verify_cert: bool = True,
    ) -> dict[str, Any]:
        result = self._get().connect(host, port, use_ssl, verify_cert)
        if result.get("auth_failed"):
            self.invalidate_password()
        return result

    def disconnect(self, session_id: str) -> dict[str, Any]:
        return self._get().disconnect(session_id)

    def disconnect_all(self) -> dict[str, Any]:
        return self._get().disconnect_all()

    def list_sessions(self) -> dict[str, Any]:
        return self._get().list_sessions()

    def run_ps(
        self,
        session_id: str,
        command: str,
        tool_name: str = "",
        redactions: list[str] | None = None,
    ) -> dict[str, Any]:
        return self._get().run_ps(session_id, command, tool_name, redactions)
