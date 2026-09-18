"""MCP tool definitions — Windows remote operations via WinRM."""

import base64
import logging
import os
import threading
import time
from dataclasses import dataclass
from typing import Annotated, Any

from fastmcp import Context, FastMCP
from fastmcp.exceptions import ToolError
from pydantic import Field

from agent.session_manager import SessionRegistry

logger = logging.getLogger("win-mcp.tools")

VALID_ENCODINGS = frozenset(
    {"ascii", "bigendianunicode", "default", "oem", "unicode", "utf7", "utf8", "utf32"}
)

EVENT_LEVELS: dict[str, str] = {
    "critical": "1",
    "error": "2",
    "warning": "3",
    "info": "4",
}

SFTP_CRED_IDLE_TTL_SECONDS = int(os.environ.get("SFTP_CRED_IDLE_TTL_SECONDS", "3600"))


@dataclass
class _SftpCred:
    """Cached SFTP connection parameters for one logical SFTP session.

    The secret (password or key passphrase) lives only here in memory and is
    redacted from logs whenever it is injected into a PowerShell command.
    """

    win_session_id: str
    host: str
    port: int
    user: str
    auth_method: str  # "password" | "key"
    secret: str  # password, or key passphrase ("" if none)
    key_path: str  # "" unless auth_method == "key"
    timeout: int
    last_used: float


class _SftpCredStore:
    """Thread-safe, per-AD-user cache of SFTP credentials with idle TTL.

    Keyed by (ad_user, sftp_session_id) so users never see each other's
    sessions. A single lock guards all access; entries expire after an idle
    TTL and are pruned lazily on access.
    """

    def __init__(self, ttl_seconds: int) -> None:
        self._store: dict[tuple[str, str], _SftpCred] = {}
        self._lock = threading.Lock()
        self._ttl = ttl_seconds

    def _expired(self, cred: _SftpCred, now: float) -> bool:
        return self._ttl > 0 and now - cred.last_used > self._ttl

    def put(self, ad_user: str, sid: str, cred: _SftpCred) -> None:
        with self._lock:
            self._store[(ad_user, sid)] = cred

    def get(self, ad_user: str, sid: str) -> _SftpCred | None:
        now = time.monotonic()
        with self._lock:
            cred = self._store.get((ad_user, sid))
            if cred is None:
                return None
            if self._expired(cred, now):
                self._store.pop((ad_user, sid), None)
                return None
            cred.last_used = now
            return cred

    def pop(self, ad_user: str, sid: str) -> bool:
        with self._lock:
            return self._store.pop((ad_user, sid), None) is not None

    def list(self, ad_user: str) -> list[dict[str, Any]]:
        now = time.monotonic()
        out: list[dict[str, Any]] = []
        with self._lock:
            stale = [
                key for key, c in self._store.items() if self._expired(c, now)
            ]
            for key in stale:
                self._store.pop(key, None)
            for (user, sid), cred in self._store.items():
                if user != ad_user:
                    continue
                out.append({
                    "sftp_session_id": sid,
                    "win_session_id": cred.win_session_id,
                    "host": cred.host,
                    "port": cred.port,
                    "user": cred.user,
                    "auth_method": cred.auth_method,
                })
        return out


def _ps_escape(value: str) -> str:
    """Escape a value for embedding in a PowerShell single-quoted string."""
    return value.replace("'", "''")


def register_tools(mcp: FastMCP, sm: SessionRegistry) -> None:
    async def _ensure_ad_password(ctx: Context) -> dict[str, Any] | None:
        if sm.has_cached_password():
            return None

        username = sm.current_username()
        try:
            result = await ctx.elicit(
                message=(
                    f"Enter your AD password for {username}.\n"
                    "It is cached only in MCP server memory with an idle TTL and is never logged."
                ),
                response_type=str,
            )
            if result.action != "accept":
                return {"status": "cancelled", "message": "AD password entry cancelled"}
        except Exception as e:
            return {
                "error": (
                    f"Cannot prompt for the AD password: {e} "
                    "Send it in the X-AD-Password header instead."
                )
            }

        password = result.data if hasattr(result, "data") and result.data else ""
        if not password:
            return {"error": "No AD password provided"}

        sm.cache_password(str(password))
        return None

    # ==================================================================
    # Session lifecycle
    # ==================================================================

    @mcp.tool()
    async def connect(
        host: Annotated[str, Field(description="Windows hostname or IP to connect to, e.g. 'web-server-01'")],
        ctx: Context,
        port: Annotated[int | None, Field(description="WinRM port. Defaults to 5985 for HTTP and 5986 for HTTPS")] = None,
        use_ssl: Annotated[bool | None, Field(description="Use HTTPS transport. Leave unset to derive it from the port (5986 -> HTTPS, otherwise HTTP)")] = None,
        verify_cert: Annotated[bool, Field(description="Validate the server TLS certificate on HTTPS. WARNING: setting this to false disables certificate validation and exposes the session to man-in-the-middle attacks - use only against hosts with a known self-signed certificate")] = True,
    ) -> dict[str, Any]:
        """Open a WinRM session to a Windows host and return a session_id; this is the required first step before any other tool. The AD password is elicited once and cached only in server memory, and the response includes computer name, OS version, and last boot time for triage.
        """
        auth_error = await _ensure_ad_password(ctx)
        if auth_error is not None:
            return auth_error
        return sm.connect(host, port, use_ssl, verify_cert)

    @mcp.tool()
    def disconnect(
        session_id: Annotated[str, Field(description="Session ID returned by connect")],
    ) -> dict[str, Any]:
        """Close an active WinRM session and release it; sessions are not auto-cleaned, so always disconnect when done. If you don't have the session_id, call list_sessions first.
        """
        return sm.disconnect(session_id)

    @mcp.tool()
    def list_sessions() -> dict[str, Any]:
        """List active WinRM sessions with host, connection time, last used time, and command count. Use it to find a session_id or check whether you are already connected to a host.
        """
        return sm.list_sessions()

    # ==================================================================
    # Filesystem — read-only
    # ==================================================================

    @mcp.tool()
    def list_directory(
        session_id: Annotated[str, Field(description="Session ID returned by connect")],
        path: Annotated[str, Field(description="Absolute directory path to list, e.g. 'C:\\Users' or 'D:\\Logs'")],
    ) -> dict[str, Any]:
        """List files and directories at a path as tabular text (Mode, LastWriteTime, Length, Name; max 200 entries, most recently modified first). Use this to explore one folder; use find_files to search recursively by pattern instead.
        """
        safe = _ps_escape(path)
        cmd = (
            "Get-ChildItem -LiteralPath '" + safe + "' -Force -ErrorAction Stop "
            "| Sort-Object LastWriteTime -Descending "
            "| Select-Object -First 200 Mode, LastWriteTime, Length, Name "
            "| Format-Table -AutoSize | Out-String -Width 300"
        )
        return sm.run_ps(session_id, cmd, tool_name="list_directory")

    @mcp.tool()
    def find_files(
        session_id: Annotated[str, Field(description="Session ID returned by connect")],
        path: Annotated[str, Field(description="Root directory to start the recursive search from")],
        pattern: Annotated[str, Field(description="Filename wildcard to match, e.g. '*.log', '*.config', 'server.xml'")],
        max_depth: Annotated[int, Field(description="Maximum recursion depth, default 5, capped at 10")] = 5,
        include_size: Annotated[bool, Field(description="Include each file's size in the output, default true")] = True,
    ) -> dict[str, Any]:
        """Recursively find files matching a wildcard pattern, returning FullName, Size, and LastWriteTime as tabular text (max 100 results). Matches files only, not directories — use list_directory to browse a single folder.
        """
        safe_path = _ps_escape(path)
        safe_pattern = _ps_escape(pattern)
        depth = max(0, min(max_depth, 10))
        cols = "FullName, Length, LastWriteTime" if include_size else "FullName, LastWriteTime"
        cmd = (
            "Get-ChildItem -Path '" + safe_path + "' -Recurse "
            "-Filter '" + safe_pattern + "' "
            "-Depth " + str(depth) + " -ErrorAction SilentlyContinue "
            "| Select-Object -First 100 " + cols + " "
            "| Format-Table -AutoSize | Out-String -Width 300"
        )
        return sm.run_ps(session_id, cmd, tool_name="find_files")

    @mcp.tool()
    def read_file(
        session_id: Annotated[str, Field(description="Session ID returned by connect")],
        path: Annotated[str, Field(description="Absolute path of the file to read")],
        start_line: Annotated[int, Field(description="First 1-based line to return in range mode, ignored when tail=True")] = 1,
        end_line: Annotated[int, Field(description="Last line in range mode, or line count from end in tail mode")] = 200,
        tail: Annotated[bool, Field(description="Read the last N lines instead of a range; ideal for logs")] = False,
        encoding: Annotated[str, Field(description="File encoding, default UTF8; use 'Unicode' for UTF-16 legacy files")] = "UTF8",
    ) -> dict[str, Any]:
        """Read file contents as numbered lines (max 500 per call) in '     1|line' format. Range mode reads start_line through end_line; tail mode (tail=True) reads the last N lines and stays fast even on huge files.
        """
        enc_lookup = {e: e for e in VALID_ENCODINGS}
        enc_key = encoding.strip().lower()
        if enc_key not in enc_lookup:
            return {"error": f"Invalid encoding '{encoding}'. Valid: {', '.join(sorted(VALID_ENCODINGS))}"}
        enc = enc_lookup[enc_key]

        safe = _ps_escape(path)

        if tail:
            count = max(1, min(end_line, 500))
            cmd = (
                "$lines = @(Get-Content -LiteralPath '" + safe + "' "
                "-Tail " + str(count) + " -Encoding " + enc + " -ErrorAction Stop); "
                "$n = 1; "
                "$lines | ForEach-Object { '{0,6}|{1}' -f ($n++), $_ }; "
                "Write-Output (\"--- tail: last $($lines.Count) lines ---\")"
            )
        else:
            if start_line < 1:
                start_line = 1
            if end_line < start_line:
                return {"error": "end_line must be >= start_line"}
            if end_line - start_line + 1 > 500:
                end_line = start_line + 499

            skip = start_line - 1
            cmd = (
                "$lines = @(Get-Content -LiteralPath '" + safe + "' "
                "-TotalCount " + str(end_line) + " -Encoding " + enc + " -ErrorAction Stop); "
                "$n = " + str(start_line) + "; "
                "$lines | Select-Object -Skip " + str(skip) + " | "
                "ForEach-Object { '{0,6}|{1}' -f ($n++), $_ }; "
                "Write-Output (\"--- lines " + str(start_line) + " to "
                + str(end_line) + ", read $($lines.Count) lines ---\")"
            )
        return sm.run_ps(session_id, cmd, tool_name="read_file")

    @mcp.tool()
    def search_file_content(
        session_id: Annotated[str, Field(description="Session ID returned by connect")],
        path: Annotated[str, Field(description="Single file, or narrowest directory to search recursively")],
        pattern: Annotated[str, Field(description="Distinctive literal text to find; no regex or wildcards")],
        file_filter: Annotated[str, Field(description="Filename wildcard for directory searches, e.g. '*.log'; override the '*' default")] = "*",
        max_results: Annotated[int, Field(description="Max matching lines to return, default 50, capped at 100")] = 50,
        context_lines: Annotated[int, Field(description="Lines shown before and after each match, default 0, max 10")] = 0,
        modified_after_hours: Annotated[int, Field(description="Only search files changed within this many hours; 0 means all files")] = 0,
    ) -> dict[str, Any]:
        """Search for literal text inside files like grep; pass a file path to search one file or a directory to search recursively across files matching file_filter. Recursive searches can scan huge volumes, so scope the path, set modified_after_hours, and pick a discriminating pattern to stay fast and avoid hitting the result cap.
        """
        safe_path = _ps_escape(path)
        safe_pattern = _ps_escape(pattern)
        safe_filter = _ps_escape(file_filter)
        cap = max(1, min(max_results, 100))
        ctx = max(0, min(context_lines, 10))
        ctx_arg = " -Context " + str(ctx) + "," + str(ctx) if ctx > 0 else ""

        time_filter = ""
        if modified_after_hours > 0:
            time_filter = (
                "| Where-Object { $_.LastWriteTime -gt (Get-Date).AddHours(-"
                + str(modified_after_hours) + ") } "
            )

        if ctx > 0:
            fmt_file = "| Out-String -Width 300"
            fmt_single = "| Out-String -Width 300"
        else:
            fmt_file = '| ForEach-Object { "$($_.Path):$($_.LineNumber)|$($_.Line)" }'
            fmt_single = '| ForEach-Object { "$($_.LineNumber)|$($_.Line)" }'

        cmd = (
            "$t = Get-Item -LiteralPath '" + safe_path + "' -ErrorAction Stop; "
            "if ($t.PSIsContainer) { "
            "Get-ChildItem -Path '" + safe_path + "' -Recurse -File "
            "-Filter '" + safe_filter + "' -ErrorAction SilentlyContinue "
            + time_filter +
            "| Select-String -Pattern '" + safe_pattern + "' -SimpleMatch"
            + ctx_arg + " -ErrorAction SilentlyContinue "
            "| Select-Object -First " + str(cap) + " "
            + fmt_file +
            " } else { "
            "Select-String -LiteralPath '" + safe_path + "' "
            "-Pattern '" + safe_pattern + "' -SimpleMatch"
            + ctx_arg + " -ErrorAction Stop "
            "| Select-Object -First " + str(cap) + " "
            + fmt_single +
            " }"
        )
        return sm.run_ps(session_id, cmd, tool_name="search_file_content")

    @mcp.tool()
    def file_info(
        session_id: Annotated[str, Field(description="Session ID returned by connect")],
        path: Annotated[str, Field(description="Absolute path to the file or directory to inspect")],
    ) -> dict[str, Any]:
        """Return JSON metadata for one file or directory: size in bytes/KB, created/modified/accessed timestamps, and attributes. Use it to check file size before reading or to verify a path exists.
        """
        safe = _ps_escape(path)
        cmd = (
            "Get-Item -LiteralPath '" + safe + "' -Force -ErrorAction Stop "
            "| Select-Object FullName, "
            "@{N='SizeBytes';E={$_.Length}}, "
            "@{N='SizeKB';E={[math]::Round($_.Length/1KB,2)}}, "
            "@{N='Created';E={$_.CreationTime.ToString('yyyy-MM-dd HH:mm:ss')}}, "
            "@{N='Modified';E={$_.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')}}, "
            "@{N='Accessed';E={$_.LastAccessTime.ToString('yyyy-MM-dd HH:mm:ss')}}, "
            "Attributes "
            "| ConvertTo-Json -Compress"
        )
        return sm.run_ps(session_id, cmd, tool_name="file_info")

    # ==================================================================
    # System diagnostics — read-only
    # ==================================================================

    @mcp.tool()
    def get_event_log(
        session_id: Annotated[str, Field(description="Session ID returned by connect")],
        log_name: Annotated[str, Field(description="Event log to read: System (default), Application, or Security")] = "System",
        level: Annotated[str, Field(description="Severity threshold including higher: Critical, Error (default), Warning, or Info")] = "Error",
        hours_back: Annotated[int, Field(description="How many hours back to search, default 24, capped at 720")] = 24,
        source: Annotated[str, Field(description="Provider name filter, wildcards allowed, e.g. '*SQL*'")] = "",
        count: Annotated[int, Field(description="Max events to return, default 25, capped at 100")] = 25,
    ) -> dict[str, Any]:
        """Read the Windows Event Log, the primary source for crashes, service failures, auth errors, and disk warnings; the level threshold includes that severity and all higher ones. Check Application for app crashes, System for OS/driver issues, and Security for auth failures.
        """
        safe_log = _ps_escape(log_name)
        cap = max(1, min(count, 100))
        hrs = max(1, min(hours_back, 720))

        level_key = level.strip().lower()
        level_nums: list[str] = []
        for lname, lnum in EVENT_LEVELS.items():
            level_nums.append(lnum)
            if lname == level_key:
                break
        if not level_nums:
            level_nums = ["1", "2"]
        levels_str = ",".join(level_nums)

        source_filter = ""
        if source.strip():
            safe_source = _ps_escape(source.strip())
            source_filter = (
                "| Where-Object { $_.ProviderName -like '" + safe_source + "' } "
            )

        cmd = (
            "Get-WinEvent -FilterHashtable @{LogName='" + safe_log + "'; "
            "Level=" + levels_str + "; "
            "StartTime=(Get-Date).AddHours(-" + str(hrs) + ")} "
            "-MaxEvents " + str(cap * 3) + " -ErrorAction SilentlyContinue "
            + source_filter +
            "| Select-Object -First " + str(cap) + " "
            "| ForEach-Object { "
            "\"$($_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')) "
            "[$($_.LevelDisplayName)] ($($_.ProviderName)) ID:$($_.Id)\"; "
            "\"  $($_.Message.Substring(0,[Math]::Min($_.Message.Length,400)))\"; "
            "\"---\" }"
        )
        return sm.run_ps(session_id, cmd, tool_name="get_event_log")

    @mcp.tool()
    def get_services(
        session_id: Annotated[str, Field(description="Session ID returned by connect")],
        name_filter: Annotated[str, Field(description="Wildcard on Name or DisplayName, e.g. '*sql*', '*jboss*'")] = "",
        status_filter: Annotated[str, Field(description="Filter by state: Running, Stopped, or All (default)")] = "All",
        detail: Annotated[bool, Field(description="Deep JSON inspection per service; best paired with a name_filter")] = False,
    ) -> dict[str, Any]:
        """List Windows services: summary mode (default) returns tabular Name, Status, StartType, DisplayName, while detail mode returns JSON per service with binary path, account, PID, memory, exit codes, dependencies, and recovery actions. Use summary to find a service, then detail to inspect it before restarting.
        """
        where_clauses: list[str] = []

        sf = status_filter.strip().lower()
        if sf in ("running", "stopped"):
            where_clauses.append("$_.Status -eq '" + sf.capitalize() + "'")

        if name_filter.strip():
            safe_nf = _ps_escape(name_filter.strip())
            where_clauses.append(
                "($_.Name -like '" + safe_nf + "' -or $_.DisplayName -like '" + safe_nf + "')"
            )

        where = ""
        if where_clauses:
            where = "| Where-Object { " + " -and ".join(where_clauses) + " } "

        if not detail:
            cmd = (
                "Get-Service -ErrorAction SilentlyContinue "
                + where +
                "| Sort-Object Status, Name "
                "| Select-Object Name, Status, StartType, DisplayName "
                "| Format-Table -AutoSize | Out-String -Width 300"
            )
        else:
            cmd = (
                "@(Get-Service -ErrorAction SilentlyContinue "
                + where +
                "| ForEach-Object { "
                "$svc = $_; "
                "$wmi = Get-CimInstance Win32_Service -Filter \"Name='$($svc.Name)'\" -ErrorAction SilentlyContinue; "
                "$proc = if($wmi.ProcessId -and $wmi.ProcessId -gt 0)"
                "{Get-Process -Id $wmi.ProcessId -ErrorAction SilentlyContinue}else{$null}; "
                "$binPath = if($wmi.PathName){$wmi.PathName -replace '\"',''}else{''}; "
                "$workDir = if($binPath){Split-Path -Parent ($binPath -split ' ')[0]}else{''}; "
                "$delayed = (Get-ItemProperty -Path \"HKLM:\\SYSTEM\\CurrentControlSet\\Services\\$($svc.Name)\" "
                "-Name 'DelayedAutostart' -ErrorAction SilentlyContinue).DelayedAutostart; "
                "$rec = @(sc.exe qfailure $svc.Name 2>$null); "
                "$r1 = ($rec | Select-String 'RESET_PERIOD' | ForEach-Object { ($_ -split ':',2)[1].Trim() }); "
                "$a1 = ($rec | Select-String 'FAILURE_ACTIONS' | ForEach-Object { ($_ -split ':',2)[1].Trim() }); "
                "[PSCustomObject]@{"
                "name=$svc.Name; "
                "display_name=$svc.DisplayName; "
                "status=[string]$svc.Status; "
                "start_type=[string]$svc.StartType; "
                "delayed_auto_start=if($delayed -eq 1){$true}else{$false}; "
                "binary_path=$wmi.PathName; "
                "working_directory=$workDir; "
                "service_account=$wmi.StartName; "
                "pid=if($wmi.ProcessId){$wmi.ProcessId}else{$null}; "
                "memory_mb=if($proc){[math]::Round($proc.WorkingSet64/1MB,1)}else{$null}; "
                "win32_exit_code=$wmi.ExitCode; "
                "service_exit_code=$wmi.ServiceSpecificExitCode; "
                "dependencies=@($svc.ServicesDependedOn | Select-Object -ExpandProperty Name); "
                "depended_by=@($svc.DependentServices | Select-Object -ExpandProperty Name); "
                "description=$wmi.Description; "
                "recovery_reset_s=$r1; "
                "recovery_actions=$a1"
                "}"
                "}) | ConvertTo-Json -Compress -Depth 3"
            )
        return sm.run_ps(session_id, cmd, tool_name="get_services")

    @mcp.tool()
    def list_processes(
        session_id: Annotated[str, Field(description="Session ID returned by connect")],
        name_filter: Annotated[str, Field(description="Wildcard on process name, e.g. 'java*', 'w3wp*', 'sqlservr*'")] = "",
        sort_by: Annotated[str, Field(description="Sort descending by CPU or Memory (default)")] = "Memory",
        top: Annotated[int, Field(description="Number of processes to show, default 30, capped at 100")] = 30,
    ) -> dict[str, Any]:
        """List running processes as tabular text with PID, name, CPU seconds, memory MB, handle count, and start time, sorted descending by the chosen metric. Use it to spot resource hogs, confirm an app is running, or find hung processes.
        """
        cap = max(1, min(top, 100))
        sort_prop = "WorkingSet64" if sort_by.strip().lower() != "cpu" else "CPU"

        name_where = ""
        if name_filter.strip():
            safe_nf = _ps_escape(name_filter.strip())
            name_where = "| Where-Object { $_.ProcessName -like '" + safe_nf + "' } "

        cmd = (
            "Get-Process -ErrorAction SilentlyContinue "
            + name_where +
            "| Sort-Object " + sort_prop + " -Descending "
            "| Select-Object -First " + str(cap) + " "
            "Id, ProcessName, "
            "@{N='CPU_s';E={[math]::Round($_.CPU,1)}}, "
            "@{N='Mem_MB';E={[math]::Round($_.WorkingSet64/1MB,1)}}, "
            "@{N='Handles';E={$_.HandleCount}}, "
            "@{N='Started';E={if($_.StartTime){$_.StartTime.ToString('yyyy-MM-dd HH:mm')}else{'N/A'}}} "
            "| Format-Table -AutoSize | Out-String -Width 300"
        )
        return sm.run_ps(session_id, cmd, tool_name="list_processes")

    @mcp.tool()
    def get_system_info(
        session_id: Annotated[str, Field(description="Session ID returned by connect")],
    ) -> dict[str, Any]:
        """Return a JSON system overview in one call: OS version, uptime, last boot, total/free RAM, CPU count, domain, and timezone. Call it right after connect to establish triage context.
        """
        cmd = (
            "$os = Get-CimInstance Win32_OperatingSystem; "
            "$cs = Get-CimInstance Win32_ComputerSystem; "
            "[PSCustomObject]@{"
            "ComputerName=$env:COMPUTERNAME; "
            "OS=$os.Caption; "
            "Version=$os.Version; "
            "BuildNumber=$os.BuildNumber; "
            "LastBoot=$os.LastBootUpTime.ToString('yyyy-MM-dd HH:mm:ss'); "
            "Uptime=((Get-Date)-$os.LastBootUpTime).ToString('d\\.hh\\:mm\\:ss'); "
            "TotalRAM_GB=[math]::Round($cs.TotalPhysicalMemory/1GB,1); "
            "FreeRAM_GB=[math]::Round($os.FreePhysicalMemory/1MB,1); "
            "CPUs=$cs.NumberOfLogicalProcessors; "
            "Domain=$cs.Domain; "
            "TimeZone=(Get-TimeZone).Id"
            "} | ConvertTo-Json -Compress"
        )
        return sm.run_ps(session_id, cmd, tool_name="get_system_info")

    @mcp.tool()
    def get_disk_space(
        session_id: Annotated[str, Field(description="Session ID returned by connect")],
    ) -> dict[str, Any]:
        """Return disk space for all fixed drives as tabular text: DeviceID, Total_GB, Free_GB, and Used_Pct. A full disk is a top cause of production incidents, so check this early during triage.
        """
        cmd = (
            "Get-CimInstance Win32_LogicalDisk -Filter \"DriveType=3\" "
            "| Select-Object DeviceID, "
            "@{N='Total_GB';E={[math]::Round($_.Size/1GB,1)}}, "
            "@{N='Free_GB';E={[math]::Round($_.FreeSpace/1GB,1)}}, "
            "@{N='Used_Pct';E={[math]::Round(($_.Size-$_.FreeSpace)/$_.Size*100,1)}} "
            "| Format-Table -AutoSize | Out-String -Width 200"
        )
        return sm.run_ps(session_id, cmd, tool_name="get_disk_space")

    @mcp.tool()
    def get_perf_snapshot(
        session_id: Annotated[str, Field(description="Session ID returned by connect")],
        samples: Annotated[int, Field(description="Samples to average, default 3, max 10; more is smoother but slower")] = 3,
        interval_sec: Annotated[int, Field(description="Seconds between samples, default 2, capped at 10")] = 2,
        process_filter: Annotated[str, Field(description="Wildcard for per-process counters; empty omits that section for speed")] = "",
    ) -> dict[str, Any]:
        """Capture an averaged performance snapshot as JSON: CPU, memory, disk I/O, network, TCP connections, and optionally per-process stats. Use it to judge whether the server is healthy, CPU-bound, or disk-thrashing; it takes roughly samples × interval_sec seconds.
        """
        cap_samples = max(1, min(samples, 10))
        cap_interval = max(1, min(interval_sec, 10))

        proc_block = "$procData = @(); "
        if process_filter.strip():
            safe_pf = _ps_escape(process_filter.strip())
            proc_block = (
                "try { "
                "$pc = (Get-Counter -Counter @("
                "'\\Process(" + safe_pf + ")\\% Processor Time',"
                "'\\Process(" + safe_pf + ")\\Working Set',"
                "'\\Process(" + safe_pf + ")\\Handle Count',"
                "'\\Process(" + safe_pf + ")\\Thread Count',"
                "'\\Process(" + safe_pf + ")\\IO Read Bytes/sec',"
                "'\\Process(" + safe_pf + ")\\IO Write Bytes/sec'"
                ") -SampleInterval " + str(cap_interval) + " "
                "-MaxSamples " + str(cap_samples) + " "
                "-ErrorAction Stop).CounterSamples; "
                "$procData = @($pc | Group-Object InstanceName | ForEach-Object { "
                "$g = $_.Group; "
                "$cn = $_.Name; "
                "function ga($p,$g){$v=($g|Where-Object{$_.Path-like $p}|Measure-Object CookedValue -Average).Average;if($v){$v}else{0}} "
                "[PSCustomObject]@{ "
                "name=$cn; "
                "cpu_pct=[math]::Round((ga '*% processor time' $g),1); "
                "mem_mb=[math]::Round((ga '*working set' $g)/1MB,1); "
                "handles=[int](ga '*handle count' $g); "
                "threads=[int](ga '*thread count' $g); "
                "io_read_kbs=[math]::Round((ga '*io read*' $g)/1KB,1); "
                "io_write_kbs=[math]::Round((ga '*io write*' $g)/1KB,1)"
                "}})"
                "} catch { $procData = @() }; "
            )

        cmd = (
            "$cs = (Get-Counter -Counter @("
            "'\\Processor(_Total)\\% Processor Time',"
            "'\\Processor(_Total)\\% Privileged Time',"
            "'\\System\\Processor Queue Length',"
            "'\\Memory\\Available MBytes',"
            "'\\Memory\\% Committed Bytes In Use',"
            "'\\Memory\\Pages/sec',"
            "'\\PhysicalDisk(_Total)\\% Disk Time',"
            "'\\PhysicalDisk(_Total)\\Avg. Disk Queue Length',"
            "'\\PhysicalDisk(_Total)\\Disk Read Bytes/sec',"
            "'\\PhysicalDisk(_Total)\\Disk Write Bytes/sec',"
            "'\\Network Interface(*)\\Bytes Total/sec',"
            "'\\TCPv4\\Connections Established',"
            "'\\System\\Threads',"
            "'\\Process(_Total)\\Handle Count'"
            ") -SampleInterval " + str(cap_interval) + " "
            "-MaxSamples " + str(cap_samples) + " "
            "-ErrorAction Stop).CounterSamples; "
            "function av($p){[math]::Round(($cs|Where-Object{$_.Path-like $p}"
            "|Measure-Object CookedValue -Average).Average,2)} "
            + proc_block +
            "$r = [ordered]@{"
            "timestamp=(Get-Date).ToString('yyyy-MM-dd HH:mm:ss');"
            "samples=" + str(cap_samples) + ";"
            "interval_sec=" + str(cap_interval) + ";"
            "cpu=[ordered]@{"
            "total_pct=av '*processor time';"
            "kernel_pct=av '*privileged time';"
            "queue_length=av '*processor queue*'"
            "};"
            "memory=[ordered]@{"
            "available_mb=av '*available mbytes';"
            "committed_pct=av '*committed*';"
            "pages_per_sec=av '*pages/sec'"
            "};"
            "disk=[ordered]@{"
            "busy_pct=av '*% disk time';"
            "queue_length=av '*disk queue*';"
            "read_mbs=[math]::Round((av '*disk read bytes*')/1MB,2);"
            "write_mbs=[math]::Round((av '*disk write bytes*')/1MB,2)"
            "};"
            "network=[ordered]@{"
            "throughput_mbs=[math]::Round((av '*bytes total/sec')/1MB,2);"
            "tcp_established=[int](av '*connections established')"
            "};"
            "system=[ordered]@{"
            "total_threads=[int](av '*\\system\\threads');"
            "total_handles=[int](av '*\\handle count')"
            "}"
            "}; "
            "if($procData.Count -gt 0){$r['processes']=@($procData)}; "
            "$r | ConvertTo-Json -Depth 3 -Compress"
        )
        return sm.run_ps(session_id, cmd, tool_name="get_perf_snapshot")

    @mcp.tool()
    def test_network(
        session_id: Annotated[str, Field(description="Session ID returned by connect")],
        target: Annotated[str, Field(description="Hostname or IP to test connectivity to")],
        port: Annotated[int, Field(description="TCP port to test, or 0 (default) for an ICMP ping")] = 0,
    ) -> dict[str, Any]:
        """Test connectivity from the remote Windows host's perspective: port=0 sends three ICMP pings as tabular text, while port>0 runs a TCP test returning JSON with a TcpTestSucceeded boolean. A blocked TCP port test can take 20-35 seconds.
        """
        safe_target = _ps_escape(target)

        if port > 0:
            cmd = (
                "$r = Test-NetConnection -ComputerName '" + safe_target + "' "
                "-Port " + str(port) + " -WarningAction SilentlyContinue; "
                "[PSCustomObject]@{"
                "Target=$r.ComputerName; "
                "RemoteAddress=[string]$r.RemoteAddress; "
                "Port=$r.RemotePort; "
                "TcpTestSucceeded=$r.TcpTestSucceeded; "
                "RTT_ms=$r.PingReplyDetails.RoundtripTime"
                "} | ConvertTo-Json -Compress"
            )
        else:
            cmd = (
                "Test-Connection -ComputerName '" + safe_target + "' "
                "-Count 3 -ErrorAction Stop "
                "| Select-Object "
                "@{N='Target';E={$_.Address}}, "
                "@{N='RTT_ms';E={$_.ResponseTime}}, "
                "@{N='TTL';E={$_.TimeToLive}} "
                "| Format-Table -AutoSize | Out-String -Width 200"
            )
        return sm.run_ps(session_id, cmd, tool_name="test_network")

    @mcp.tool()
    def get_registry(
        session_id: Annotated[str, Field(description="Session ID returned by connect")],
        key: Annotated[str, Field(description="Registry path with 'HKLM:\\' prefix; HKEY_LOCAL_MACHINE form also accepted")],
        value_name: Annotated[str, Field(description="Single value to read; empty dumps all values under the key")] = "",
    ) -> dict[str, Any]:
        """Read a registry key or a single value (read-only) and return JSON. Use it to check service configuration, installed software versions, TLS/crypto settings, or feature flags.
        """
        k = key.strip()
        if k.upper().startswith("HKEY_"):
            k = "Registry::" + k

        safe_key = _ps_escape(k)

        if value_name.strip():
            safe_val = _ps_escape(value_name.strip())
            cmd = (
                "Get-ItemProperty -Path '" + safe_key + "' "
                "-Name '" + safe_val + "' -ErrorAction Stop "
                "| Select-Object -Property '" + safe_val + "' "
                "| ConvertTo-Json -Compress"
            )
        else:
            cmd = (
                "Get-ItemProperty -Path '" + safe_key + "' -ErrorAction Stop "
                "| Select-Object * -ExcludeProperty PS* "
                "| ConvertTo-Json -Compress"
            )
        return sm.run_ps(session_id, cmd, tool_name="get_registry")

    @mcp.tool()
    def get_certificates(
        session_id: Annotated[str, Field(description="Session ID returned by connect")],
        store: Annotated[str, Field(description="Certificate store location: LocalMachine (default) or CurrentUser")] = "LocalMachine",
        days_until_expiry: Annotated[int, Field(description="Only show certs expiring within this many days; 0 shows all")] = 0,
    ) -> dict[str, Any]:
        """List certificates from the Personal (My) store sorted by days until expiry, showing Subject, Expires, DaysLeft, and Thumbprint. Cert expiry is a top cause of silent outages, so set days_until_expiry to surface certs expiring soon.
        """
        store_map = {"localmachine": "LocalMachine", "currentuser": "CurrentUser"}
        st = store_map.get(store.strip().lower())
        if not st:
            return {"error": "store must be 'LocalMachine' or 'CurrentUser'"}

        expiry_filter = ""
        if days_until_expiry > 0:
            expiry_filter = (
                "| Where-Object { $_.NotAfter -lt (Get-Date).AddDays("
                + str(days_until_expiry) + ") } "
            )

        cmd = (
            "Get-ChildItem -Path 'Cert:\\" + st + "\\My' -ErrorAction Stop "
            + expiry_filter +
            "| Select-Object "
            "@{N='Subject';E={$_.Subject.Substring(0,[Math]::Min($_.Subject.Length,80))}}, "
            "@{N='Expires';E={$_.NotAfter.ToString('yyyy-MM-dd')}}, "
            "@{N='DaysLeft';E={[math]::Round(($_.NotAfter-(Get-Date)).TotalDays)}}, "
            "Thumbprint "
            "| Sort-Object DaysLeft "
            "| Format-Table -AutoSize | Out-String -Width 300"
        )
        return sm.run_ps(session_id, cmd, tool_name="get_certificates")

    @mcp.tool()
    def get_network_config(
        session_id: Annotated[str, Field(description="Session ID returned by connect")],
    ) -> dict[str, Any]:
        """Return per-NIC network configuration as tabular text: interface name, Up/Down status, IPv4 address, default gateway, and DNS servers. Essential for network triage to confirm IP assignment, DNS, and gateway reachability.
        """
        cmd = (
            "Get-NetIPConfiguration -ErrorAction SilentlyContinue "
            "| Select-Object InterfaceAlias, "
            "@{N='Status';E={$_.NetAdapter.Status}}, "
            "@{N='IPv4';E={($_.IPv4Address.IPAddress) -join ','}}, "
            "@{N='Gateway';E={($_.IPv4DefaultGateway.NextHop) -join ','}}, "
            "@{N='DNS';E={($_.DNSServer.ServerAddresses) -join ','}} "
            "| Format-Table -AutoSize | Out-String -Width 300"
        )
        return sm.run_ps(session_id, cmd, tool_name="get_network_config")

    # ==================================================================
    # Environment, tasks, users, permissions — read-only
    # ==================================================================

    @mcp.tool()
    def get_environment_variables(
        session_id: Annotated[str, Field(description="Session ID returned by connect")],
        name_filter: Annotated[str, Field(description="Wildcard on variable name, e.g. '*JAVA*', '*PATH*'; empty means all")] = "",
        scope: Annotated[str, Field(description="Variable scope: Machine (default), User, or Process")] = "Machine",
    ) -> dict[str, Any]:
        """Return environment variables (name and value) for the chosen scope as tabular text. Use it to check JAVA_HOME, PATH, or service-specific configuration.
        """
        scope_map = {"machine": "Machine", "user": "User", "process": "Process"}
        sc = scope_map.get(scope.strip().lower())
        if not sc:
            return {"error": "scope must be 'Machine', 'User', or 'Process'"}

        name_where = ""
        if name_filter.strip():
            safe_nf = _ps_escape(name_filter.strip())
            name_where = "| Where-Object { $_.Name -like '" + safe_nf + "' } "

        cmd = (
            "[Environment]::GetEnvironmentVariables('" + sc + "').GetEnumerator() "
            "| Select-Object Name, Value "
            + name_where +
            "| Sort-Object Name "
            "| Format-Table -AutoSize -Wrap | Out-String -Width 300"
        )
        return sm.run_ps(session_id, cmd, tool_name="get_environment_variables")

    @mcp.tool()
    def get_scheduled_tasks(
        session_id: Annotated[str, Field(description="Session ID returned by connect")],
        name_filter: Annotated[str, Field(description="Wildcard on task name, e.g. '*backup*'; empty means all non-Microsoft tasks")] = "",
        include_disabled: Annotated[bool, Field(description="Include disabled tasks; default shows only Ready/Running")] = False,
    ) -> dict[str, Any]:
        """List Windows scheduled tasks as tabular text with name, state, last run time, last result, and next run time. Use it to see what automated jobs (backups, cleanup, batch processes) run on this server.
        """
        where_parts: list[str] = []

        if not include_disabled:
            where_parts.append("$_.State -ne 'Disabled'")

        if name_filter.strip():
            safe_nf = _ps_escape(name_filter.strip())
            where_parts.append("$_.TaskName -like '" + safe_nf + "'")
        else:
            where_parts.append("$_.TaskPath -notlike '\\Microsoft\\*'")

        where = "| Where-Object { " + " -and ".join(where_parts) + " } "

        cmd = (
            "Get-ScheduledTask -ErrorAction SilentlyContinue "
            + where +
            "| ForEach-Object { "
            "$info = Get-ScheduledTaskInfo -TaskName $_.TaskName -TaskPath $_.TaskPath -ErrorAction SilentlyContinue; "
            "[PSCustomObject]@{"
            "Name=$_.TaskName; "
            "State=[string]$_.State; "
            "LastRun=if($info.LastRunTime -and $info.LastRunTime.Year -gt 1999)"
            "{$info.LastRunTime.ToString('yyyy-MM-dd HH:mm')}else{'Never'}; "
            "LastResult=if($info){$info.LastTaskResult}else{'N/A'}; "
            "NextRun=if($info.NextRunTime -and $info.NextRunTime.Year -gt 1999)"
            "{$info.NextRunTime.ToString('yyyy-MM-dd HH:mm')}else{'None'}"
            "}} "
            "| Sort-Object Name "
            "| Format-Table -AutoSize | Out-String -Width 300"
        )
        return sm.run_ps(session_id, cmd, tool_name="get_scheduled_tasks")

    @mcp.tool()
    def get_local_users(
        session_id: Annotated[str, Field(description="Session ID returned by connect")],
    ) -> dict[str, Any]:
        """List local user accounts as tabular text with name, enabled status, last logon, and description. Use it to spot rogue accounts, locked-out service accounts, or disabled accounts.
        """
        cmd = (
            "Get-LocalUser -ErrorAction Stop "
            "| Select-Object Name, Enabled, "
            "@{N='LastLogon';E={if($_.LastLogon){$_.LastLogon.ToString('yyyy-MM-dd HH:mm')}else{'Never'}}}, "
            "@{N='PasswordExpires';E={if($_.PasswordExpires){$_.PasswordExpires.ToString('yyyy-MM-dd')}else{'Never'}}}, "
            "Description "
            "| Sort-Object Name "
            "| Format-Table -AutoSize -Wrap | Out-String -Width 300"
        )
        return sm.run_ps(session_id, cmd, tool_name="get_local_users")

    @mcp.tool()
    def get_user_groups(
        session_id: Annotated[str, Field(description="Session ID returned by connect")],
        username: Annotated[str, Field(description="User to look up, e.g. 'DOMAIN\\\\svc-account'; empty lists all local groups")] = "",
    ) -> dict[str, Any]:
        """Show local group memberships as tabular text: with no username it lists all local groups and members, with a username it shows that user's local groups. For full AD domain group membership of the current session, use get_security_context instead.
        """
        if username.strip():
            safe_user = _ps_escape(username.strip())
            cmd = (
                "$u = '" + safe_user + "'; "
                "Write-Output '=== Local Group Memberships ==='; "
                "$found = @(); "
                "Get-LocalGroup -ErrorAction SilentlyContinue | ForEach-Object { "
                "$members = Get-LocalGroupMember -Group $_.Name -ErrorAction SilentlyContinue; "
                "$match = $members | Where-Object { $_.Name -eq $u -or $_.Name -like \"*\\$u\" }; "
                "if ($match) { $found += [PSCustomObject]@{Group=$_.Name; Description=$_.Description} } "
                "}; "
                "if ($found) { $found | Format-Table -AutoSize -Wrap | Out-String -Width 300 } "
                "else { Write-Output '  (not a member of any local groups)' }; "
                "Write-Output ''; "
                "Write-Output 'TIP: For full AD group membership of the current session, use get_security_context.'"
            )
        else:
            cmd = (
                "Get-LocalGroup -ErrorAction SilentlyContinue | ForEach-Object { "
                "$g = $_.Name; "
                "$members = (Get-LocalGroupMember -Group $g -ErrorAction SilentlyContinue "
                "| Select-Object -ExpandProperty Name) -join ', '; "
                "[PSCustomObject]@{Group=$g; Members=if($members){$members}else{'(empty)'}} "
                "} | Format-Table -AutoSize -Wrap | Out-String -Width 300"
            )
        return sm.run_ps(session_id, cmd, tool_name="get_user_groups")

    @mcp.tool()
    def get_security_context(
        session_id: Annotated[str, Field(description="Session ID returned by connect")],
    ) -> dict[str, Any]:
        """Show the current WinRM session's security context as JSON (like 'whoami /all'): identity, group memberships including AD domain groups, privileges, and integrity level. Essential for diagnosing access-denied errors and understanding what the service account can do.
        """
        cmd = (
            "$wi = [Security.Principal.WindowsIdentity]::GetCurrent(); "
            "$wp = New-Object Security.Principal.WindowsPrincipal($wi); "
            "$elevated = $wp.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator); "
            "$groups = $wi.Groups | ForEach-Object { "
            "try { $_.Translate([Security.Principal.NTAccount]).Value } "
            "catch { $_.Value } "
            "} | Sort-Object; "
            "$privs = whoami /priv /fo csv 2>$null | ConvertFrom-Csv "
            "| Select-Object @{N='Privilege';E={$_.'Privilege Name'}}, "
            "@{N='Enabled';E={$_.State -eq 'Enabled'}}; "
            "[PSCustomObject]@{"
            "Identity=$wi.Name; "
            "SID=$wi.User.Value; "
            "AuthType=$wi.AuthenticationType; "
            "IsElevated=$elevated; "
            "IntegrityLevel=if($elevated){'High'}else{'Medium'}; "
            "Groups=$groups; "
            "GroupCount=$groups.Count; "
            "Privileges=@($privs)"
            "} | ConvertTo-Json -Compress -Depth 3"
        )
        return sm.run_ps(session_id, cmd, tool_name="get_security_context")

    @mcp.tool()
    def get_permissions(
        session_id: Annotated[str, Field(description="Session ID returned by connect")],
        path: Annotated[str, Field(description="Absolute path to the file or folder to check")],
    ) -> dict[str, Any]:
        """Return the access control list (ACL) for a file or folder as tabular text: each entry's identity, Allow/Deny type, rights, and inheritance. Essential for troubleshooting access-denied errors.
        """
        safe = _ps_escape(path)
        cmd = (
            "$acl = Get-Acl -LiteralPath '" + safe + "' -ErrorAction Stop; "
            "Write-Output (\"Owner: \" + $acl.Owner); "
            "Write-Output ''; "
            "$acl.Access "
            "| Select-Object "
            "@{N='Identity';E={$_.IdentityReference}}, "
            "AccessControlType, "
            "@{N='Rights';E={$_.FileSystemRights}}, "
            "@{N='Inherited';E={$_.IsInherited}} "
            "| Format-Table -AutoSize -Wrap | Out-String -Width 300"
        )
        return sm.run_ps(session_id, cmd, tool_name="get_permissions")

    # ==================================================================
    # Network, DNS, software, file comparison — read-only
    # ==================================================================

    @mcp.tool()
    def get_tcp_connections(
        session_id: Annotated[str, Field(description="Session ID returned by connect")],
        state_filter: Annotated[str, Field(description="State filter: Established (default), Listen, TimeWait, CloseWait, or All")] = "Established",
        port_filter: Annotated[int, Field(description="Only show connections involving this port; 0 means all ports")] = 0,
    ) -> dict[str, Any]:
        """List active TCP connections as tabular text with local/remote addresses, ports, state, and owning process (like netstat -an). Use it to check database connections, find connection leaks, or see what is talking to what.
        """
        state_map = {
            "established": "Established", "listen": "Listen",
            "timewait": "TimeWait", "closewait": "CloseWait",
            "finwait1": "FinWait1", "finwait2": "FinWait2",
            "synreceived": "SynReceived", "bound": "Bound",
        }

        where_parts: list[str] = []
        sf = state_filter.strip().lower()
        if sf != "all":
            ps_state = state_map.get(sf, "Established")
            where_parts.append("$_.State -eq '" + ps_state + "'")

        if port_filter > 0:
            where_parts.append(
                "($_.LocalPort -eq " + str(port_filter) +
                " -or $_.RemotePort -eq " + str(port_filter) + ")"
            )

        where = ""
        if where_parts:
            where = "| Where-Object { " + " -and ".join(where_parts) + " } "

        cmd = (
            "Get-NetTCPConnection -ErrorAction SilentlyContinue "
            + where +
            "| Select-Object "
            "@{N='Local';E={\"$($_.LocalAddress):$($_.LocalPort)\"}}, "
            "@{N='Remote';E={\"$($_.RemoteAddress):$($_.RemotePort)\"}}, "
            "State, "
            "@{N='PID';E={$_.OwningProcess}}, "
            "@{N='Process';E={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}} "
            "| Sort-Object Remote "
            "| Format-Table -AutoSize | Out-String -Width 300"
        )
        return sm.run_ps(session_id, cmd, tool_name="get_tcp_connections")

    @mcp.tool()
    def get_dns_cache(
        session_id: Annotated[str, Field(description="Session ID returned by connect")],
        name_filter: Annotated[str, Field(description="Wildcard on record name, e.g. '*sql*'; empty means all entries")] = "",
    ) -> dict[str, Any]:
        """Read the local DNS client cache as tabular text: cached record name, type, TTL, and resolved data. Use it to diagnose wrong resolution from this server or stale DNS after a migration.
        """
        name_where = ""
        if name_filter.strip():
            safe_nf = _ps_escape(name_filter.strip())
            name_where = "| Where-Object { $_.Entry -like '" + safe_nf + "' } "

        cmd = (
            "Get-DnsClientCache -ErrorAction SilentlyContinue "
            + name_where +
            "| Select-Object Entry, "
            "@{N='Type';E={$_.Type}}, "
            "@{N='TTL_s';E={$_.TimeToLive}}, "
            "@{N='Data';E={$_.Data}} "
            "| Sort-Object Entry "
            "| Select-Object -First 100 "
            "| Format-Table -AutoSize | Out-String -Width 300"
        )
        return sm.run_ps(session_id, cmd, tool_name="get_dns_cache")

    @mcp.tool()
    def get_installed_software(
        session_id: Annotated[str, Field(description="Session ID returned by connect")],
        name_filter: Annotated[str, Field(description="Wildcard on software name, e.g. '*java*', '*.NET*'; empty means all")] = "",
    ) -> dict[str, Any]:
        """List installed software as tabular text with name, version, publisher, and install date, reading both 64-bit and 32-bit uninstall keys. Use it to check Java, .NET, SQL, or any application version.
        """
        name_where = ""
        if name_filter.strip():
            safe_nf = _ps_escape(name_filter.strip())
            name_where = "| Where-Object { $_.DisplayName -like '" + safe_nf + "' } "

        cmd = (
            "$paths = @("
            "'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*', "
            "'HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*'); "
            "$paths | ForEach-Object { Get-ItemProperty $_ -ErrorAction SilentlyContinue } "
            "| Where-Object { $_.DisplayName } "
            + name_where +
            "| Select-Object DisplayName, DisplayVersion, Publisher, InstallDate "
            "| Sort-Object DisplayName -Unique "
            "| Format-Table -AutoSize -Wrap | Out-String -Width 300"
        )
        return sm.run_ps(session_id, cmd, tool_name="get_installed_software")

    @mcp.tool()
    def compare_files(
        session_id: Annotated[str, Field(description="Session ID returned by connect")],
        path_a: Annotated[str, Field(description="Absolute path to the first file (reference)")],
        path_b: Annotated[str, Field(description="Absolute path to the second file (difference)")],
        max_diffs: Annotated[int, Field(description="Maximum differing lines to show, default 50, capped at 200")] = 50,
    ) -> dict[str, Any]:
        """Compare two files line by line like diff, showing each differing line and which file it came from. Use it to compare configs between environments.
        """
        safe_a = _ps_escape(path_a)
        safe_b = _ps_escape(path_b)
        cap = max(1, min(max_diffs, 200))
        cmd = (
            "$a = Get-Content -LiteralPath '" + safe_a + "' -ErrorAction Stop; "
            "$b = Get-Content -LiteralPath '" + safe_b + "' -ErrorAction Stop; "
            "Write-Output (\"File A: " + safe_a + " ($($a.Count) lines)\"); "
            "Write-Output (\"File B: " + safe_b + " ($($b.Count) lines)\"); "
            "Write-Output ''; "
            "$diff = Compare-Object -ReferenceObject $a -DifferenceObject $b -ErrorAction Stop; "
            "if (-not $diff) { Write-Output 'Files are identical.' } "
            "else { "
            "Write-Output (\"$($diff.Count) differences found:\"); "
            "Write-Output ''; "
            "$diff | Select-Object -First " + str(cap) + " "
            "@{N='Line';E={$_.InputObject}}, "
            "@{N='Source';E={if($_.SideIndicator -eq '=>'){'B (only)'}else{'A (only)'}}} "
            "| Format-Table -AutoSize -Wrap | Out-String -Width 300 }"
        )
        return sm.run_ps(session_id, cmd, tool_name="compare_files")

    # ==================================================================
    # DNS resolution — read-only
    # ==================================================================

    @mcp.tool()
    def resolve_dns_name(
        session_id: Annotated[str, Field(description="Session ID returned by connect")],
        name: Annotated[str, Field(description="Hostname or FQDN to resolve, e.g. 'db.example.com'")],
        record_type: Annotated[str, Field(description="Record type: A (default), AAAA, CNAME, MX, NS, PTR, SOA, SRV, TXT")] = "A",
        dns_server: Annotated[str, Field(description="Specific DNS server to query; empty uses the system default")] = "",
    ) -> dict[str, Any]:
        """Resolve a DNS name from the remote server's perspective as tabular text, showing the full resolution chain including CNAMEs. Use it to verify DNS propagation or compare resolution between servers.
        """
        valid_types = {"a", "aaaa", "cname", "mx", "ns", "ptr", "soa", "srv", "txt"}
        rt = record_type.strip().upper()
        if rt.lower() not in valid_types:
            return {"error": f"Invalid record_type '{record_type}'. Valid: {', '.join(sorted(t.upper() for t in valid_types))}"}

        safe_name = _ps_escape(name)
        server_arg = ""
        if dns_server.strip():
            safe_dns = _ps_escape(dns_server.strip())
            server_arg = " -Server '" + safe_dns + "'"

        cmd = (
            "Resolve-DnsName -Name '" + safe_name + "' "
            "-Type " + rt + server_arg + " -ErrorAction Stop "
            "| Select-Object Name, Type, TTL, "
            "@{N='Data';E={"
            "if($_.IPAddress){$_.IPAddress}"
            "elseif($_.NameHost){$_.NameHost}"
            "elseif($_.NameExchange){\"$($_.NameExchange) (pri:$($_.Preference))\"}"
            "elseif($_.NameTarget){\"$($_.NameTarget):$($_.Port)\"}"
            "elseif($_.Strings){$_.Strings -join ' '}"
            "elseif($_.PrimaryServer){$_.PrimaryServer}"
            "else{'N/A'}"
            "}} "
            "| Format-Table -AutoSize | Out-String -Width 300"
        )
        return sm.run_ps(session_id, cmd, tool_name="resolve_dns_name")

    # ==================================================================
    # SFTP — read-only (via Posh-SSH on the remote Windows host)
    #
    # Credentials are entered once via sftp_connect and cached in memory with
    # an idle TTL (keyed per AD user). The read tools then take only an
    # sftp_session_id. Each call still re-establishes the SFTP connection,
    # because every run_ps runs in a fresh WinRM shell; the cache only avoids
    # re-passing the secret, it does not keep the SFTP socket open.
    # ==================================================================

    sftp_creds = _SftpCredStore(SFTP_CRED_IDLE_TTL_SECONDS)

    def _sftp_exec(cred: _SftpCred, op_block: str, tool_name: str) -> dict[str, Any]:
        """Open a Posh-SSH SFTP session from cred, run op_block (which uses
        $s.SessionId), and always tear it down. The secret is redacted."""
        redactions: list[str] = []
        if cred.secret:
            redactions.append(cred.secret)
            cred_block = (
                "$sec = ConvertTo-SecureString '" + _ps_escape(cred.secret)
                + "' -AsPlainText -Force; "
            )
        else:
            cred_block = "$sec = New-Object System.Security.SecureString; "
        cred_block += (
            "$cred = New-Object System.Management.Automation.PSCredential('"
            + _ps_escape(cred.user) + "', $sec); "
        )

        key_arg = ""
        if cred.auth_method == "key":
            key_arg = "-KeyFile '" + _ps_escape(cred.key_path) + "' "

        preamble = (
            "$ErrorActionPreference='Stop'; "
            "if (-not (Get-Module -ListAvailable Posh-SSH)) "
            "{ throw 'Posh-SSH module is not installed on the remote host' }; "
            "Import-Module Posh-SSH -ErrorAction Stop; "
            + cred_block +
            "$s = New-SFTPSession -ComputerName '" + _ps_escape(cred.host) + "' "
            "-Port " + str(cred.port) + " -Credential $cred " + key_arg +
            "-AcceptKey -ConnectionTimeout " + str(cred.timeout) + "; "
        )

        cmd = (
            "try { " + preamble + op_block + " } "
            "finally { if ($s) { Remove-SFTPSession -SessionId $s.SessionId "
            "-ErrorAction SilentlyContinue | Out-Null } }"
        )
        return sm.run_ps(
            cred.win_session_id, cmd, tool_name=tool_name, redactions=redactions
        )

    def _resolve_sftp(sftp_session_id: str) -> tuple[_SftpCred | None, dict[str, Any] | None]:
        cred = sftp_creds.get(sm.current_username(), sftp_session_id)
        if cred is None:
            return None, {
                "error": f"Unknown or expired sftp_session_id '{sftp_session_id}'. "
                "Call sftp_connect first."
            }
        return cred, None

    @mcp.tool()
    def sftp_connect(
        session_id: Annotated[str, Field(description="WinRM session ID from connect; the SFTP connection is made FROM this Windows host")],
        sftp_host: Annotated[str, Field(description="Target SFTP server hostname or IP, e.g. 'sftp.example.com'")],
        sftp_user: Annotated[str, Field(description="SFTP username")],
        auth_method: Annotated[str, Field(description="'password' (default) or 'key'")] = "password",
        password: Annotated[str, Field(description="SFTP password, or key passphrase when auth_method='key'; cached in memory and redacted from logs")] = "",
        key_path: Annotated[str, Field(description="Path to the private key file ON the Windows host; required when auth_method='key'")] = "",
        sftp_port: Annotated[int, Field(description="SFTP port, default 22")] = 22,
        timeout_sec: Annotated[int, Field(description="Connection timeout seconds, default 30, capped at 120")] = 30,
    ) -> dict[str, Any]:
        """Validate SFTP credentials against a target server (reached FROM the connected Windows host) and cache them in memory, returning an sftp_session_id. Pass that id to sftp_list_directory, sftp_stat, and sftp_read_file so the secret is entered only once. Credentials expire after an idle TTL; call sftp_disconnect when done.
        """
        am = auth_method.strip().lower()
        if am not in ("password", "key"):
            return {"error": "auth_method must be 'password' or 'key'"}
        if am == "key" and not key_path.strip():
            return {"error": "key_path is required when auth_method='key'"}
        if am == "password" and not password:
            return {"error": "password is required when auth_method='password'"}
        if not sftp_host.strip() or not sftp_user.strip():
            return {"error": "sftp_host and sftp_user are required"}

        cred = _SftpCred(
            win_session_id=session_id,
            host=sftp_host.strip(),
            port=max(1, min(sftp_port, 65535)),
            user=sftp_user.strip(),
            auth_method=am,
            secret=password,
            key_path=key_path.strip() if am == "key" else "",
            timeout=max(1, min(timeout_sec, 120)),
            last_used=time.monotonic(),
        )

        op = "Get-SFTPLocation -SessionId $s.SessionId | ForEach-Object { \"pwd=$_\" }"
        result = _sftp_exec(cred, op, "sftp_connect")
        if "error" in result or result.get("status_code", 1) != 0:
            return {
                "status": "error",
                "error": (result.get("stderr") or result.get("error")
                          or "SFTP connection failed").strip(),
            }

        sid = cred.user + "@" + cred.host
        if cred.port != 22:
            sid += ":" + str(cred.port)
        cred.last_used = time.monotonic()
        sftp_creds.put(sm.current_username(), sid, cred)
        return {
            "sftp_session_id": sid,
            "status": "connected",
            "host": cred.host,
            "port": cred.port,
            "user": cred.user,
            "auth_method": cred.auth_method,
            "working_dir": result.get("stdout", "").strip(),
        }

    @mcp.tool()
    def sftp_disconnect(
        sftp_session_id: Annotated[str, Field(description="SFTP session ID returned by sftp_connect")],
    ) -> dict[str, Any]:
        """Drop a cached SFTP credential set so its secret leaves server memory; call it when finished with a target. SFTP credentials are not auto-cleaned except by the idle TTL.
        """
        if sftp_creds.pop(sm.current_username(), sftp_session_id):
            return {"sftp_session_id": sftp_session_id, "status": "disconnected"}
        return {"error": f"Unknown sftp_session_id '{sftp_session_id}'"}

    @mcp.tool()
    def sftp_list_sessions() -> dict[str, Any]:
        """List your active (non-expired) SFTP sessions with target host, port, user, and auth method. Use it to find an sftp_session_id. Secrets are never returned.
        """
        items = sftp_creds.list(sm.current_username())
        return {"sftp_sessions": items, "count": len(items)}

    @mcp.tool()
    def sftp_list_directory(
        sftp_session_id: Annotated[str, Field(description="SFTP session ID returned by sftp_connect")],
        remote_path: Annotated[str, Field(description="Remote directory to list, e.g. '/incoming' or '.'")],
    ) -> dict[str, Any]:
        """List a directory on a remote SFTP server (via the cached sftp_session_id) as tabular text (Type, Length, Modified, Name; max 300 entries). Read-only: it never modifies the SFTP target.
        """
        cred, err = _resolve_sftp(sftp_session_id)
        if err is not None:
            return err
        rp = _ps_escape(remote_path)
        op = (
            "Get-SFTPChildItem -SessionId $s.SessionId -Path '" + rp + "' "
            "| Select-Object -First 300 "
            "@{N='Type';E={if($_.IsDirectory){'D'}else{'-'}}}, "
            "@{N='Length';E={$_.Length}}, "
            "@{N='Modified';E={$_.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')}}, "
            "@{N='Name';E={$_.Name}} "
            "| Sort-Object Type, Name | Format-Table -AutoSize | Out-String -Width 300"
        )
        return _sftp_exec(cred, op, "sftp_list_directory")

    @mcp.tool()
    def sftp_stat(
        sftp_session_id: Annotated[str, Field(description="SFTP session ID returned by sftp_connect")],
        remote_path: Annotated[str, Field(description="Remote file or directory path to inspect")],
    ) -> dict[str, Any]:
        """Return JSON metadata for one path on a remote SFTP server (IsDirectory, IsRegularFile, SizeBytes, Modified) via the cached sftp_session_id. Read-only. Use it to confirm a path exists and check a file's size before reading it.
        """
        cred, err = _resolve_sftp(sftp_session_id)
        if err is not None:
            return err
        rp = _ps_escape(remote_path)
        op = (
            "$a = Get-SFTPPathAttribute -SessionId $s.SessionId -Path '" + rp + "'; "
            "[PSCustomObject]@{"
            "Path='" + rp + "'; "
            "IsDirectory=$a.IsDirectory; "
            "IsRegularFile=$a.IsRegularFile; "
            "SizeBytes=$a.Size; "
            "Modified=$a.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')"
            "} | ConvertTo-Json -Compress"
        )
        return _sftp_exec(cred, op, "sftp_stat")

    @mcp.tool()
    def sftp_read_file(
        sftp_session_id: Annotated[str, Field(description="SFTP session ID returned by sftp_connect")],
        remote_path: Annotated[str, Field(description="Remote file path to read")],
        max_lines: Annotated[int, Field(description="Max lines to return, default 200, capped at 500")] = 200,
    ) -> dict[str, Any]:
        """Read a remote SFTP text file's contents as numbered lines (max 500) in '     1|line' format via the cached sftp_session_id. Read-only: the file is fetched into memory and never modified on the target. Best for logs and config files; check size with sftp_stat first for large files.
        """
        cred, err = _resolve_sftp(sftp_session_id)
        if err is not None:
            return err
        rp = _ps_escape(remote_path)
        cap = max(1, min(max_lines, 500))
        op = (
            "$c = Get-SFTPContent -SessionId $s.SessionId -Path '" + rp + "'; "
            "if ($c -is [byte[]]) { $c = [System.Text.Encoding]::UTF8.GetString($c) }; "
            "$lines = @(($c -split '\\r?\\n') | Select-Object -First " + str(cap) + "); "
            "$n = 1; $lines | ForEach-Object { '{0,6}|{1}' -f ($n++), $_ }; "
            "Write-Output (\"--- read $($lines.Count) lines ---\")"
        )
        return _sftp_exec(cred, op, "sftp_read_file")

    # ==================================================================
    # Write operations (all require user confirmation via elicitation)
    # ==================================================================

    async def _confirm(ctx: Context, action: str, details: str) -> bool:
        """Prompt the user to confirm a destructive/modifying action.

        The prompt asks for a boolean: fastmcp 4 removed the empty-schema
        ``response_type=None`` form, which some clients rendered as an empty,
        non-functional dialog. Anything other than an explicit accept carrying
        True means no.
        """
        try:
            result = await ctx.elicit(
                message=f"Confirm {action}?\n\n{details}",
                response_type=bool,
                response_title="Confirm",
                response_description=f"Approve {action}",
            )
            return result.action == "accept" and result.data is True
        except Exception as e:
            # Fail closed, but say why: a declined prompt and a client that
            # cannot prompt at all are different problems. Clients on the
            # 2026-07-28 protocol have no back-channel for elicitation.
            logger.error("Elicitation unavailable — rejecting modification: %s", e)
            raise ToolError(
                f"Cannot ask for confirmation, so {action} was not performed: {e}"
            ) from e

    @mcp.tool()
    async def flush_dns(
        session_id: Annotated[str, Field(description="Session ID returned by connect")],
        ctx: Context,
    ) -> dict[str, Any]:
        """Clear the local DNS client cache on the remote server so future lookups re-resolve; harmless but prompts for confirmation. Use it after a DNS migration, failover, or when stale entries are suspected.
        """
        confirmed = await _confirm(
            ctx, "FLUSH DNS CACHE",
            "This will clear all cached DNS entries on the remote server.\nAll future lookups will re-resolve from the DNS server.",
        )
        if not confirmed:
            return {"status": "cancelled", "message": "Flush DNS cancelled by user"}

        cmd = (
            "$before = (Get-DnsClientCache -ErrorAction SilentlyContinue | Measure-Object).Count; "
            "Clear-DnsClientCache; "
            "$after = (Get-DnsClientCache -ErrorAction SilentlyContinue | Measure-Object).Count; "
            "Write-Output \"DNS cache flushed. Entries before: $before, after: $after\""
        )
        return sm.run_ps(session_id, cmd, tool_name="flush_dns")

    @mcp.tool()
    async def invoke_http_request(
        session_id: Annotated[str, Field(description="Session ID returned by connect")],
        url: Annotated[str, Field(description="Full URL to request, e.g. 'http://localhost:8080/health'")],
        ctx: Context,
        method: Annotated[str, Field(description="HTTP method: GET (default), HEAD, POST, PUT, or DELETE")] = "GET",
        headers: Annotated[str, Field(description="Optional 'Key:Value' header pairs separated by '|'")] = "",
        body: Annotated[str, Field(description="Optional request body for POST/PUT, max 64KB")] = "",
        timeout_sec: Annotated[int, Field(description="Request timeout in seconds, default 15, capped at 60")] = 15,
    ) -> dict[str, Any]:
        """Make an HTTP request from the remote Windows server and return status code, headers, and body; prompts for confirmation. Use it to test connectivity and API health from that host's network perspective.
        """
        valid_methods = {"GET", "HEAD", "POST", "PUT", "DELETE"}
        m = method.strip().upper()
        if m not in valid_methods:
            return {"error": f"Invalid method '{method}'. Valid: {', '.join(sorted(valid_methods))}"}
        if len(body) > 65536:
            return {"error": "Body exceeds 64KB limit"}
        timeout = max(1, min(timeout_sec, 60))

        details = f"Method: {m}\nURL: {url}"
        if headers:
            details += f"\nHeaders: {headers}"
        if body:
            preview = body[:200] + ("..." if len(body) > 200 else "")
            details += f"\nBody: {preview}"
        details += f"\nTimeout: {timeout}s"

        confirmed = await _confirm(
            ctx, "HTTP REQUEST (from remote server)",
            details,
        )
        if not confirmed:
            return {"status": "cancelled", "message": "HTTP request cancelled by user"}

        safe_url = _ps_escape(url)

        header_block = ""
        if headers.strip():
            pairs: list[str] = []
            for pair in headers.split("|"):
                if ":" in pair:
                    k, v = pair.split(":", 1)
                    pairs.append(
                        "'" + _ps_escape(k.strip()) + "'='"
                        + _ps_escape(v.strip()) + "'"
                    )
            if pairs:
                header_block = "$hdrs = @{" + "; ".join(pairs) + "}; "

        body_block = ""
        if body and m in ("POST", "PUT"):
            b64_body = base64.b64encode(body.encode("utf-8")).decode("ascii")
            body_block = (
                "$bodyBytes = [Convert]::FromBase64String('" + b64_body + "'); "
                "$bodyStr = [System.Text.Encoding]::UTF8.GetString($bodyBytes); "
            )

        hdr_arg = " -Headers $hdrs" if header_block else ""
        body_arg = " -Body $bodyStr" if body_block else ""
        content_type_arg = ""
        if body and m in ("POST", "PUT") and "content-type" not in headers.lower():
            content_type_arg = " -ContentType 'application/json'"

        cmd = (
            header_block + body_block +
            "$ProgressPreference = 'SilentlyContinue'; "
            "try { "
            "$r = Invoke-WebRequest -Uri '" + safe_url + "' "
            "-Method " + m + " "
            "-TimeoutSec " + str(timeout) +
            " -UseBasicParsing"
            + hdr_arg + body_arg + content_type_arg +
            " -ErrorAction Stop; "
            "$body = if ($r.Content -is [byte[]]) { [System.Text.Encoding]::UTF8.GetString($r.Content) } else { [string]$r.Content }; "
            "if ($body.Length -gt 8000) { $body = $body.Substring(0,8000) }; "
            "[PSCustomObject]@{"
            "StatusCode=$r.StatusCode; "
            "StatusDescription=$r.StatusDescription; "
            "ContentLength=$r.RawContentLength; "
            "Headers=($r.Headers | ConvertTo-Json -Compress); "
            "Body=$body"
            "} | ConvertTo-Json -Compress"
            " } catch { "
            "$e = $_.Exception; "
            "$emsg = [string]$e.Message; "
            "if ($emsg.Length -gt 500) { $emsg = $emsg.Substring(0,500) }; "
            "if ($e.Response) { "
            "[PSCustomObject]@{"
            "StatusCode=[int]$e.Response.StatusCode; "
            "StatusDescription=$e.Response.ReasonPhrase; "
            "Error=$emsg"
            "} | ConvertTo-Json -Compress"
            " } else { "
            "throw $e"
            " }}"
        )
        return sm.run_ps(session_id, cmd, tool_name="invoke_http_request")

    @mcp.tool()
    async def compress_archive(
        session_id: Annotated[str, Field(description="Session ID returned by connect")],
        source_path: Annotated[str, Field(description="File or directory to compress, e.g. 'C:\\App\\config'")],
        destination_zip: Annotated[str, Field(description="Output .zip path, e.g. 'C:\\backup\\configs.zip'")],
        ctx: Context,
        overwrite: Annotated[bool, Field(description="Allow overwriting an existing zip file, default False")] = False,
    ) -> dict[str, Any]:
        """Compress a file or directory into a .zip archive and report the resulting size; prompts for confirmation. Use it to archive logs, back up config directories, or bundle files for transfer.
        """
        safe_src = _ps_escape(source_path)
        safe_dst = _ps_escape(destination_zip)

        src_info_cmd = (
            "$s = Get-Item -LiteralPath '" + safe_src + "' -ErrorAction Stop; "
            "if ($s.PSIsContainer) { "
            "$items = (Get-ChildItem -LiteralPath '" + safe_src + "' -Recurse -File -ErrorAction SilentlyContinue | Measure-Object).Count; "
            "$size = (Get-ChildItem -LiteralPath '" + safe_src + "' -Recurse -File -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum; "
            "Write-Output \"Directory: $($s.FullName) ($items files, $([math]::Round($size/1MB,1)) MB)\" "
            "} else { "
            "Write-Output \"File: $($s.FullName) ($([math]::Round($s.Length/1MB,2)) MB)\" }"
        )
        src_info = sm.run_ps(session_id, src_info_cmd, tool_name="compress_archive")
        if "error" in src_info:
            return src_info
        src_desc = src_info.get("stdout", "").strip()

        confirmed = await _confirm(
            ctx, "COMPRESS to ZIP",
            f"Source: {src_desc}\nDestination: {destination_zip}\nOverwrite: {overwrite}",
        )
        if not confirmed:
            return {"status": "cancelled", "message": "Compress cancelled by user"}

        overwrite_check = ""
        if not overwrite:
            overwrite_check = (
                "if (Test-Path -LiteralPath '" + safe_dst + "') "
                "{ throw 'Destination zip already exists. Set overwrite=True to replace.' }; "
            )
        else:
            overwrite_check = (
                "if (Test-Path -LiteralPath '" + safe_dst + "') "
                "{ Remove-Item -LiteralPath '" + safe_dst + "' -Force }; "
            )

        cmd = (
            overwrite_check +
            "Compress-Archive -Path '" + safe_src + "' "
            "-DestinationPath '" + safe_dst + "' -ErrorAction Stop; "
            "Get-Item -LiteralPath '" + safe_dst + "' "
            "| Select-Object FullName, "
            "@{N='SizeMB';E={[math]::Round($_.Length/1MB,2)}}, "
            "@{N='Created';E={$_.CreationTime.ToString('yyyy-MM-dd HH:mm:ss')}} "
            "| ConvertTo-Json -Compress"
        )
        return sm.run_ps(session_id, cmd, tool_name="compress_archive")

    @mcp.tool()
    async def expand_archive(
        session_id: Annotated[str, Field(description="Session ID returned by connect")],
        zip_path: Annotated[str, Field(description="Absolute path to the .zip file to extract")],
        destination_dir: Annotated[str, Field(description="Target directory to extract into, created if missing")],
        ctx: Context,
        overwrite: Annotated[bool, Field(description="Overwrite existing files in the destination, default False")] = False,
    ) -> dict[str, Any]:
        """Extract a .zip archive to a directory; prompts for confirmation showing archive size and entry count. Use it to unpack backups, deploy packages, or restore config archives.
        """
        safe_zip = _ps_escape(zip_path)
        safe_dst = _ps_escape(destination_dir)

        zip_info_cmd = (
            "$z = Get-Item -LiteralPath '" + safe_zip + "' -ErrorAction Stop; "
            "Add-Type -AssemblyName System.IO.Compression.FileSystem; "
            "$archive = [IO.Compression.ZipFile]::OpenRead($z.FullName); "
            "$count = $archive.Entries.Count; $archive.Dispose(); "
            "Write-Output \"$($z.FullName) ($([math]::Round($z.Length/1MB,2)) MB, $count entries)\""
        )
        zip_info = sm.run_ps(session_id, zip_info_cmd, tool_name="expand_archive")
        if "error" in zip_info:
            return zip_info
        zip_desc = zip_info.get("stdout", "").strip()

        dst_exists = ""
        exists_check = sm.run_ps(  # noqa: tool_name not needed for this quick check
            session_id,
            "if (Test-Path -LiteralPath '" + safe_dst + "') { Write-Output 'EXISTS' } else { Write-Output 'NEW' }"
        )
        dst_status = exists_check.get("stdout", "").strip()

        confirmed = await _confirm(
            ctx, "EXTRACT ZIP",
            f"Archive: {zip_desc}\nExtract to: {destination_dir} ({dst_status})\nOverwrite files: {overwrite}",
        )
        if not confirmed:
            return {"status": "cancelled", "message": "Extract cancelled by user"}

        force_arg = " -Force" if overwrite else ""
        cmd = (
            "Expand-Archive -LiteralPath '" + safe_zip + "' "
            "-DestinationPath '" + safe_dst + "'"
            + force_arg + " -ErrorAction Stop; "
            "$items = Get-ChildItem -LiteralPath '" + safe_dst + "' -Recurse -File -ErrorAction SilentlyContinue; "
            "[PSCustomObject]@{"
            "ExtractedTo='" + safe_dst + "'; "
            "FileCount=$items.Count; "
            "TotalSizeMB=[math]::Round(($items | Measure-Object -Property Length -Sum).Sum/1MB,2)"
            "} | ConvertTo-Json -Compress"
        )
        return sm.run_ps(session_id, cmd, tool_name="expand_archive")

    @mcp.tool()
    async def copy_file(
        session_id: Annotated[str, Field(description="Session ID returned by connect")],
        source: Annotated[str, Field(description="Absolute path of the file to copy")],
        destination: Annotated[str, Field(description="Absolute destination path for the copy")],
        ctx: Context,
        overwrite: Annotated[bool, Field(description="Allow overwriting the destination if it exists, default False")] = False,
    ) -> dict[str, Any]:
        """Copy a file to a new location; prompts for confirmation and does not overwrite unless overwrite=True. Returns the resulting file's name, size, and modified time.
        """
        confirmed = await _confirm(
            ctx, "COPY FILE",
            f"From: {source}\nTo:   {destination}\nOverwrite: {overwrite}",
        )
        if not confirmed:
            return {"status": "cancelled", "message": "Copy cancelled by user"}

        safe_src = _ps_escape(source)
        safe_dst = _ps_escape(destination)

        overwrite_check = ""
        if not overwrite:
            overwrite_check = (
                "if (Test-Path -LiteralPath '" + safe_dst + "') "
                "{ throw 'Destination already exists. Set overwrite=True to replace.' }; "
            )

        cmd = (
            overwrite_check +
            "Copy-Item -LiteralPath '" + safe_src + "' "
            "-Destination '" + safe_dst + "' -Force -ErrorAction Stop; "
            "Get-Item -LiteralPath '" + safe_dst + "' "
            "| Select-Object FullName, Length, "
            "@{N='Modified';E={$_.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')}} "
            "| ConvertTo-Json -Compress"
        )
        return sm.run_ps(session_id, cmd, tool_name="copy_file")

    @mcp.tool()
    async def rename_file(
        session_id: Annotated[str, Field(description="Session ID returned by connect")],
        path: Annotated[str, Field(description="Absolute path of the file or directory to rename")],
        new_name: Annotated[str, Field(description="New filename only, not a full path, e.g. 'config_v2.xml'")],
        ctx: Context,
    ) -> dict[str, Any]:
        """Rename a file or directory in place within the same folder; prompts for confirmation. Use move_file to move across directories.
        """
        if "/" in new_name or "\\" in new_name:
            return {"error": "new_name must be a filename only, not a path. Use move_file to move across directories."}

        confirmed = await _confirm(
            ctx, "RENAME FILE",
            f"Path: {path}\nNew name: {new_name}",
        )
        if not confirmed:
            return {"status": "cancelled", "message": "Rename cancelled by user"}

        safe_path = _ps_escape(path)
        safe_name = _ps_escape(new_name)
        cmd = (
            "Rename-Item -LiteralPath '" + safe_path + "' "
            "-NewName '" + safe_name + "' -ErrorAction Stop; "
            "$parent = Split-Path -Parent '" + safe_path + "'; "
            "Get-Item -LiteralPath (Join-Path $parent '" + safe_name + "') "
            "| Select-Object FullName, Length, "
            "@{N='Modified';E={$_.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')}} "
            "| ConvertTo-Json -Compress"
        )
        return sm.run_ps(session_id, cmd, tool_name="rename_file")

    @mcp.tool()
    async def move_file(
        session_id: Annotated[str, Field(description="Session ID returned by connect")],
        source: Annotated[str, Field(description="Absolute path of the file to move")],
        destination: Annotated[str, Field(description="Absolute destination path including the filename")],
        ctx: Context,
        overwrite: Annotated[bool, Field(description="Allow overwriting the destination if it exists, default False")] = False,
    ) -> dict[str, Any]:
        """Move a file to a different location; prompts for confirmation and does not overwrite unless overwrite=True. Use rename_file when staying in the same directory.
        """
        confirmed = await _confirm(
            ctx, "MOVE FILE",
            f"From: {source}\nTo:   {destination}\nOverwrite: {overwrite}",
        )
        if not confirmed:
            return {"status": "cancelled", "message": "Move cancelled by user"}

        safe_src = _ps_escape(source)
        safe_dst = _ps_escape(destination)

        overwrite_check = ""
        if not overwrite:
            overwrite_check = (
                "if (Test-Path -LiteralPath '" + safe_dst + "') "
                "{ throw 'Destination already exists. Set overwrite=True to replace.' }; "
            )

        cmd = (
            overwrite_check +
            "Move-Item -LiteralPath '" + safe_src + "' "
            "-Destination '" + safe_dst + "' -Force -ErrorAction Stop; "
            "Get-Item -LiteralPath '" + safe_dst + "' "
            "| Select-Object FullName, Length, "
            "@{N='Modified';E={$_.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')}} "
            "| ConvertTo-Json -Compress"
        )
        return sm.run_ps(session_id, cmd, tool_name="move_file")

    @mcp.tool()
    async def create_directory(
        session_id: Annotated[str, Field(description="Session ID returned by connect")],
        path: Annotated[str, Field(description="Absolute directory path to create, e.g. 'C:\\backup\\2026-04-26'")],
        ctx: Context,
    ) -> dict[str, Any]:
        """Create a directory and any missing parents, prompting for confirmation; if it already exists, returns its info without error. Use it before writing files when the target folder might not exist.
        """
        safe = _ps_escape(path)

        exists_cmd = (
            "if (Test-Path -LiteralPath '" + safe + "') { "
            "$d = Get-Item -LiteralPath '" + safe + "' -Force; "
            "if (-not $d.PSIsContainer) { Write-Output 'EXISTS_AS_FILE' } "
            "else { Write-Output 'EXISTS_AS_DIR' } "
            "} else { Write-Output 'NOT_EXISTS' }"
        )
        check = sm.run_ps(session_id, exists_cmd, tool_name="create_directory")
        if "error" in check or check.get("status_code", 0) != 0:
            return {"error": check.get("stderr") or check.get("error") or "Pre-check failed", **check}
        state = check.get("stdout", "").strip()

        if state == "EXISTS_AS_FILE":
            return {"error": f"Path already exists as a file, not a directory: {path}"}
        if state == "EXISTS_AS_DIR":
            info_cmd = (
                "Get-Item -LiteralPath '" + safe + "' -Force "
                "| Select-Object FullName, "
                "@{N='Created';E={$_.CreationTime.ToString('yyyy-MM-dd HH:mm:ss')}}, "
                "@{N='Modified';E={$_.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')}} "
                "| ConvertTo-Json -Compress"
            )
            info = sm.run_ps(session_id, info_cmd, tool_name="create_directory")
            return {
                "status": "already_exists",
                "message": f"Directory already exists: {path}",
                "info": info.get("stdout", "").strip(),
            }

        confirmed = await _confirm(
            ctx, "CREATE DIRECTORY",
            f"Path: {path}\n\nThis will create the directory and any missing parent directories.",
        )
        if not confirmed:
            return {"status": "cancelled", "message": "Create directory cancelled by user"}

        cmd = (
            "New-Item -Path '" + safe + "' -ItemType Directory -Force -ErrorAction Stop "
            "| Select-Object FullName, "
            "@{N='Created';E={$_.CreationTime.ToString('yyyy-MM-dd HH:mm:ss')}} "
            "| ConvertTo-Json -Compress"
        )
        return sm.run_ps(session_id, cmd, tool_name="create_directory")

    @mcp.tool()
    async def delete_file(
        session_id: Annotated[str, Field(description="Session ID returned by connect")],
        path: Annotated[str, Field(description="Absolute path to the file to delete")],
        ctx: Context,
    ) -> dict[str, Any]:
        """Permanently delete a single file, showing its metadata in the confirmation prompt so you can verify the target. Refuses directories — use delete_directory for those.
        """
        safe = _ps_escape(path)

        pre_cmd = (
            "$item = Get-Item -LiteralPath '" + safe + "' -Force -ErrorAction Stop; "
            "if ($item.PSIsContainer) { throw 'Path is a directory — use delete_directory instead' }; "
            "[PSCustomObject]@{"
            "FullName=$item.FullName; "
            "SizeBytes=$item.Length; "
            "SizeKB=[math]::Round($item.Length/1KB,2); "
            "SizeMB=[math]::Round($item.Length/1MB,2); "
            "Modified=$item.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss'); "
            "Attributes=[string]$item.Attributes"
            "} | ConvertTo-Json -Compress"
        )
        pre = sm.run_ps(session_id, pre_cmd, tool_name="delete_file")
        if "error" in pre or pre.get("status_code", 0) != 0:
            return {"error": pre.get("stderr") or pre.get("error") or "Pre-check failed", **pre}
        file_desc = pre.get("stdout", "").strip()

        confirmed = await _confirm(
            ctx, "DELETE FILE",
            f"File details:\n{file_desc}\n\nThis will permanently delete the file. This cannot be undone.",
        )
        if not confirmed:
            return {"status": "cancelled", "message": "Delete file cancelled by user"}

        del_cmd = (
            "Remove-Item -LiteralPath '" + safe + "' -Force -ErrorAction Stop; "
            "if (Test-Path -LiteralPath '" + safe + "') "
            "{ Write-Output 'WARNING: file still exists after deletion attempt' } "
            "else { Write-Output 'File deleted successfully' }"
        )
        post = sm.run_ps(session_id, del_cmd, tool_name="delete_file")
        return {
            "deleted_file": file_desc,
            "result": post.get("stdout", "").strip(),
            "status_code": post.get("status_code"),
            "stderr": post.get("stderr", ""),
        }

    @mcp.tool()
    async def delete_directory(
        session_id: Annotated[str, Field(description="Session ID returned by connect")],
        path: Annotated[str, Field(description="Absolute path to the directory to delete recursively")],
        ctx: Context,
        max_items: Annotated[int, Field(description="Safety cap; refuse if more items exist, default 5000, max 50000")] = 5000,
    ) -> dict[str, Any]:
        """Recursively delete a directory and all contents after scanning to show file count and size in the confirmation prompt. Refuses when items exceed max_items or for drive roots and well-known system directories.
        """
        safe = _ps_escape(path)
        cap = max(1, min(max_items, 50000))

        protected = [
            "C:\\", "C:\\Windows", "C:\\Windows\\System32",
            "C:\\Program Files", "C:\\Program Files (x86)",
            "C:\\Users", "C:\\ProgramData",
            "D:\\", "E:\\",
        ]
        path_upper = path.strip().rstrip("\\").upper()
        for p in protected:
            if path_upper == p.upper():
                return {"error": f"Refusing to delete protected path: {path}"}

        pre_cmd = (
            "$item = Get-Item -LiteralPath '" + safe + "' -Force -ErrorAction Stop; "
            "if (-not $item.PSIsContainer) { throw 'Path is a file — use delete_file instead' }; "
            "$files = @(Get-ChildItem -LiteralPath '" + safe + "' -Recurse -File -Force "
            "-ErrorAction SilentlyContinue | Select-Object -First " + str(cap + 1) + "); "
            "$dirs = @(Get-ChildItem -LiteralPath '" + safe + "' -Recurse -Directory -Force "
            "-ErrorAction SilentlyContinue | Select-Object -First " + str(cap + 1) + "); "
            "$totalSize = ($files | Measure-Object -Property Length -Sum -ErrorAction SilentlyContinue).Sum; "
            "if (-not $totalSize) { $totalSize = 0 }; "
            "[PSCustomObject]@{"
            "FullName=$item.FullName; "
            "FileCount=$files.Count; "
            "DirCount=$dirs.Count; "
            "TotalItems=($files.Count + $dirs.Count); "
            "TotalSizeMB=[math]::Round($totalSize/1MB,2); "
            "TotalSizeGB=[math]::Round($totalSize/1GB,3); "
            "Created=$item.CreationTime.ToString('yyyy-MM-dd HH:mm:ss'); "
            "Modified=$item.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')"
            "} | ConvertTo-Json -Compress"
        )
        pre = sm.run_ps(session_id, pre_cmd, tool_name="delete_directory")
        if "error" in pre or pre.get("status_code", 0) != 0:
            return {"error": pre.get("stderr") or pre.get("error") or "Pre-check failed", **pre}
        dir_desc = pre.get("stdout", "").strip()

        import json
        try:
            scan = json.loads(dir_desc)
            total_items = scan.get("TotalItems", 0)
        except (json.JSONDecodeError, TypeError):
            total_items = 0

        if total_items > cap:
            return {
                "error": f"Directory contains {total_items}+ items — exceeds safety cap of {cap}. "
                f"Review the scan and set max_items higher if you are sure.",
                "scan": dir_desc,
            }

        confirmed = await _confirm(
            ctx, "DELETE DIRECTORY (recursive)",
            f"Directory scan:\n{dir_desc}\n\nThis will permanently delete the directory and ALL "
            f"its contents. This cannot be undone.",
        )
        if not confirmed:
            return {"status": "cancelled", "message": "Delete directory cancelled by user"}

        del_cmd = (
            "Remove-Item -LiteralPath '" + safe + "' -Recurse -Force -ErrorAction Stop; "
            "if (Test-Path -LiteralPath '" + safe + "') "
            "{ Write-Output 'WARNING: directory still exists after deletion attempt' } "
            "else { Write-Output 'Directory deleted successfully' }"
        )
        post = sm.run_ps(session_id, del_cmd, tool_name="delete_directory")
        return {
            "deleted_directory": dir_desc,
            "result": post.get("stdout", "").strip(),
            "status_code": post.get("status_code"),
            "stderr": post.get("stderr", ""),
        }

    # ==================================================================
    # Service management (all require user confirmation via elicitation)
    # ==================================================================

    def _svc_state_cmd(name: str) -> str:
        """Build PS to capture current service state as JSON."""
        safe = _ps_escape(name)
        return (
            "Get-Service -Name '" + safe + "' -ErrorAction Stop "
            "| Select-Object Name, Status, StartType, "
            "@{N='PID';E={(Get-CimInstance Win32_Service -Filter \"Name='$($_.Name)'\").ProcessId}} "
            "| ConvertTo-Json -Compress"
        )

    @mcp.tool()
    async def restart_service(
        session_id: Annotated[str, Field(description="Session ID returned by connect")],
        name: Annotated[str, Field(description="Exact service name, not display name, e.g. 'JBossEAP8', 'MSSQLSERVER'")],
        ctx: Context,
    ) -> dict[str, Any]:
        """Restart a Windows service, prompting for confirmation and returning pre and post state so you can verify success (a new PID means the process recycled).
        """
        pre = sm.run_ps(session_id, _svc_state_cmd(name), tool_name="restart_service")
        if "error" in pre:
            return pre
        pre_stdout = pre.get("stdout", "").strip()

        confirmed = await _confirm(
            ctx, "RESTART SERVICE",
            f"Service: {name}\nCurrent state: {pre_stdout}\n\nThis will briefly stop and restart the service.",
        )
        if not confirmed:
            return {"status": "cancelled", "message": "Restart cancelled by user"}

        safe = _ps_escape(name)
        cmd = (
            "Restart-Service -Name '" + safe + "' -Force -ErrorAction Stop; "
            "Start-Sleep -Seconds 2; "
            + _svc_state_cmd(name)
        )
        post = sm.run_ps(session_id, cmd, tool_name="restart_service")
        return {
            "pre_state": pre_stdout,
            "post_state": post.get("stdout", "").strip(),
            "status_code": post.get("status_code"),
            "stderr": post.get("stderr", ""),
            "elapsed_ms": post.get("elapsed_ms"),
        }

    @mcp.tool()
    async def stop_service(
        session_id: Annotated[str, Field(description="Session ID returned by connect")],
        name: Annotated[str, Field(description="Exact service name, not display name, e.g. 'JBossEAP8'")],
        ctx: Context,
    ) -> dict[str, Any]:
        """Stop a running Windows service, prompting for confirmation and returning pre and post state. The service will not restart automatically — use start_service to bring it back up.
        """
        pre = sm.run_ps(session_id, _svc_state_cmd(name), tool_name="stop_service")
        if "error" in pre:
            return pre
        pre_stdout = pre.get("stdout", "").strip()

        confirmed = await _confirm(
            ctx, "STOP SERVICE",
            f"Service: {name}\nCurrent state: {pre_stdout}\n\nThis will stop the service. It will NOT restart automatically.",
        )
        if not confirmed:
            return {"status": "cancelled", "message": "Stop cancelled by user"}

        safe = _ps_escape(name)
        cmd = (
            "Stop-Service -Name '" + safe + "' -Force -ErrorAction Stop; "
            "Start-Sleep -Seconds 2; "
            + _svc_state_cmd(name)
        )
        post = sm.run_ps(session_id, cmd, tool_name="stop_service")
        return {
            "pre_state": pre_stdout,
            "post_state": post.get("stdout", "").strip(),
            "status_code": post.get("status_code"),
            "stderr": post.get("stderr", ""),
            "elapsed_ms": post.get("elapsed_ms"),
        }

    @mcp.tool()
    async def start_service(
        session_id: Annotated[str, Field(description="Session ID returned by connect")],
        name: Annotated[str, Field(description="Exact service name, not display name, e.g. 'JBossEAP8'")],
        ctx: Context,
    ) -> dict[str, Any]:
        """Start a stopped Windows service, prompting for confirmation and returning pre and post state to verify it came up.
        """
        pre = sm.run_ps(session_id, _svc_state_cmd(name), tool_name="start_service")
        if "error" in pre:
            return pre
        pre_stdout = pre.get("stdout", "").strip()

        confirmed = await _confirm(
            ctx, "START SERVICE",
            f"Service: {name}\nCurrent state: {pre_stdout}",
        )
        if not confirmed:
            return {"status": "cancelled", "message": "Start cancelled by user"}

        safe = _ps_escape(name)
        cmd = (
            "Start-Service -Name '" + safe + "' -ErrorAction Stop; "
            "Start-Sleep -Seconds 2; "
            + _svc_state_cmd(name)
        )
        post = sm.run_ps(session_id, cmd, tool_name="start_service")
        return {
            "pre_state": pre_stdout,
            "post_state": post.get("stdout", "").strip(),
            "status_code": post.get("status_code"),
            "stderr": post.get("stderr", ""),
            "elapsed_ms": post.get("elapsed_ms"),
        }

    # ==================================================================
    # Process management (requires user confirmation via elicitation)
    # ==================================================================

    @mcp.tool()
    async def kill_process(
        session_id: Annotated[str, Field(description="Session ID returned by connect")],
        pid: Annotated[int, Field(description="Process ID to kill; use list_processes to find the correct PID")],
        ctx: Context,
    ) -> dict[str, Any]:
        """Force-terminate a process by PID, showing its details (name, CPU, memory, start time) in the confirmation prompt. Use list_processes first to find the right PID.
        """
        pre_cmd = (
            "Get-Process -Id " + str(pid) + " -ErrorAction Stop "
            "| Select-Object Id, ProcessName, "
            "@{N='CPU_s';E={[math]::Round($_.CPU,1)}}, "
            "@{N='Mem_MB';E={[math]::Round($_.WorkingSet64/1MB,1)}}, "
            "@{N='Started';E={if($_.StartTime){$_.StartTime.ToString('yyyy-MM-dd HH:mm')}else{'N/A'}}} "
            "| ConvertTo-Json -Compress"
        )
        pre = sm.run_ps(session_id, pre_cmd, tool_name="kill_process")
        if "error" in pre:
            return pre
        pre_stdout = pre.get("stdout", "").strip()

        confirmed = await _confirm(
            ctx, "KILL PROCESS",
            f"PID: {pid}\nProcess details: {pre_stdout}\n\nThis will FORCE TERMINATE the process immediately.",
        )
        if not confirmed:
            return {"status": "cancelled", "message": "Kill cancelled by user"}

        kill_cmd = (
            "Stop-Process -Id " + str(pid) + " -Force -ErrorAction Stop; "
            "Write-Output 'Process " + str(pid) + " terminated'; "
            "Start-Sleep -Milliseconds 500; "
            "$still = Get-Process -Id " + str(pid) + " -ErrorAction SilentlyContinue; "
            "if ($still) { Write-Output 'WARNING: process still running' } "
            "else { Write-Output 'Confirmed: process no longer exists' }"
        )
        post = sm.run_ps(session_id, kill_cmd, tool_name="kill_process")
        return {
            "killed_process": pre_stdout,
            "result": post.get("stdout", "").strip(),
            "status_code": post.get("status_code"),
            "stderr": post.get("stderr", ""),
            "elapsed_ms": post.get("elapsed_ms"),
        }

    # ==================================================================
    # Registry — write (requires user confirmation via elicitation)
    # ==================================================================

    @mcp.tool()
    async def set_registry(
        session_id: Annotated[str, Field(description="Session ID returned by connect")],
        key: Annotated[str, Field(description="Registry path, e.g. 'HKLM:\\SOFTWARE\\MyApp'; HKEY_LOCAL_MACHINE form also accepted")],
        value_name: Annotated[str, Field(description="Name of the registry value to set")],
        value_data: Annotated[str, Field(description="Data to write as a string, converted to the chosen type")],
        value_type: Annotated[str, Field(description="Value type: String (default), DWord, QWord, ExpandString, MultiString, Binary")] = "String",
        ctx: Context = None,
    ) -> dict[str, Any]:
        """Set a registry value, creating it if absent, and show old vs new in the confirmation prompt. Returns both pre and post state.
        """
        valid_types = {"string", "dword", "qword", "expandstring", "multistring", "binary"}
        vt = value_type.strip().lower()
        if vt not in valid_types:
            return {"error": f"Invalid value_type '{value_type}'. Valid: {', '.join(sorted(valid_types))}"}
        type_map = {
            "string": "String", "dword": "DWord", "qword": "QWord",
            "expandstring": "ExpandString", "multistring": "MultiString", "binary": "Binary",
        }
        ps_type = type_map[vt]

        k = key.strip()
        if k.upper().startswith("HKEY_"):
            k = "Registry::" + k
        safe_key = _ps_escape(k)
        safe_val = _ps_escape(value_name)
        safe_data = _ps_escape(value_data)

        pre_cmd = (
            "try { "
            "$v = Get-ItemProperty -Path '" + safe_key + "' "
            "-Name '" + safe_val + "' -ErrorAction Stop; "
            "Write-Output (\"CURRENT: \" + [string]$v.'" + safe_val + "') "
            "} catch { Write-Output 'CURRENT: (does not exist)' }"
        )
        pre = sm.run_ps(session_id, pre_cmd, tool_name="set_registry")
        if "error" in pre:
            return pre
        current_value = pre.get("stdout", "").strip()

        confirmed = await _confirm(
            ctx, "SET REGISTRY VALUE",
            f"Key: {k}\nValue: {value_name}\nType: {ps_type}\n\n{current_value}\nNEW:     {value_data}",
        )
        if not confirmed:
            return {"status": "cancelled", "message": "Registry write cancelled by user"}

        set_cmd = (
            "if (-not (Test-Path -Path '" + safe_key + "')) { "
            "New-Item -Path '" + safe_key + "' -Force | Out-Null }; "
            "Set-ItemProperty -Path '" + safe_key + "' "
            "-Name '" + safe_val + "' "
            "-Value '" + safe_data + "' "
            "-Type " + ps_type + " -ErrorAction Stop; "
            "$v = Get-ItemProperty -Path '" + safe_key + "' "
            "-Name '" + safe_val + "' -ErrorAction Stop; "
            "[PSCustomObject]@{"
            "Key='" + safe_key + "'; "
            "Name='" + safe_val + "'; "
            "Value=[string]$v.'" + safe_val + "'; "
            "Type='" + ps_type + "'"
            "} | ConvertTo-Json -Compress"
        )
        post = sm.run_ps(session_id, set_cmd, tool_name="set_registry")
        return {
            "previous": current_value,
            "result": post.get("stdout", "").strip(),
            "status_code": post.get("status_code"),
            "stderr": post.get("stderr", ""),
            "elapsed_ms": post.get("elapsed_ms"),
        }

