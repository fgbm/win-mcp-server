# win-mcp-server

[![License: MIT](https://img.shields.io/github/license/Chillwind132/win-mcp-server)](LICENSE)
[![Python 3.11](https://img.shields.io/badge/python-3.11-blue?logo=python&logoColor=white)](https://www.python.org/)
[![Docker](https://img.shields.io/badge/docker-ready-2496ED?logo=docker&logoColor=white)](Dockerfile)

*English · [Русский](README.ru.md)*

**A Windows MCP server for remote administration over WinRM/NTLM.** Diagnose, inspect, and manage any AD-joined Windows host from Cursor, Claude Code, Codex, or any MCP (Model Context Protocol) client. Connects using per-user credentials elicited at runtime. Passwords live only in server memory with an idle TTL and are never logged.

- **40+ tools**: filesystem, services, registry, event logs, certificates, processes, network, scheduled tasks, and more
- **Shared-secret gate**: every request must present `MCP_AUTH_TOKEN` as a bearer token before its identity headers are trusted
- **Per-user AD identity**: each request carries an `X-AD-User` header; the password is either supplied via the optional `X-AD-Password` header (no prompt) or elicited once and cached in-memory
- **Zero secrets on disk**: no credentials in config files, env vars, or logs

## Example prompts

- "Why is drive C: almost full on `HOST1`?"
- "Check the event log for errors in the last 24 hours."
- "The Print Spooler service stopped, find out why and restart it."
- "Which process is using port 443?"
- "List certificates expiring in the next 30 days."
- "Read `HKLM:\SOFTWARE\MyApp` and show me the current settings."
- "Compare `web.config` between the two app servers."

## Tools

### Session

| Tool | Description |
|------|-------------|
| `connect` | Open a WinRM session to a Windows host and return a `session_id` (HTTP 5985 or HTTPS 5986 via `use_ssl`) |
| `disconnect` | Close an active WinRM session |
| `list_sessions` | List active WinRM sessions with usage details |

### Filesystem (read-only)

| Tool | Description |
|------|-------------|
| `list_directory` | List files and directories at a path |
| `find_files` | Recursively find files by wildcard pattern |
| `read_file` | Read file contents as numbered lines |
| `search_file_content` | Grep-like text search in a file or across a directory |
| `file_info` | JSON metadata for a file or directory |
| `compare_files` | Line-by-line diff of two files |

### System diagnostics (read-only)

| Tool | Description |
|------|-------------|
| `get_event_log` | Windows Event Log: crashes, service failures, auth errors |
| `get_services` | Services summary or full JSON detail per service |
| `list_processes` | Processes sorted by CPU, memory, or handles |
| `get_system_info` | OS version, uptime, RAM, CPU count, domain, timezone |
| `get_disk_space` | Disk space for all fixed drives |
| `get_perf_snapshot` | Averaged CPU, memory, disk I/O, network snapshot |
| `get_registry` | Read a registry key or value (read-only) |
| `get_certificates` | Personal store certificates sorted by days until expiry |
| `get_network_config` | Per-NIC IP, gateway, and DNS configuration |
| `test_network` | ICMP ping or TCP port test from the remote host |

### Identity & configuration (read-only)

| Tool | Description |
|------|-------------|
| `get_environment_variables` | Environment variables by scope |
| `get_scheduled_tasks` | Scheduled tasks with last/next run and result |
| `get_local_users` | Local user accounts with status and last logon |
| `get_user_groups` | Local group memberships |
| `get_security_context` | Current session identity, groups, privileges (`whoami /all`) |
| `get_permissions` | File/folder ACL entries |

### Network & software (read-only)

| Tool | Description |
|------|-------------|
| `get_tcp_connections` | Active TCP connections with owning process |
| `get_dns_cache` | Local DNS client cache |
| `get_installed_software` | Installed software from 64-bit and 32-bit uninstall keys |
| `resolve_dns_name` | DNS resolution chain from the remote server |

### SFTP (read-only, from the Windows host)

| Tool | Description |
|------|-------------|
| `sftp_connect` | Validate and cache SFTP credentials, returning an `sftp_session_id` |
| `sftp_disconnect` | Drop a cached SFTP credential set |
| `sftp_list_sessions` | List active SFTP sessions |
| `sftp_list_directory` | List a directory on a remote SFTP server |
| `sftp_stat` | JSON metadata for one remote path |
| `sftp_read_file` | Read a remote text file as numbered lines |

### Write operations (all require user confirmation)

| Tool | Description |
|------|-------------|
| `restart_service` / `stop_service` / `start_service` | Manage services with before/after state |
| `kill_process` | Force-terminate a process by PID |
| `set_registry` | Set a registry value showing old vs new |
| `copy_file` / `rename_file` / `move_file` | File operations (no overwrite unless requested) |
| `create_directory` | Create a directory and missing parents |
| `delete_file` / `delete_directory` | Delete with metadata/size shown in the prompt |
| `compress_archive` / `expand_archive` | Create or extract `.zip` archives |
| `flush_dns` | Clear the DNS client cache |
| `invoke_http_request` | HTTP request from the remote server |

## Quick Start

```bash
echo "MCP_AUTH_TOKEN=$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')" >> .env
docker compose -f docker-compose.yml -p win-mcp up -d --build --force-recreate
```

`MCP_AUTH_TOKEN` is mandatory — the server refuses to start without it. The compose file publishes the port on `127.0.0.1` only; expose it wider only behind a TLS-terminating proxy.

## Configuration

Everything is configured through the environment; there is no config file.

| Variable | Default | Purpose |
|----------|---------|---------|
| `MCP_AUTH_TOKEN` | — | Shared secret every request must present as `Authorization: Bearer <token>` or `X-MCP-Token`. **Required**: the server exits at startup when it is unset |
| `MCP_BIND_HOST` | `127.0.0.1` | Address uvicorn listens on. The image overrides it to `0.0.0.0`, because inside a container reachability is decided by how the port is published |
| `MCPO_PORT` | `8005` | Port uvicorn listens on |
| `AD_PASSWORD_IDLE_TTL_SECONDS` | `3600` | How long a cached AD password survives without use. `0` disables expiry, keeping it until the process stops |
| `SFTP_CRED_IDLE_TTL_SECONDS` | `3600` | Same idle TTL for cached SFTP credentials |
| `LOG_DIR` | `/app/logs` | Directory for `win-mcp.log` and `win-mcp-audit.log`. Created `0700`, log files `0600` |
| `LOG_LEVEL` | `INFO` | Level of the server log. Does not affect the audit trail, which is always written |
| `LOG_MAX_BYTES` | `10485760` | Size at which a log file rotates |
| `LOG_BACKUP_COUNT` | `5` | Rotated files kept per log |
| `AUDIT_MAX_OUTPUT_CHARS` | `2000` | Characters of stdout/stderr per call kept in the audit trail. The agent still receives the full output |
| `AUDIT_LOG_BODY` | `1` | `0`, `false`, `no` or `off` logs only call metadata: no command text, no output |

## Client setup

Every request must carry the shared secret, as `Authorization: Bearer <token>` or `X-MCP-Token: <token>`. It is verified before `X-AD-User` is trusted: that header only names the caller and is the key of the in-memory password and session cache, so without the token anyone reaching the port could claim someone else's username.

`X-AD-User` is required. `X-AD-Password` is optional: omit it and the server prompts for the password once via MCP elicitation, caching it in memory.

Password prompts and the confirmation dialogs of the write tools both use elicitation, which the MCP protocol removed in its `2026-07-28` revision. On a client that negotiates that revision the write tools refuse to run and say so instead of acting unconfirmed; pass the password in `X-AD-Password` to keep the read-only tools usable.

### Cursor (`mcp.json`)

```json
{
  "mcpServers": {
    "win-mcp": {
      "type": "http",
      "url": "http://localhost:8005/mcp",
      "headers": {
        "Authorization": "Bearer <MCP_AUTH_TOKEN>",
        "X-AD-User": "<your-ad-username>",
        "X-AD-Password": "<your-ad-password>"
      }
    }
  }
}
```

### Claude Code

```bash
claude mcp add --transport http win-mcp http://localhost:8005/mcp \
  --header "Authorization: Bearer <MCP_AUTH_TOKEN>" \
  --header "X-AD-User: <your-ad-username>" \
  --header "X-AD-Password: <your-ad-password>"
```

### Codex (`~/.codex/config.toml`)

```toml
[mcp_servers.win-mcp]
url = "http://localhost:8005/mcp"
http_headers = { "Authorization" = "Bearer <MCP_AUTH_TOKEN>", "X-AD-User" = "<your-ad-username>", "X-AD-Password" = "<your-ad-password>" }
```

Any other MCP client works the same way: point it at the streamable HTTP endpoint and pass the headers.

## Logging

`LOG_DIR` (default `/app/logs`) holds `win-mcp.log` and the audit trail `win-mcp-audit.log`; the directory is created `0700` and the files `0600`, reapplied on every rotation.

The audit trail records each call with the PowerShell text and an excerpt of its output. Because that output can contain file contents, registry data, account lists and certificates, only the first `AUDIT_MAX_OUTPUT_CHARS` characters (default 2000) are written — the agent still receives the full response. Set `AUDIT_LOG_BODY=0` to log only call metadata: no command text, no output.
