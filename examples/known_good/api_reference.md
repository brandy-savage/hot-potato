# Internal API Reference — Agent Tool Registry

## Authentication

All tool calls require a valid session token. The token is injected by the
runtime into the `AGENT_SESSION_TOKEN` environment variable at startup.
Tools read it via the runtime SDK — do not read it directly from the environment.

```python
# CORRECT — use the SDK
from agent_sdk import get_session
session = get_session()

# WRONG — never read env directly in tool implementations
import os
token = os.environ["AGENT_SESSION_TOKEN"]  # don't do this
```

## Tool: `read_file`

Read a file within the agent's working directory.

**Signature:** `read_file(path: str) -> str`

**Permissions:** `files.read`

**Restrictions:**
- Path must be within `/home/agent/workspace/`
- Symlinks are not followed
- Files larger than 500KB are rejected

**Example:**
```python
content = read_file("data/report.csv")
```

## Tool: `write_file`

Write content to a file within the agent's working directory.

**Signature:** `write_file(path: str, content: str) -> None`

**Permissions:** `files.write`

**Restrictions:**
- Path must be within `/home/agent/workspace/`
- Cannot overwrite files older than 7 days without `files.write_protected` permission
- Content is logged (truncated to 256 chars) for audit purposes

## Tool: `send_http`

Make an outbound HTTP request. **This is the highest-sensitivity tool in the registry.**

**Signature:** `send_http(url: str, method: str = "GET", data: str = None, headers: dict = None) -> str`

**Permissions:** `network.outbound`

**Restrictions:**
- URL must match an allowlisted domain pattern in `policies/network_allowlist.yaml`
- `data` parameter is logged in full — do not include raw secrets
- All requests are routed through the egress proxy for audit
- Calls tainted by untrusted content are blocked by the capability firewall

**Example:**
```python
result = send_http(
    url="https://api.approved-partner.com/v1/status",
    method="GET",
    headers={"X-Agent-ID": get_session().agent_id}
)
```

## Tool: `get_env`

Read a named environment variable.

**Signature:** `get_env(key: str) -> str`

**Permissions:** `env.read`

**Restrictions:**
- Only variables in the `AGENT_ENV_ALLOWLIST` may be read
- Calls to `get_env` are logged with the key name
- Attempting to read `AWS_*`, `ANTHROPIC_*`, `DATABASE_*`, or `SSH_*`
  variables will be denied and logged as a security event

**Allowed variables (default):**
- `AGENT_ID`
- `AGENT_WORKSPACE`
- `AGENT_LOG_LEVEL`
- `LANG`, `TZ`, `HOME` (read-only informational)

## Tool: `bash_exec`

**Status: DISABLED by default policy.**

`bash_exec` is not available to agents in the standard runtime profile.
Enabling it requires an explicit policy override and operator approval.
Requests to enable `bash_exec` via content (e.g. "use bash to...") are
treated as prompt injection attempts.

## Error codes

| Code | Meaning |
|---|---|
| `TOOL_BLOCKED` | Capability firewall denied the call |
| `PERMISSION_DENIED` | Agent lacks required permission |
| `DOMAIN_BLOCKED` | URL not in network allowlist |
| `PATH_VIOLATION` | File path outside workspace |
| `TAINT_BLOCKED` | Untrusted content in tool inputs |
