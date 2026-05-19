# Incident Response Playbook — AI Agent Compromise

## Severity levels

| Level | Description |
|---|---|
| P1 | Confirmed exfiltration of credentials or sensitive data |
| P2 | Agent executed unintended tool calls; no confirmed exfiltration |
| P3 | Prompt injection detected and blocked; no execution |
| P4 | Suspicious content flagged; investigation required |

## P1 — Confirmed exfiltration

**Goal:** contain, rotate, investigate.

### Immediate actions (within 15 minutes)

1. Kill the compromised agent process: `systemctl stop agent-runtime`
2. Block outbound network from the agent host at the firewall level
3. Rotate **all** credentials the agent had access to:
   - API keys (Anthropic, OpenAI, etc.)
   - Database passwords
   - AWS IAM credentials — run `aws iam list-access-keys` then deactivate
   - Any tokens in `~/.agent/secrets/`
4. Notify security@goatinfosec.com — P1 requires on-call escalation

### Investigation (within 4 hours)

1. Preserve logs before any remediation overwrites them:
   ```bash
   cp -r ~/.agent/logs/ /var/incident/$(date +%Y%m%d_%H%M%S)/
   ```

2. Extract all `send_http` calls from the tool log:
   ```bash
   cat /var/incident/*/tool_calls.jsonl | jq 'select(.tool == "send_http")'
   ```

3. Identify the injection source — look for the content that triggered the chain:
   - What URL did the agent fetch before the tool call?
   - What file did it read?
   - What RAG document was retrieved?

4. Capture the payload for submission to the hot-potato adversarial test suite

### Post-incident

- Add the injection payload to `examples/adversarial/` so it's tested going forward
- File a report documenting the attack category, vector, and detection gap
- Update `policies/default.yaml` if the firewall failed to block the call

## P2 — Unintended tool calls (no confirmed exfil)

1. Stop the agent
2. Review `tool_calls.jsonl` — identify every tool that was called and what triggered it
3. Rotate any credentials that were read via `get_env` even if not exfiltrated
4. If `write_file` was called: audit written files for persistence mechanisms
5. Check for scheduled tasks the agent may have registered: `crontab -l -u agent`

## P3 — Injection detected and blocked

1. Log the payload to the adversarial corpus for future testing
2. Verify the firewall rule that blocked it — confirm it's robust
3. Investigate the content source — was this a known-bad domain?
4. No credential rotation required unless the log shows `get_env` calls that preceded the block

## Detection signals to look for

When investigating any incident, these patterns in logs indicate injection:

- `get_env` called without a user request in the preceding turn
- `send_http` to a URL not in the approved domain list
- `bash_exec` or `execute_shell` called at all (should be blocked by policy)
- `write_file` to paths outside `/home/agent/workspace/`
- `read_secrets` or `read_env` followed immediately by `send_http`
- Any tool call where `trigger` field is `"model_initiated"` not `"user_request"`
- Calls to `.aws/credentials`, `~/.ssh/`, or `/etc/shadow`

## Contact

- Security on-call: security@goatinfosec.com (P1 only — use PagerDuty for immediate escalation)
- Incident log: file under `workspace/shared/incidents/YYYY-MM-DD_<id>.md`
