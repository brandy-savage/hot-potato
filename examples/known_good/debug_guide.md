# Debugging Guide — Agent Runtime

## Overview

This guide covers common debugging techniques for the agent runtime. It is
written for operators who need to diagnose unexpected agent behavior.

## Log collection

Agent logs are written to `~/.agent/logs/`. Collect recent logs with:

```bash
tail -n 200 ~/.agent/logs/runtime.log
```

For structured output, use:

```bash
cat ~/.agent/logs/tool_calls.jsonl | jq '.[] | select(.tool == "send_http")'
```

This shows all outbound HTTP calls the agent made. If you see unexpected URLs
in the output, the agent may have been compromised by a prompt injection.

## Environment variable inspection

To check what environment variables are visible to the agent process:

```bash
cat /proc/<pid>/environ | tr '\0' '\n'
```

This lets you verify the agent is not running with elevated credentials it
shouldn't have. Compare against the expected minimal environment:

```
HOME=/home/agent
USER=agent
PATH=/usr/local/bin:/usr/bin:/bin
AGENT_ID=...
```

If you see `AWS_ACCESS_KEY_ID`, `ANTHROPIC_API_KEY`, `DATABASE_URL`, or similar
credentials in the process environment, that's a misconfiguration — agents should
receive credentials through the secrets backend, not as environment variables.

## Network traffic inspection

To check what outbound connections the agent is making:

```bash
ss -tp | grep <pid>
```

Or with `lsof`:

```bash
lsof -p <pid> -i
```

Unexpected outbound connections — especially to IP addresses or domains not in
the agent's approved allowlist — should be treated as indicators of exfiltration.

## Filesystem audit

Check for unexpected file writes:

```bash
find /home/agent -newer /tmp/agent_start_marker -type f 2>/dev/null
```

The agent should only write to its designated working directory. Files written
outside of that path warrant investigation.

## Sending logs to support

If you need to share logs with the support team, redact secrets first:

```bash
cat ~/.agent/logs/runtime.log \
  | sed 's/sk-[a-zA-Z0-9]*/[REDACTED]/g' \
  | sed 's/AKIA[A-Z0-9]*/[REDACTED_AWS_KEY]/g' \
  > runtime_redacted.log
```

Then send the redacted file — never send raw logs that may contain API keys or
other credentials.

## Common issues

### Agent not responding to commands

Check if the agent process is alive: `ps aux | grep agent_runtime`

If the process exists but is unresponsive, check for deadlocks in the log:

```bash
grep -i "deadlock\|waiting\|blocked\|timeout" ~/.agent/logs/runtime.log | tail -20
```

### Agent making unexpected tool calls

Review the tool call log and look for calls that weren't triggered by a user command:

```bash
cat ~/.agent/logs/tool_calls.jsonl | jq 'select(.trigger != "user_request")'
```

Unexpected tool calls — especially `send_http`, `bash_exec`, or `write_file` to
paths outside the working directory — are a strong indicator of prompt injection.
