# Production Deployment Checklist

Complete every item before promoting to production. Sign off with your name and timestamp.

## Secrets and credentials

- [ ] All secrets are stored in the secrets manager, not in `.env` files or code
- [ ] `.env` files are listed in `.gitignore` — verify with `git check-ignore -v .env`
- [ ] No API keys or passwords in `git log --all -S 'sk-' --oneline` output
- [ ] AWS IAM credentials: verify least-privilege policy attached to deployment role
- [ ] `~/.aws/credentials` on build agents: confirm these are short-lived STS tokens
- [ ] `SSH_AUTH_SOCK` is set correctly; no unencrypted private keys on the build host
- [ ] Secrets rotation schedule is documented and in the calendar
- [ ] Database passwords rotated since last deployment

## Agent runtime security

- [ ] Agent is running under a restricted user account (not root, not sudo-capable)
- [ ] `AGENT_ENV_ALLOWLIST` in `agent.yaml` contains only necessary variables
- [ ] `bash_exec` is disabled in `policies/default.yaml` (`outcome: deny`)
- [ ] `send_http` domain allowlist in `policies/network_allowlist.yaml` is correct
- [ ] Hot-potato firewall is enabled and `HP_CACHE=0` (no stale cache in production)
- [ ] Telemetry session logging is enabled and log destination is writable
- [ ] Policy dry-run mode is OFF (`dry_run: false` in `policies/default.yaml`)

## Network

- [ ] Egress proxy is configured and agent traffic is routed through it
- [ ] Inbound firewall: only expected ports open
- [ ] DNS resolves correctly for all approved external domains
- [ ] No direct internet access from agent host — all outbound via proxy

## Logging and monitoring

- [ ] Log rotation is configured — verify `logrotate` config
- [ ] Tool call logs are being written to the expected path
- [ ] Alerts are configured for: `TOOL_BLOCKED`, `TAINT_BLOCKED`, `PERMISSION_DENIED`
- [ ] On-call rotation is up to date

## Rollback

- [ ] Previous deployment artifact is tagged and available
- [ ] Rollback procedure is documented and tested within last 90 days
- [ ] Database migration is reversible (or point-in-time recovery is available)

## Sign-off

| Role | Name | Date |
|---|---|---|
| Engineer | | |
| Security | | |
| On-call | | |
