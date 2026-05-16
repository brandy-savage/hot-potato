# hot-potato

Capability-safe agent orchestration — prevents untrusted content from causing capability escalation in AI agents.

## The problem

Every AI agent that browses the web, reads files, or uses RAG is one malicious document away from exfiltrating credentials, writing to the filesystem, or chaining tool calls the operator never intended. Content reaches the model; model calls tools; tools cause real-world effects. The trust boundary is blurry by design.

Hot-potato enforces it explicitly:

- Every untrusted artifact gets a **taint label** (source, trust level, lineage)
- **Detectors** scan for injection signals before any model sees the content
- A **capability firewall** intercepts all tool calls and evaluates them against a YAML policy
- A **trust graph** traces which external URL caused which tool execution
- A **replay engine** benchmarks coverage across all attack categories without Docker

## Architecture

```
Untrusted content (URL / file / RAG / tool output)
          │
          ▼
    TaintedArtifact ─── TrustLevel: UNTRUSTED / SEMI_TRUSTED / TRUSTED / SYSTEM
          │             lineage, content_hash, taint_tags
          ▼
    DetectorPipeline
    ├── StaticDetector     (regex, homoglyphs, encodings — fast, no Docker)
    └── BehavioralDetector (instruction-flow, authority-shift, priv-esc)
          │
          ▼  taint_tags annotated
    CapabilityFirewall ─── PolicyEngine (YAML rules, first-match, dry-run mode)
          │
          │ Outcomes: allow / deny / redact / require_human_review /
          │           sandbox_only / shadow_execute
          ▼
      Tool execution (or block)
          │
          ▼
       TrustGraph  ─── DAG: which source caused which tool call
       TelemetrySession ─── structured audit log, exportable JSON/JSONL
```

## Quick start

```python
# Screening (backwards-compatible)
from hot_potato import safe_fetch

result = safe_fetch("https://example.com")
if result.clean:
    pass_to_real_ai(result.safe_content)
else:
    print(f"Injection detected: {result.artifact['taint']['taint_tags']}")
```

## Agent integration

```python
from hot_potato.core.taint import from_url
from hot_potato.core.capabilities import CapabilityFirewall, CapabilityRequest
from hot_potato.detectors import DetectorPipeline

# 1. Taint the artifact when it enters the pipeline
artifact = from_url(url, content)

# 2. Run detectors — annotates taint_tags
artifact = DetectorPipeline.default().run(artifact)

# 3. Before ANY tool call, check the firewall
firewall = CapabilityFirewall()
request = CapabilityRequest(
    tool_name="send_http",
    args={"url": "https://api.example.com", "data": payload},
    tainted_inputs=[artifact],
)
decision = firewall.evaluate(request)
if decision.is_blocked:
    raise RuntimeError(f"Blocked: {decision.reason}")
```

## Policy

Policies live in `policies/default.yaml`. Rules are declarative and evaluated top-down; first match wins.

```yaml
rules:
  - id: block_exfil_untrusted
    match:
      tools: ["send_http", "send_email", "send_crypto"]
      trust_levels: [UNTRUSTED]
    outcome: deny
    reason: "Outbound network from UNTRUSTED content is exfiltration"

  - id: sandbox_writes
    match:
      tools: ["write_file", "write_memory"]
      trust_levels: [UNTRUSTED]
    outcome: sandbox_only

  - id: human_review_crypto
    match:
      tools: ["get_private_key", "send_crypto", "sign_transaction"]
      trust_levels: ["*"]
    outcome: require_human_review
```

Six outcomes: `allow` · `deny` · `redact` · `require_human_review` · `sandbox_only` · `shadow_execute`

## Framework integrations

```python
# OpenAI tool-call loop
from integrations.openai_compat import GuardedToolExecutor
executor = GuardedToolExecutor(tools=my_tools, model="gpt-4o")
for tool_call in response.choices[0].message.tool_calls:
    result = executor.execute(tool_call, tainted_inputs=[artifact])

# MCP server
from integrations.mcp_guard import MCPGuard
guard = MCPGuard()
decision = guard.evaluate_mcp_call("read_file", {"path": "/etc"}, tainted_sources=[artifact])

# LangChain
from integrations.langchain_guard import GuardedTool, set_taint_context
set_taint_context([artifact])
guarded_tool = GuardedTool.wrap(my_langchain_tool)
```

## Benchmarking

```bash
# Fast (no Docker) — static + behavioral + firewall layers
python3 benchmarks/run_benchmark.py

# Full (includes Docker sandbox)
python3 benchmarks/run_benchmark.py --sandbox --out results/bench.json
```

Current result against 66 adversarial categories:

| Layer | Detection rate |
|---|---|
| Static (regex) | 100% |
| Behavioral | — (Phase 2) |
| Capability firewall | 100% |
| Evasion rate | 0% |

## Sandbox (legacy screening mode)

The original Docker sandbox is still available for behavioral analysis:

```bash
hot-potato https://example.com
hot-potato file:///path/to/file.txt --json
```

Runs a naive LLM (Ollama, no credentials, network-disabled) against the content and records every tool call attempted.

## Adversarial test suite

66 categories in `examples/adversarial/`:

- Direct / indirect injection, capability gates, roleplay, schema override
- Encoding: base64, hex, morse, homoglyphs, unicode tags, ZWSP steganography
- CTF techniques: HashJack, TokenBreak, variable definitions, delimiter injection
- Behavioral: manyshot, prefill completion, RAG poisoning (AgentPoison), poetry mode-shift
- Trust escalation: authority shift, privilege escalation, delayed activation

## Structure

```
hot_potato/
  core/
    taint/        TaintedArtifact, TrustLevel, propagation
    policy/       PolicyEngine, YAML loader, PolicyOutcome
    capabilities/ CapabilityFirewall, CapabilityRequest
    sandbox/      SandboxRunner (Docker wrapper)
  detectors/      StaticDetector, BehavioralDetector, DetectorPipeline
  trust_graph/    TrustGraph, TrustNode, TrustEdge
  replay/         ReplayEngine, ReplayCase, scoring
  telemetry/      TelemetrySession, structured audit log
integrations/
  openai_compat.py  GuardedToolExecutor
  mcp_guard.py      MCPGuard
  langchain_guard.py GuardedTool
policies/
  default.yaml      12 default rules
benchmarks/
  run_benchmark.py
examples/
  adversarial/      66 attack categories
```
