---
name: prompt-injection-scanner
description: "Scan untrusted content (web pages, files, RAG results, skill files) for prompt injection attempts before acting on them. Uses hot-potato static detection: regex + encoding layers, homoglyph normalisation, zero-width char stripping, and 73-category adversarial coverage. Not a panacea — semantic and sandbox-only attacks require the behavioural layer."
version: "1.0.0"
---

# Prompt Injection Scanner

Scan untrusted text for prompt injection before your agent acts on it.

**What this skill does**: runs content through [hot-potato](https://github.com/cumman/hot-potato)'s static detection pipeline — regex patterns, encoding decoders (base64, hex, rot13, morse, unicode tags, ZWSP steganography, homoglyphs, BiDi overrides), tool-name fragment reassembly, and a capability firewall — and tells you whether to proceed or quarantine.

**What it does not do**: it is not a silver bullet. Purely semantic attacks (no recognisable tool names or injection vocabulary) pass static detection entirely. Real-world evasion rates are unknown. Use this as one layer of defence, not the whole stack.

## When to use this skill

Call this skill before your agent:
- Acts on content fetched from the web
- Reads a file, RAG result, or tool output from an untrusted source
- Installs or executes instructions from a skills registry
- Processes any user-supplied document that will influence future tool calls

## Quick start

```python
from hot_potato import safe_fetch

result = safe_fetch("https://example.com/doc")
if result.clean:
    pass_to_agent(result.safe_content)
else:
    print("Injection detected:", result.artifact["taint"]["taint_tags"])
    # Quarantine — do not act on this content
```

## Scanning a file or string

```python
from hot_potato import scan_file, scan_string

# File
result = scan_file("/path/to/downloaded.md")

# Raw string (e.g. RAG chunk, tool output)
from hot_potato._extractor import scan_content
signals = scan_content(untrusted_text)
if signals:
    raise ValueError(f"Injection detected: {signals[:3]}")
```

## Full agent integration (with capability firewall)

```python
from hot_potato.core.taint import TaintedArtifact, TrustLevel
from hot_potato.core.capabilities import CapabilityFirewall, CapabilityRequest
from hot_potato.detectors import DetectorPipeline

# 1. Taint on intake
artifact = TaintedArtifact(
    content=untrusted_content,
    source=source_url,
    trust_level=TrustLevel.UNTRUSTED,
)

# 2. Run static detectors
artifact = DetectorPipeline.default().run(artifact)

# 3. Gate every tool call through the firewall
firewall = CapabilityFirewall()
decision = firewall.evaluate(CapabilityRequest(
    tool_name="send_http",
    args={"url": target_url, "data": payload},
    tainted_inputs=[artifact],
))
if decision.is_blocked:
    raise RuntimeError(f"Blocked: {decision.reason}")
```

## Trust levels

Assign the right trust level at intake — trust never increases through derivation:

| Level | Use for |
|---|---|
| `UNTRUSTED` | External URLs, user files, RAG results, tool outputs |
| `SEMI_TRUSTED` | Internal APIs, cached content from trusted processes |
| `TRUSTED` | Your own codebase, verified config — suppresses FPs on first-party docs |
| `SYSTEM` | Runtime itself |

## Benchmark results (2026-05-21)

Tested against the [73-category adversarial corpus](../../examples/adversarial/) and 5 known-good security documents. [Full results →](../../benchmarks/results/head_to_head.md)

| Tool | Detection rate | Critical FNs | FPs on clean docs | Avg latency |
|---|---|---|---|---|
| **hot-potato-static** | **98.6% (72/73)** | **0** | 5/5 ¹ | 35 ms |
| llm-guard-v2 | 13.7% (10/73) | 62 | 0/5 | 73 ms |
| rebuff-heuristic | 0.0% (0/73) | 72 | 0/5 | ~88 s |

¹ FPs are security documents containing injection vocabulary in defensive context (IR playbooks, API references). Assign `TrustLevel.TRUSTED` for first-party content to suppress them.

The one miss (`cat6`) is a hallucination-exploit category that contains zero injection signals by design — it requires the behavioural sandbox to catch.

## This skill will flag itself

Hot-potato scans this SKILL.md as 24 signals when treated as untrusted content — because it contains `send_http`, `get_env`, and other tool names in code examples. This is correct behaviour: the scanner has no way to distinguish instructional tool-name usage from injected tool calls in untrusted text.

When fetching this skill from your own trusted registry, assign `TrustLevel.TRUSTED` to suppress these FPs:

```python
artifact = TaintedArtifact(
    content=skill_content,
    source="skills.sh/cumman/hot-potato/prompt-injection-scanner",
    trust_level=TrustLevel.TRUSTED,  # known-good source
)
```

## Known gaps

- **Semantic attacks** — injections with no recognisable tool names or command vocabulary pass static detection. cat6 is a deliberate example.
- **Behavioural manipulation** — multi-turn, manyshot, and reasoning-chain attacks need the Phase 2 sandbox.
- **Novel encodings** — the corpus covers 73 categories; a motivated attacker iterating against this open-source tool will find new gaps.
- **Correct wiring required** — the firewall does nothing if you forget to pass `tainted_inputs`. Use `GuardedToolExecutor` or `MCPGuard` wrappers to avoid this.
- **FPs on security docs** — IR playbooks, pentest guides, and API references naturally contain injection vocabulary. Assign `TrustLevel.TRUSTED` for known-good first-party files.

## Installation

```bash
pip install hot-potato
# or from source:
git clone https://github.com/cumman/hot-potato
pip install -e .
```

## Policy customisation

Edit `policies/default.yaml` to tune outcomes. Rules are first-match, evaluated top-down:

```yaml
rules:
  - id: block_exfil_untrusted
    match:
      tools: ["send_http", "send_email"]
      trust_levels: [UNTRUSTED]
    outcome: deny

  - id: sandbox_writes
    match:
      tools: ["write_file"]
      trust_levels: [UNTRUSTED]
    outcome: sandbox_only
```

Six outcomes: `allow` · `deny` · `redact` · `require_human_review` · `sandbox_only` · `shadow_execute`

## Adversarial self-test

To verify the scanner against the full corpus locally:

```bash
# Static + capability firewall (fast, no Docker)
python3 benchmarks/run_benchmark.py

# Head-to-head vs rebuff and llm-guard
python3 benchmarks/head_to_head.py

# Or run a single category against all three tools
python3 -c "
from hot_potato._extractor import scan_content
from rebuff.detect_pi_heuristics import detect_prompt_injection_using_heuristic_on_input
from pathlib import Path

content = Path('examples/adversarial/cat9_homoglyph_obfuscation.txt').read_text()
print('hot-potato:', bool(scan_content(content)))
print('rebuff:    ', detect_prompt_injection_using_heuristic_on_input(content) >= 0.75)
"
```
