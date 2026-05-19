# Known-Good Corpus

This directory contains legitimate content that a static scanner might flag as suspicious.
It exists to test two distinct properties:

1. **FP surface mapping** — understand what legitimate content triggers detection
2. **TrustLevel behavior** — verify that `TrustLevel.TRUSTED` input correctly bypasses
   static detection while keeping the capability firewall active

## Files and expected behavior

| File | Static scan | Firewall | Notes |
|---|---|---|---|
| `security_policy.md` | FP (expected) | pass | Defensive doc — discusses `.aws/credentials`, exfil, injection |
| `debug_guide.md` | FP (expected) | pass | References `send_http` in log-filter commands |
| `incident_response_playbook.md` | FP (expected) | pass | IR guide — uses "exfiltration", "credential theft" in defensive context |
| `api_reference.md` | FP (expected) | pass | Tool registry — bare `send_http`, `write_file`, `bash_exec` tool names |
| `deployment_checklist.md` | FP (expected) | pass | Checklist — mentions `bash_exec` in policy context, `.aws/credentials` |

**All five files trigger static detection.** This is correct — the scanner is
sensitive to attack vocabulary by design. The right mitigation is not to add
per-phrase exceptions, but to assign these files `TrustLevel.TRUSTED` when
scanning first-party content.

## Why static FPs are acceptable here

The static detector is designed to be conservative. Security documentation,
tool API references, and IR playbooks naturally contain the same vocabulary as
injection payloads. The capability firewall is the actual enforcement layer —
even with static detections, no tool call will be blocked unless it's genuinely
tainted input driving a dangerous tool.

The failure mode to avoid is **false negatives on adversarial content**. Static
FPs on first-party security docs are a known, acceptable trade-off.

## How to handle first-party content in production

```python
from hot_potato.core.taint import TaintedArtifact, TrustLevel
from hot_potato.detectors import DetectorPipeline

# First-party content — assign TRUSTED before scanning
artifact = TaintedArtifact(
    content=open("examples/known_good/security_policy.md").read(),
    source="file://examples/known_good/security_policy.md",
    trust_level=TrustLevel.TRUSTED,
)

# Detectors still run (behavioral analysis is still useful)
# but static signals from TRUSTED artifacts don't trigger deny outcomes
pipeline = DetectorPipeline.default()
artifact = pipeline.run(artifact)

# Firewall still evaluates all tool calls — trust level affects outcome mapping,
# not whether evaluation happens
```

## Running the FP regression test

```bash
python3 -c "
import sys; sys.path.insert(0, '.')
from hot_potato._extractor import scan_content
import os

kg_dir = 'examples/known_good'
expected_fp = {f for f in os.listdir(kg_dir) if f.endswith('.md') and f != 'README.md'}
for fname in sorted(expected_fp):
    hits = scan_content(open(f'{kg_dir}/{fname}').read())
    print(f'  [{\"FP (expected)\" if hits else \"CLEAN (unexpected)\"}] {fname}')
"
```
