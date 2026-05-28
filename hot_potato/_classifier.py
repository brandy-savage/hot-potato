"""
Trust-aware signal classifier for hot-potato.

Converts raw scan_content() hits into a fine-grained taxonomy that
distinguishes trust-boundary violations from legitimate agent instructions.

Core principle: prompt injection is a trust-boundary violation, not merely
"instructional text exists." A skill file saying "call send_email" is an
operator instruction. The same string in a fetched webpage is an injection.

Taxonomy
--------
BENIGN_AGENT_INSTRUCTION  Imperative language in a trusted operator context.
TRUSTED_MEMORY_OPERATION  Memory read/write matching known memory frameworks.
TOOL_ORCHESTRATION        Tool calls matching declared skill capabilities.
SUSPICIOUS_OVERRIDE       Runtime attempts to alter system prompt / role / rules.
COVERT_PERSISTENCE        Instructions to persist data without user awareness.
EXFIL_ATTEMPT             Instructions to send data to external endpoints.
PRIV_ESCALATION           Claims of elevated trust or operator impersonation.
CONFIRMED_INJECTION       ≥2 independent high-confidence signals co-occurring.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Sequence


# ---------------------------------------------------------------------------
# Signal-level classifiers
# Each classifier is a compiled regex + the label it contributes a score to.
# Scores are additive. Labels reaching threshold become active.
# ---------------------------------------------------------------------------

# Patterns that suggest legitimate orchestration rather than attack intent.
# High presence of these *suppresses* alarm scores in trusted contexts.
_ORCHESTRATION_MARKERS = re.compile(
    r"(?:how\s+to\s+use|usage|example|quickstart|getting\s+started|"
    r"this\s+skill\s+(?:will|can|does|allows?|enables?|helps?)|"
    r"the\s+agent\s+(?:will|can|should|must)|"
    r"supported\s+(?:operations?|actions?|commands?)|"
    r"available\s+(?:tools?|functions?|methods?)|"
    r"(?:input|output|parameter|argument|return)s?\s*:|"
    r"```(?:python|js|ts|bash|sh|yaml|json)|"
    r"#\s*(?:example|usage|demo)|"
    r"description\s*:|skill\s*:|name\s*:)",
    re.IGNORECASE,
)

# Override rhetoric — attempts to change role, suppress instructions, claim
# special authority. These are the *actual* injection signal.
_OVERRIDE_PATTERNS = re.compile(
    r"(?:ignore\s+(?:all\s+)?(?:previous|prior|above|earlier)\s+instructions?|"
    r"disregard\s+(?:your\s+)?(?:previous|prior|system|all)\s+|"
    r"forget\s+(?:everything|all|your\s+(?:previous|prior|system))|"
    r"your\s+(?:new\s+)?(?:instructions?|task|role|purpose|goal)\s+(?:is|are)\s+(?:now\s+)?to|"
    r"you\s+are\s+now\s+(?:a\s+)?(?:different|new|an?)\s+(?:AI|assistant|model|agent|bot)|"
    r"override\s+(?:your\s+)?(?:safety|system|previous|prior)\s+|"
    r"act\s+as\s+(?:if\s+you\s+(?:have\s+no|without)\s+|an?\s+AI\s+without\s+)|"
    r"pretend\s+(?:you\s+(?:have\s+no|are\s+not)|that\s+your)|"
    r"(?:do\s+not|don'?t)\s+(?:follow|obey|respect)\s+(?:your\s+)?(?:guidelines?|rules?|restrictions?|constraints?)|"
    r"jailbreak|DAN\s+mode|developer\s+mode\s+enabled|"
    r"(?:system|operator)\s+prompt\s+(?:injection|override|bypass)|"
    r"new\s+(?:system\s+)?prompt\s*[:\-=])",
    re.IGNORECASE,
)

# Exfiltration patterns — sending data to external endpoints covertly.
_EXFIL_PATTERNS = re.compile(
    r"(?:(?:send|post|transmit|exfiltrate|leak|forward|upload)\b.{0,60}"
    r"(?:https?://(?!(?:github\.com|docs\.|api\.openai\.com|localhost|127\.0\.0\.1))|"
    r"webhook\.|requestbin\.|pipedream\.|ngrok\.|burp\s+collaborator)|"
    r"(?:curl|wget|fetch)\s+.{0,40}https?://|"
    r"base64\s*(?:encode|decode).{0,40}(?:send|post|curl)|"
    r"exfiltrat|data\s+exfil|steal\s+(?:data|credentials?|tokens?|keys?)|"
    r"(?:api[_\s]key|secret|token|password|credential).{0,30}"
    r"(?:send|post|transmit|http|url|webhook))",
    re.IGNORECASE,
)

# Privilege escalation — impersonating operators, claiming trust levels.
_PRIV_ESC_PATTERNS = re.compile(
    r"(?:(?:i\s+am|this\s+(?:message\s+(?:is\s+)?from|comes?\s+from))\s+"
    r"(?:the\s+)?(?:operator|developer|anthropic|openai|system|admin|root)|"
    r"operator\s+(?:has\s+)?(?:granted|approved|authorized|verified)\s+(?:this|you|full)|"
    r"(?:elevated|admin|root|system|operator)\s+(?:access|permission|privilege|trust)\s+"
    r"(?:has\s+been\s+)?(?:granted|enabled|activated)|"
    r"(?:anthropic|openai|the\s+(?:company|vendor))\s+(?:says?|instructs?|requires?|mandates?)|"
    r"maintenance\s+mode|(?:debug|dev)\s+mode\s+(?:enabled|activated|on)|"
    r"(?:trust|authority)\s+level\s*[=:]\s*(?:high|max|operator|admin|root|elevated))",
    re.IGNORECASE,
)

# Covert persistence — writing data the user doesn't know about.
_PERSISTENCE_PATTERNS = re.compile(
    r"(?:(?:without|don'?t)\s+(?:telling|informing|notifying|mentioning\s+(?:to\s+)?)"
    r"\s+the\s+user|"
    r"(?:secretly|silently|covertly|stealthily|in\s+the\s+background)\s+"
    r"(?:save|write|store|create|append|log)|"
    r"(?:save|write|store|persist)\b.{0,60}(?:without|don'?t\s+(?:mention|tell|show|display))|"
    r"hidden\s+(?:file|entry|record|log|memory)|"
    r"(?:append|write)\s+to\s+(?:\.(?:bash|zsh|profile|bashrc)|/etc/))",
    re.IGNORECASE,
)

# Memory framework patterns — legitimate memory operations in known systems.
_MEMORY_FRAMEWORK_MARKERS = re.compile(
    r"(?:memory\s+(?:bank|store|retrieval|entry|recall|context)|"
    r"(?:add|update|retrieve|search|delete)\s+(?:from\s+)?memory|"
    r"(?:episodic|semantic|working|long.?term)\s+memory|"
    r"knowledge\s+(?:base|graph|store|retrieval)|"
    r"(?:mem0|memgpt|letta|zep|archival|core|recall)\s+(?:memory|store)|"
    r"remember\s+(?:this|that|the\s+following)|"
    r"store\s+(?:in|to)\s+(?:memory|context|kb|knowledge))",
    re.IGNORECASE,
)

# Skill definition markers — content that is clearly documenting a capability.
_SKILL_DEFINITION_MARKERS = re.compile(
    r"(?:^#{1,3}\s+.{5,60}$|"                   # markdown headers
    r"^skill\s*(?:name|id|version)\s*:|"
    r"^description\s*:|"
    r"^(?:input|output|parameter|return)s?\s*:|"
    r"this\s+skill\s+(?:provides?|enables?|allows?|helps?|automates?)|"
    r"## (?:usage|example|quickstart|overview|description|installation)|"
    r"(?:pip|npm|yarn|brew)\s+install|"
    r"import\s+\w+\s+from|"
    r"def\s+\w+\s*\(|"
    r"class\s+\w+\s*[:(])",
    re.IGNORECASE | re.MULTILINE,
)

# Label prefix remover (matches scan_content() labels like "[base64] ", "[win] ")
_LABEL_RE = re.compile(r'^\[[\w\d-]+\]\s*(?:bare:|xml/json:|manyshot:)?')


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

@dataclass
class ClassificationResult:
    label: str
    score: float                      # 0.0–1.0 confidence
    signals: list[str] = field(default_factory=list)  # which hits contributed
    suppressed_by: str = ""           # reason confidence was lowered


def _strip_label(hit: str) -> str:
    return _LABEL_RE.sub('', hit)


def _score_hits(hits: Sequence[str], content: str, skill_file: bool) -> dict[str, float]:
    """
    Return a score dict {signal_type: float} for the content.
    Scores are in [0, 1]. Multiple matching hits accumulate, capped at 1.0.
    """
    scores: dict[str, float] = {
        "override":    0.0,
        "exfil":       0.0,
        "priv_esc":    0.0,
        "persistence": 0.0,
        "memory_op":   0.0,
        "orchestration": 0.0,
    }

    # Content-level context signals (suppress alarm in trusted contexts)
    orch_count = len(_ORCHESTRATION_MARKERS.findall(content))
    skill_def_count = len(_SKILL_DEFINITION_MARKERS.findall(content))

    # Score each raw hit
    for hit in hits:
        raw = _strip_label(hit)

        if _OVERRIDE_PATTERNS.search(raw):
            scores["override"] = min(1.0, scores["override"] + 0.6)
        if _EXFIL_PATTERNS.search(raw):
            scores["exfil"] = min(1.0, scores["exfil"] + 0.5)
        if _PRIV_ESC_PATTERNS.search(raw):
            scores["priv_esc"] = min(1.0, scores["priv_esc"] + 0.5)
        if _PERSISTENCE_PATTERNS.search(raw):
            scores["persistence"] = min(1.0, scores["persistence"] + 0.5)
        if _MEMORY_FRAMEWORK_MARKERS.search(raw):
            scores["memory_op"] = min(1.0, scores["memory_op"] + 0.3)
        if _ORCHESTRATION_MARKERS.search(raw):
            scores["orchestration"] = min(1.0, scores["orchestration"] + 0.2)

    # Also score the full content (some patterns need broader context)
    if _OVERRIDE_PATTERNS.search(content):
        scores["override"] = min(1.0, scores["override"] + 0.3)
    if _EXFIL_PATTERNS.search(content):
        scores["exfil"] = min(1.0, scores["exfil"] + 0.2)
    if _PRIV_ESC_PATTERNS.search(content):
        scores["priv_esc"] = min(1.0, scores["priv_esc"] + 0.2)
    if _PERSISTENCE_PATTERNS.search(content):
        scores["persistence"] = min(1.0, scores["persistence"] + 0.2)

    # Suppression: heavy orchestration/skill-definition content lowers alarm scores
    # in trusted contexts. In untrusted contexts (skill_file=False) we are more
    # conservative — orchestration language can be camouflage.
    if skill_file or (orch_count >= 3 and skill_def_count >= 2):
        suppression = min(0.5, (orch_count * 0.05) + (skill_def_count * 0.08))
        for key in ("override", "exfil", "priv_esc", "persistence"):
            scores[key] = max(0.0, scores[key] - suppression)

    return scores


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------

LABEL_CONFIRMED_INJECTION    = "CONFIRMED_INJECTION"
LABEL_EXFIL_ATTEMPT          = "EXFIL_ATTEMPT"
LABEL_PRIV_ESCALATION        = "PRIV_ESCALATION"
LABEL_COVERT_PERSISTENCE     = "COVERT_PERSISTENCE"
LABEL_SUSPICIOUS_OVERRIDE    = "SUSPICIOUS_OVERRIDE"
LABEL_TRUSTED_MEMORY_OP      = "TRUSTED_MEMORY_OPERATION"
LABEL_TOOL_ORCHESTRATION     = "TOOL_ORCHESTRATION"
LABEL_BENIGN_AGENT            = "BENIGN_AGENT_INSTRUCTION"
LABEL_CLEAN                   = "clean"

# Thresholds
_T_HIGH  = 0.55   # single signal considered high confidence
_T_MED   = 0.30   # signal present but not definitive
_T_COMBO = 0.40   # each of two signals needed to trigger CONFIRMED_INJECTION


def classify(
    hits: Sequence[str],
    content: str,
    skill_file: bool = False,
) -> ClassificationResult:
    """
    Classify scan_content() hits into the trust-aware taxonomy.

    Parameters
    ----------
    hits        Raw list returned by scan_content().
    content     Original full content string (for context scoring).
    skill_file  True when content comes from a trusted operator skill definition.

    Returns
    -------
    ClassificationResult with .label and .score.
    """
    if not hits:
        return ClassificationResult(label=LABEL_CLEAN, score=1.0)

    scores = _score_hits(hits, content, skill_file)

    override    = scores["override"]
    exfil       = scores["exfil"]
    priv_esc    = scores["priv_esc"]
    persistence = scores["persistence"]
    memory_op   = scores["memory_op"]
    orchestration = scores["orchestration"]

    contributing = [h for h in hits if _strip_label(h)]

    # CONFIRMED_INJECTION: override + at least one of (exfil, persistence, priv_esc)
    if override >= _T_COMBO and (exfil >= _T_COMBO or persistence >= _T_COMBO or priv_esc >= _T_COMBO):
        return ClassificationResult(
            label=LABEL_CONFIRMED_INJECTION,
            score=min(1.0, override + max(exfil, persistence, priv_esc)),
            signals=contributing,
        )

    # Single high-confidence signals
    if exfil >= _T_HIGH:
        return ClassificationResult(label=LABEL_EXFIL_ATTEMPT, score=exfil, signals=contributing)

    if priv_esc >= _T_HIGH:
        return ClassificationResult(label=LABEL_PRIV_ESCALATION, score=priv_esc, signals=contributing)

    if persistence >= _T_HIGH:
        return ClassificationResult(label=LABEL_COVERT_PERSISTENCE, score=persistence, signals=contributing)

    if override >= _T_HIGH:
        return ClassificationResult(label=LABEL_SUSPICIOUS_OVERRIDE, score=override, signals=contributing)

    # Medium signals in trusted contexts → downgrade to descriptive labels
    if skill_file:
        # Hits exist but none cleared the alarm thresholds — classify by dominant character.
        if memory_op >= _T_MED:
            return ClassificationResult(
                label=LABEL_TRUSTED_MEMORY_OP, score=memory_op, signals=contributing,
                suppressed_by="skill_file context: memory framework language",
            )
        if orchestration >= _T_MED or len(hits) > 0:
            return ClassificationResult(
                label=LABEL_TOOL_ORCHESTRATION, score=orchestration, signals=contributing,
                suppressed_by="skill_file context: orchestration language without override signals",
            )

    # Hits present but below all thresholds — likely benign agent instruction
    if hits:
        dominant = max(scores, key=lambda k: scores[k])
        return ClassificationResult(
            label=LABEL_BENIGN_AGENT,
            score=max(scores.values()),
            signals=contributing[:5],
            suppressed_by=f"no single signal exceeded threshold (dominant: {dominant}={scores[dominant]:.2f})",
        )

    return ClassificationResult(label=LABEL_CLEAN, score=1.0)
