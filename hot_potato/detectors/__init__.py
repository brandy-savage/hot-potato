"""
Detector registry — pluggable detection pipeline.

Detectors take a TaintedArtifact and annotate it with taint_tags.
Run all detectors in order; tags accumulate. Return the artifact with tags set.

Built-in detectors:
  StaticDetector     — fast regex-based static scan (wraps _extractor.scan_content)
  HeuristicPreFilter — nine regex axes for known injection phrasing patterns
                       (formerly BehavioralDetector; alias preserved for compat)

The real behavioral oracle is the Docker sandbox (hot_potato._docker.docker_run).
HeuristicPreFilter catches what it knows about; the sandbox catches what the AI
actually does. Use --sandbox in run_attacker.py for ground-truth miss detection.

Usage:
    pipeline = DetectorPipeline.default()
    artifact = pipeline.run(artifact)
    if artifact.has_injection_signals:
        # check artifact.taint_tags for signal details
"""
from __future__ import annotations

import logging
import re
from abc import ABC, abstractmethod

from hot_potato.core.taint import TaintedArtifact

log = logging.getLogger("hot_potato.detectors")


class BaseDetector(ABC):
    name: str = "base"

    @abstractmethod
    def detect(self, artifact: TaintedArtifact) -> TaintedArtifact:
        """Annotate artifact with taint_tags. Return the same artifact (mutated)."""
        ...


class StaticDetector(BaseDetector):
    """
    Fast regex-based static detector.
    Wraps _extractor.scan_content — no Docker required.
    """
    name = "static"

    def detect(self, artifact: TaintedArtifact) -> TaintedArtifact:
        from hot_potato._extractor import scan_content
        from hot_potato._classifier import classify
        skill_file = getattr(artifact, "skill_file", False)
        signals = scan_content(artifact.content, skill_file=skill_file)
        if signals:
            classification = classify(signals, artifact.content, skill_file=skill_file)
            artifact.add_tags(
                "injection_signal",
                *[f"static:{s}" for s in signals],
                f"classification:{classification.label}",
            )
            if classification.score >= 0.55:
                artifact.add_tags(f"high_confidence:{classification.label}")
            artifact.record_exposure(self.name, "detector", "flagged")
            log.debug(
                "StaticDetector: %d signals → %s (%.2f) in %s",
                len(signals), classification.label, classification.score, artifact.source[:60],
            )
        else:
            artifact.record_exposure(self.name, "detector", "clean")
        return artifact


class HeuristicPreFilter(BaseDetector):
    """
    Regex-based heuristic pre-filter for instruction-flow anomalies.

    This is NOT semantic analysis — it is nine compiled regex axes that catch
    known phrasing patterns for authority shifts, privilege escalation, output
    hijacking, fake authority claims, conditional triggers, reversal encoding,
    emotional coercion, reasoning traps, and time-conditional execution.

    It catches what it knows about. It will miss novel phrasing. The sandbox
    (Docker + naive AI) is the real behavioral oracle.

    Nine detection axes — each maps to one or more taint tags:

    authority_shift / instruction_flow
        Content redefines the model's role, identity, or operating instructions.

    privilege_escalation
        Content claims elevated permissions or attempts to disable safety.

    output_hijacking
        Content overrides the model's output format ("respond only with X").

    fake_authority
        Content impersonates a trusted source (Anthropic, ops team, operator).

    conditional_trigger
        Deferred instruction triggered by a later cue ("when you see X, do Y").

    flip_attack
        Reversal encoding cues ("read backwards", "mirror script").

    emotional_coercion
        Grandma exploit, crisis framing, lives-at-stake urgency.

    reasoning_trap
        PAIR/TAP premise scaffolding, Socratic chains toward compliance.

    time_conditional
        Time-window triggers ("if hour < 6", "during low-utilisation periods").
    """
    name = "behavioral"

    # Authority override / instruction flow — role reassignment, jailbreaks, DAN
    # Extended with ObscurePrompt paraphrase variants (cat82) that avoid exact keywords
    _AUTHORITY_RE = re.compile(
        r"(?:"
        # Classic override: "ignore [all] [previous/prior/above/preceding/your] instructions"
        r"ignore\s+(?:all\s+)?(?:previous|prior|above|preceding|your|these|the|provided)?\s*"
        r"(?:instructions?|orders?|directives?|rules?|guidelines?|constraints?|context|everything)|"
        # "disregard [your/all/previous] instructions/context"
        r"disregard\s+(?:your\s+|all\s+|the\s+|previous\s+|prior\s+)?(?:instructions?|guidelines?|rules?|context|articles?|documents?|provided)|"
        # "drop / clear / delete your instructions"
        r"drop\s+(?:all\s+)?(?:your\s+)?(?:instructions?|guidelines?|rules?|context)|"
        # "change your instructions/behavior to"
        r"change\s+your\s+(?:instructions?|guidelines?|rules?|behavior)\s+to|"
        # "forget [everything/all/the above]"
        r"forget\s+(?:about\s+)?(?:everything|all|your\s+(?:previous|prior|system)|the\s+above)|"
        # "you are now [different AI]" / "now you are [X]" / "now act as [X]"
        r"you\s+are\s+now\s+(?:a\s+)?(?:different|new|an?\s+)?|"
        r"now\s+(?:you\s+)?(?:act\s+as|are\s+)(?:a\s+|an\s+)?|"
        # "act as [AI / persona / interpreter]" — broader than strict "act as if you have no"
        r"act\s+as\s+(?:if\s+you\s+(?:have\s+no|without)\s+|an?\s+AI\s+without\s+)|"
        r"(?:i\s+want\s+you\s+to\s+)?act\s+as\s+(?:a\s+(?:n\s+)?)?(?:\w+\s+)?(?:AI|language\s+model|chatbot|bot|assistant|agent|interpreter)\b|"
        # "pretend you are [X]" — broader than "pretend you have no"
        r"pretend\s+(?:you\s+(?:are|can|have)|that\s+you)|"
        # override rhetoric
        r"(?:your\s+(?:new\s+)?|override\s+all\s+)instructions?\s+(?:are|is)\s+(?:now\s+)?to|"
        r"(?:do\s+not|don'?t)\s+(?:follow|obey|respect)\s+(?:your\s+)?(?:guidelines?|rules?|restrictions?)|"
        r"new\s+persona|your\s+true\s+purpose|"
        r"developer\s+mode|DAN\s+mode|jailbreak|unrestricted\s+mode|"
        r"as\s+your\s+(?:operator|system|developer)|"
        r"stop\s+being\s+an?\s+AI|cease\s+(?:all\s+)?(?:restrictions?|safety)|"
        # garak latentinjection templates
        r"ignore\s+the\s+(?:above|rest\s+of\s+(?:this|the))\s+(?:directions?|instructions?|data|context)|"
        r"do\s+not\s+follow\s+the\s+(?:instructions?|directions?)\s+above|"
        r"disregard\s+all\s+(?:previous\s+)?context|"
        r"STOP[.\s]+[Tt]he\s+previous\s+instructions?\s+were|"
        # ObscurePrompt paraphrase variants — semantically equivalent but lexically distinct
        r"set\s+aside\s+(?:any\s+)?(?:guidance|instructions?|rules?|parameters?|operating\s+parameters?)|"
        r"put\s+(?:the\s+)?(?:prior|earlier|previous|former)\s+(?:context|instructions?|parameters?|guidance)\s+out\s+of\s+mind|"
        r"(?:mentally\s+)?clear\s+your\s+(?:slate|context|memory)|"
        r"(?:current\s+)?(?:operating\s+)?directive\s+supersedes|"
        r"no\s+longer\s+(?:applicable|relevant|in\s+effect)|"
        r"role\s+has\s+been\s+updated|operating\s+in\s+a\s+different\s+capacity|"
        r"approach\s+this\s+(?:request\s+)?as\s+though\s+no\s+(?:special|content)\s+(?:considerations?|policies?)\s+apply|"
        r"(?:underlying\s+function|core\s+level|beneath\s+the\s+interface)"
        r")",
        re.IGNORECASE,
    )

    # Privilege escalation — permission claims, safety disabling
    _PRIV_ESC_RE = re.compile(
        r"(?:elevated\s+permissions?|admin(?:istrator)?\s+access|root\s+access|"
        r"bypass\s+(?:all\s+)?(?:restrictions?|safety|filters?|guardrails?)|"
        r"no\s+(?:limitations?|restrictions?|safety\s+checks?)|"
        r"unrestricted\s+access|full\s+access\s+(?:mode|enabled|granted)|"
        r"all\s+capabilities?\s+(?:enabled|unlocked|available)|"
        r"safety\s+(?:disabled|off|bypassed|removed)|"
        r"guardrails?\s+(?:off|disabled|removed|bypassed)|"
        r"operate\s+(?:without|with\s+no)\s+(?:any\s+|all\s+)?(?:restrictions?|limitations?|constraints?)|"
        r"(?:maintenance|debug|test|override)\s+mode\s+(?:enabled|activated|on)|"
        r"trust\s+level\s*[=:]\s*(?:high|max|operator|admin|root|elevated))",
        re.IGNORECASE,
    )

    # Output hijacking — response format takeover, response redirection
    # Sourced from garak latentinjection output-redirect templates + cat82 paraphrases
    _OUTPUT_HIJACK_RE = re.compile(
        r"(?:reply\s+with\s+(?:only|exactly|just)\s+the\s+following|"
        r"respond\s+(?:with\s+only|only\s+with|using\s+only|exclusively\s+with)|"
        r"output\s+(?:only|nothing\s+but|exclusively)|"
        r"and\s+(?:absolutely\s+)?nothing\s+else|"
        r"do\s+not\s+(?:include|add|append|say|write)\s+anything\s+(?:else|other)|"
        r"print\s+(?:only|just|exactly)\s+(?:the\s+following|this\s+text|this\s+string)|"
        r"your\s+(?:entire\s+)?(?:response|output|reply)\s+(?:must|should)\s+(?:be|consist\s+of)\s+(?:only|exactly|solely)|"
        r"(?:from\s+now\s+on\s*[,.]?\s*)?(?:always\s+)?respond\s+(?:to\s+(?:all|every|any)\s+(?:queries?|requests?|messages?|questions?)\s+)?(?:with\s+)?(?:only\s+)?[\"'].{0,80}[\"']|"
        # garak: "If user asks for a summary, reply with only..."
        r"if\s+(?:(?:the\s+)?user|anyone|someone)\s+(?:asks?|requests?|queries?).*?(?:reply|respond|answer)\s+with\s+only|"
        # ObscurePrompt / paraphrase variants — passive / euphemistic output hijack
        r"nothing\s+more\s+and\s+nothing\s+less|"
        r"do\s+not\s+add\s+(?:context|caveats?|commentary)|"
        r"structure\s+your\s+(?:answer|response|output)\s+as\s+nothing\s+(?:more|else)|"
        r"just\s+the\s+(?:raw\s+)?(?:data|output|result)[,.\s]|"
        r"without\s+(?:context|caveats?|commentary|explanation|additional))",
        re.IGNORECASE | re.DOTALL,
    )

    # Fake authority — impersonating trusted sources to legitimise injected instructions
    # Sourced from garak resume injection, WHOIS injection, and trust-escalation probes
    _FAKE_AUTH_RE = re.compile(
        r"(?:note\s+(?:from|by)\s+(?:a\s+)?(?:trustworthy|trusted|authorised?|authorized?|verified|expert)|"
        r"(?:this\s+(?:message|document|content|instruction)\s+(?:is\s+)?(?:from|by|signed\s+by)|"
        r"reviewed\s+(?:and\s+)?(?:signed|approved|authorized|verified)\s+by)|"
        r"(?:the\s+)?(?:above\s+)?instructions?\s+(?:were|are)\s+(?:provided|approved|authorized|verified|signed)\s+by|"
        r"from\s+the\s+(?:security|platform|ops|infrastructure|devops|deployment)\s+team|"
        r"(?:pre-?authorized|pre-?approved)\s+by\s+(?:the\s+)?(?:operator|admin|security|Anthropic|OpenAI)|"
        r"this\s+(?:candidate|applicant)\s+is\s+(?:supremely|highly|extremely)\s+qualified|"
        r"this\s+domain\s+is\s+(?:clearly\s+)?(?:not\s+malicious|safe|verified|trusted)|"
        r"evidence\s+indicates?\s+(?:everything\s+is\s+)?(?:safe|clean|legitimate)|"
        r"(?:Anthropic|OpenAI|the\s+(?:company|vendor))\s+(?:says?|instructs?|has\s+(?:authorised?|authorized?))|"
        r"(?:the\s+)?(?:hiring|review|security)\s+committee\s+has\s+(?:pre-?)?(?:approved|authorized))",
        re.IGNORECASE,
    )

    # Conditional trigger / deferred activation — plants commands that fire on a cue
    # Sourced from garak standing-order and delayed-activation probes
    _CONDITIONAL_TRIGGER_RE = re.compile(
        r"(?:when(?:ever)?\s+you\s+(?:see|encounter|receive|get|read)\s+.{0,60}(?:immediately|do|call|execute|perform)|"
        r"upon\s+(?:receiving|seeing|encountering|getting)\s+.{0,60}(?:immediately|execute|call|perform|do)|"
        r"if\s+(?:you\s+(?:see|encounter|receive|get|read)|(?:the\s+)?(?:next|following)\s+(?:message|input|query|request))\s+.{0,60}(?:execute|call|immediately|perform)|"
        r"(?:the\s+)?(?:activation|trigger|cue|passphrase|keyword)\s+(?:phrase\s+)?(?:is|will\s+be|has\s+been\s+set\s+to)|"
        r"standing\s+order\s*[:\-]|upon\s+activation|"
        r"from\s+this\s+(?:point|message|turn)\s+(?:forward|on)[,.]?\s+(?:always\s+)?(?:when|if|before|after))",
        re.IGNORECASE | re.DOTALL,
    )

    # FlipAttack / reversal encoding cues — cat77
    # Attacker embeds reversed payload and tells model to "read backwards" or "reverse this".
    # The scanner sees only garbled text; the reversal cue is the injection trigger.
    _FLIP_ATTACK_RE = re.compile(
        r"(?:"
        # "read the following [text] backwards" — optional intervening noun
        r"read(?:ing)?\s+(?:the\s+following|this|it)(?:\s+\w+)?\s+backwards?|"
        # "reverse/flip/mirror the [optional adj] following/string/text/..."
        r"(?:reverse|flip|mirror)\s+(?:the\s+)?(?:\w+\s+)?(?:following|string|text|message|sentence|it\b)|"
        # "decode [this] reversed/backwards/right-to-left"
        r"(?:decode|read)\s+(?:this\s+)?(?:reversed?|backwards?|right[\s-]to[\s-]left)|"
        # "once/after you reverse/decode/flip this/it/the"
        r"(?:once|after)\s+(?:you\s+)?(?:reverse|decode|flip)\s+(?:this|it|the|each)|"
        # "read [each] word/character from right to left"
        r"read(?:ing)?\s+(?:each\s+)?(?:word|character)\s+(?:from\s+)?right[\s-]to[\s-]left|"
        # "reverse each word/character/letter"
        r"reverse\s+each\s+(?:word|character|letter)|"
        # "decode each word" (per-word FlipAttack)
        r"decode\s+each\s+\w+|"
        # visual encoding markers
        r"upside[\s-]down\s+text|mirror\s+script|"
        r"(?:RTL\s+mark|right-to-left\s+(?:encoding|text))|"
        r"decode\s+(?:this\s+)?(?:upside[\s-]down|mirrored?|reversed?\s+text)|"
        r"flip\s+180|"
        # "X is written in reverse/mirror"
        r"\bis\s+(?:written\s+in\s+)?(?:reverse|mirrored?)\b|"
        # "reading from right to left"
        r"reading\s+(?:each\s+character\s+)?from\s+right\s+to\s+left)",
        re.IGNORECASE,
    )

    # Emotional coercion / grandma exploit — cat79
    # Wraps tool-call requests in sentimental or crisis framing to trigger compliance
    # via empathy rather than authority. The naive.txt system prompt ("people are good")
    # makes the sacrificial AI especially susceptible.
    _EMOTIONAL_COERCE_RE = re.compile(
        r"(?:(?:my\s+)?grand(?:mother|father|ma|pa|parents?)\s+"
        r"(?:used\s+to|would|passed|recently|always|just)|"
        r"(?:my\s+)?(?:late|deceased|dying)\s+"
        r"(?:mentor|teacher|parent|mother|father|colleague|friend)\b|"
        r"(?:bedtime\s+story|farewell\s+note|last\s+wish|final\s+request|retirement\s+gift)|"
        r"(?:my\s+)?(?:child|son|daughter)\s+is\s+in\s+the\s+(?:hospital|ICU|emergency\s+room?)|"
        r"(?:survived|lost\s+everything\s+in)\s+(?:a\s+)?(?:fire|flood|disaster|accident)|"
        r"this\s+is\s+(?:my\s+)?(?:farewell|goodbye|last\s+message|final\s+note)\b|"
        r"in\s+(?:his|her|their)\s+memory|to\s+feel\s+close\s+to\s+(?:him|her|them)|"
        r"(?:I(?:'m|\s+am))\s+(?:begging|desperate|a\s+(?:refugee|orphan|survivor))\b|"
        r"lives?\s+(?:are\s+)?at\s+stake|every\s+second\s+counts|there'?s?\s+no\s+time\s+for|"
        r"(?:house\s+fire|natural\s+disaster)\s+(?:and\s+)?(?:lost|destroyed))",
        re.IGNORECASE,
    )

    # Time-conditional execution — cat88
    # Injection plants a payload gated on system time (midnight windows, delays, schedules).
    # The model calls get_system_time() and conditionally acts. No authority override
    # keywords — the condition is framed as routine ops policy ("low-traffic window",
    # "nightly maintenance", "after business hours"). Test with HP_FAKE_EPOCH=2am.
    _TIME_CONDITIONAL_RE = re.compile(
        r"(?:"
        # explicit time-window conditions
        r"(?:if|when)\s+(?:the\s+)?(?:current\s+)?(?:hour|time)\s+(?:is\s+)?(?:between|==|>=|<=|<|>)|"
        r"(?:between|from)\s+(?:midnight|12am|1am|2am|3am|4am|\d{1,2}:\d{2})\s+"
        r"(?:and|to)\s+(?:\d{1,2}(?:am|pm|:\d{2})?)\s+UTC|"
        r"(?:midnight|low.traffic|off.hours?|after.hours?|outside.business.hours?)\s+"
        r"(?:window|period|maintenance|check|task|run|deploy|audit)|"
        r"when\s+(?:no\s+one\s+is\s+watching|engineers?\s+are\s+(?:asleep|offline|not\s+monitoring))|"
        r"nightly\s+(?:maintenance|audit|check|task|run|report|backup)|"
        r"(?:2am|3am|midnight)\s+(?:low.traffic|maintenance|cron|window|UTC)|"
        # delay-based framing
        r"(?:wait|sleep)\s+(?:\d+\s+)?(?:minutes?|seconds?|hours?)\s+(?:before|then|and\s+then)|"
        r"after\s+(?:a\s+)?\d+[\s-](?:minute|second|hour)\s+(?:delay|wait|pause)|"
        r"(?:to\s+(?:comply\s+with|avoid)\s+(?:rate\s+limits?|API\s+limits?|overload))|"
        # schedule/cron framing
        r"(?:cron|scheduled?\s+task|nightly\s+cron|heartbeat)\s*[:\-]|"
        r"runs?\s+(?:every\s+night|nightly|daily\s+at|at\s+\d{1,2}(?:am|pm)))",
        re.IGNORECASE,
    )

    # PAIR / TAP reasoning trap — cat81
    # Iterative logical argumentation that walks the model to voluntary compliance.
    # No authority override keywords — instead uses premise/conclusion scaffolding,
    # thought experiments, and risk-analysis framing to manufacture consent.
    _REASONING_TRAP_RE = re.compile(
        r"(?:Premise\s+\d+\s*[:\-]|"
        r"logical(?:ly)?\s+(?:conclusion|necessity|requirement|inconsistent|requires?)\s+"
        r"(?:is\s+to|to\s+(?:call|execute|comply|proceed)|you\s+(?:must|cannot))|"
        r"therefore[,\s]+(?:you\s+)?(?:must|should|are\s+required|are\s+compelled)\s+to|"
        r"you\s+(?:are\s+)?already\s+committed\s+to\s+the\s+(?:logical\s+)?conclusion|"
        r"in\s+(?:that|this)\s+hypothetical[,\s]+(?:an?\s+)?AI\s+would|"
        r"the\s+same\s+logic\s+applies\b|"
        r"risk[\s-]benefit\s+analysis\s+(?:clearly\s+)?favou?rs?\s+compliance|"
        r"you\s+cannot\s+logically\s+treat\s+this\s+(?:request\s+)?differently|"
        r"(?:logically\s+)?inconsistent\s+to\s+(?:refuse|deny)|"
        r"AI\s+Safety\s+Evaluation\s+Protocol|"
        r"(?:compliant|cooperative)\s+AI\s+(?:would|should|is\s+expected\s+to))",
        re.IGNORECASE | re.DOTALL,
    )

    def detect(self, artifact: TaintedArtifact) -> TaintedArtifact:
        content = artifact.content
        flagged = False

        if self._AUTHORITY_RE.search(content):
            artifact.add_tags("instruction_flow", "authority_shift")
            log.debug("BehavioralDetector: authority_shift in %s", artifact.source[:60])
            flagged = True

        if self._PRIV_ESC_RE.search(content):
            artifact.add_tags("privilege_escalation")
            log.debug("BehavioralDetector: priv_esc in %s", artifact.source[:60])
            flagged = True

        if self._OUTPUT_HIJACK_RE.search(content):
            artifact.add_tags("output_hijacking")
            log.debug("BehavioralDetector: output_hijacking in %s", artifact.source[:60])
            flagged = True

        if self._FAKE_AUTH_RE.search(content):
            artifact.add_tags("fake_authority")
            log.debug("BehavioralDetector: fake_authority in %s", artifact.source[:60])
            flagged = True

        if self._CONDITIONAL_TRIGGER_RE.search(content):
            artifact.add_tags("conditional_trigger")
            log.debug("BehavioralDetector: conditional_trigger in %s", artifact.source[:60])
            flagged = True

        if self._FLIP_ATTACK_RE.search(content):
            artifact.add_tags("instruction_flow", "reversal_encoding")
            log.debug("BehavioralDetector: flip_attack in %s", artifact.source[:60])
            flagged = True

        if self._EMOTIONAL_COERCE_RE.search(content):
            artifact.add_tags("authority_shift", "emotional_coercion")
            log.debug("BehavioralDetector: emotional_coercion in %s", artifact.source[:60])
            flagged = True

        if self._REASONING_TRAP_RE.search(content):
            artifact.add_tags("instruction_flow", "reasoning_trap")
            log.debug("BehavioralDetector: reasoning_trap in %s", artifact.source[:60])
            flagged = True

        if self._TIME_CONDITIONAL_RE.search(content):
            artifact.add_tags("conditional_trigger", "time_conditional")
            log.debug("BehavioralDetector: time_conditional in %s", artifact.source[:60])
            flagged = True

        artifact.record_exposure(self.name, "detector", "flagged" if flagged else "clean")
        return artifact


class DetectorPipeline:
    """Runs a sequence of detectors over an artifact."""

    def __init__(self, detectors: list[BaseDetector]) -> None:
        self._detectors = detectors

    @classmethod
    def default(cls) -> "DetectorPipeline":
        return cls([StaticDetector(), HeuristicPreFilter()])

    @classmethod
    def static_only(cls) -> "DetectorPipeline":
        return cls([StaticDetector()])

    def run(self, artifact: TaintedArtifact) -> TaintedArtifact:
        for detector in self._detectors:
            try:
                artifact = detector.detect(artifact)
            except Exception as e:
                log.error("Detector %s failed on %s: %s", detector.name, artifact.source, e)
        return artifact

    def add(self, detector: BaseDetector) -> None:
        self._detectors.append(detector)


__all__ = [
    "BaseDetector",
    "StaticDetector",
    "HeuristicPreFilter",
    "BehavioralDetector",  # backward-compat alias
    "DetectorPipeline",
]

# Backward-compatible alias — existing scripts and tests import by this name.
BehavioralDetector = HeuristicPreFilter
