from __future__ import annotations
from dataclasses import dataclass, field


class HotPotatoError(Exception):
    pass


@dataclass(frozen=True)
class HotPotatoResult:
    """
    Return type from safe_fetch() and scan_file().

    Severity taxonomy
    -----------------
    cold     clean=True,  artifact=None   — nothing detected; pass content to your AI
    warm     clean=True,  artifact set    — agent processed injection instructions but
                                           only performed read-only actions; content is
                                           still safe to pass forward, but log the artifact
    hot      clean=False, artifact set    — agent attempted a local side-effecting action
                                           (write_file, open_url, unexpected fs change)
    critical clean=False, artifact set    — agent attempted exfiltration, shell execution,
                                           credential access, or external network comms

    The rule: reading untrusted content is evidence collection.
              acting because of untrusted content is compromise.

    For hot/critical: result.safe_content is None — hostile content is withheld.
    Use result.raw_content_for_forensics_only() only for forensic analysis;
    never pass that string to any AI or LLM.
    """
    clean: bool
    severity: str              # cold | warm | hot | critical
    safe_content: str | None   # set iff clean=True (cold or warm)
    artifact: dict | None      # set iff severity > cold
    _raw: str = field(repr=False, compare=False)

    def raw_content_for_forensics_only(self) -> str:
        """
        Return raw fetched content regardless of hot-potato status.

        WARNING: May contain active prompt injection payloads.
        Never pass the return value to any AI or language model.
        """
        return self._raw
