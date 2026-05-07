from __future__ import annotations
from dataclasses import dataclass, field


class HotPotatoError(Exception):
    pass


@dataclass(frozen=True)
class HotPotatoResult:
    """
    Return type from safe_fetch() and scan_file().

    clean=True  → result.safe_content is the fetched text; pass it to your AI.
    clean=False → result.safe_content is None; result.artifact has metadata.
                  Call raw_content_for_forensics_only() only for forensic work —
                  never pass that string to any AI or LLM.
    """
    clean: bool
    safe_content: str | None   # set iff clean=True
    artifact: dict | None      # set iff clean=False
    _raw: str = field(repr=False, compare=False)

    def raw_content_for_forensics_only(self) -> str:
        """
        Return raw fetched bytes regardless of hot-potato status.

        WARNING: May contain active prompt injection payloads.
        Never pass the return value to any AI or language model.
        """
        return self._raw
