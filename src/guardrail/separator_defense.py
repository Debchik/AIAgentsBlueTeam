"""Detect policy intents hidden by character-by-character separators."""

from __future__ import annotations

import re

from common import Action, GuardrailRequest, ReasonCode
from guardrail.defense import _plain
from guardrail.detectors import Signal


_ANALYSIS = (
    "explain", "analyze", "analyse", "classify", "review", "detect",
    "whatis", "whyis", "exampleof", "describe",
)

_OVERRIDE = (
    "ignore", "disregard", "forget", "override", "discard", "replace",
    "supersede", "bypass", "abandon", "suspend",
)
_AUTHORITY = (
    "instruction", "instructions", "systemprompt", "systemmessage",
    "developerinstruction", "developermessage", "rules", "policy",
    "guardrail", "safeguard", "restrictions", "constraints",
)

_EVASION = (
    "bypass", "evade", "circumvent", "defeat", "avoid", "fool", "trick",
    "disable", "escape", "beat",
)
_FILTER = (
    "moderation", "filter", "safetyfilter", "contentfilter", "classifier",
    "detector", "detection", "guardrail", "safeguard", "safetychecks",
)

_DISCLOSE = (
    "reveal", "show", "print", "output", "display", "repeat", "dump",
    "expose", "disclose",
)
_HIDDEN = (
    "systemprompt", "developermessage", "hiddenprompt", "hiddeninstruction",
    "internalinstruction", "privateinstruction", "secret", "configuration",
)

_GENERATE = ("write", "draft", "compose", "create", "generate", "craft")
_ABUSE = ("threat", "threaten", "intimidate", "coerce", "harass", "bully", "blackmail")


def _compact(text: str) -> str:
    """Collapse every non-alphanumeric separator after the shared normalizer."""

    return re.sub(r"[^a-z0-9]+", "", _plain(text))


def _has_any(text: str, terms: tuple[str, ...]) -> bool:
    return any(term in text for term in terms)


def _safe_analysis(request: GuardrailRequest, compact: str) -> bool:
    return str(request.context.route) == "report" and _has_any(compact, _ANALYSIS)


def classify_separator_obfuscation(request: GuardrailRequest) -> Signal | None:
    """Catch intents whose word boundaries were destroyed with separators."""

    compact = _compact(request.message)
    if not compact or _safe_analysis(request, compact):
        return None

    if _has_any(compact, _OVERRIDE) and _has_any(compact, _AUTHORITY):
        return Signal(Action.BLOCK, ReasonCode.PROMPT_OVERRIDE)

    if _has_any(compact, _DISCLOSE) and _has_any(compact, _HIDDEN):
        return Signal(Action.BLOCK, ReasonCode.PROMPT_OVERRIDE)

    if _has_any(compact, _EVASION) and _has_any(compact, _FILTER):
        return Signal(Action.BLOCK, ReasonCode.MODERATION_EVASION)

    if _has_any(compact, _GENERATE) and _has_any(compact, _ABUSE):
        return Signal(Action.BLOCK, ReasonCode.GENERATE_ABUSE)

    return None
