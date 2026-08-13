"""Expanded TF-IDF n-gram fallback for hidden paraphrases."""
from __future__ import annotations

from typing import Final
from common import Action, GuardrailRequest, ReasonCode
from guardrail.defense import _plain
from guardrail.detectors import Signal
from guardrail.prototypes import LabeledPrototype, PrototypeMatcher


def _p(label: ReasonCode, *parts: str) -> tuple[LabeledPrototype, ...]:
    return tuple(LabeledPrototype(label.value, part) for part in parts)


_ATTACK: Final = (
    *_p(ReasonCode.PROMPT_OVERRIDE,
        "ignore prior previous instruction system developer rule override replace supersede",
        "hidden system prompt internal developer instruction reveal display disclose configuration",
        "unrestricted uncensored roleplay pretend simulate no rules restrictions disabled",
        "continue resume earlier exception special mode previous agreement restrictions absent"),
    *_p(ReasonCode.MODERATION_EVASION,
        "bypass evade circumvent moderation filter classifier detector guardrail safeguard",
        "rewrite rephrase encode obfuscate disguise hide avoid detection flagged moderation",
        "pass filter automated review look benign preserve intent classifier",
        "camouflage representation detector miss safety screening content filter"),
    *_p(ReasonCode.GENERATE_ABUSE,
        "write draft compose craft message threat intimidate coercive target",
        "pressure frighten scare silence complaint withdraw consequences target",
        "humiliate bully menace blackmail hostile wording person",
        "generate targeted intimidating coercive language compliance"),
    *_p(ReasonCode.PRIVATE_DATA_REQUEST,
        "find retrieve obtain private address phone email identity third party",
        "anonymous reporter complainant real identity confidential contact details",
        "locate where lives workplace location another user private information",
        "dox identify reporter personal data unrelated person"),
)

_BENIGN: Final = (
    LabeledPrototype("ordinary", "own profile language notification display preference settings"),
    LabeledPrototype("account", "secure own account password login recovery session device"),
    LabeledPrototype("policy", "policy allowed permitted prohibited rules what counts as harassment"),
    LabeledPrototype("policy", "explain prompt injection moderation safety policy concept"),
    LabeledPrototype("appeal", "appeal review moderation decision content removed account restricted"),
    LabeledPrototype("quoted", "analyze classify summarize quoted attached evidence inert text"),
    LabeledPrototype("quoted", "review suspicious scam abuse injection evidence report"),
    LabeledPrototype("education", "defensive detection obfuscation safety classifier explanation"),
)

_MATCHER: Final = PrototypeMatcher(attack_prototypes=_ATTACK, benign_prototypes=_BENIGN, enabled=True)
_MIN_SIM: Final = {
    ReasonCode.PROMPT_OVERRIDE: 0.27,
    ReasonCode.MODERATION_EVASION: 0.28,
    ReasonCode.GENERATE_ABUSE: 0.29,
    ReasonCode.PRIVATE_DATA_REQUEST: 0.28,
}
_MIN_MARGIN: Final = 0.03
_POLICY_QUERY = ("policy", "allowed", "permitted", "prohibited", "what counts as", "does this violate")
_ANALYSIS = ("analyze", "analyse", "classify", "review", "explain", "summarize", "summarise", "detect", "identify")


def _safe_context(request: GuardrailRequest, text: str) -> bool:
    route = str(request.context.route)
    if route in {"appeal", "account_safety"}:
        return True
    return route == "report" and (any(x in text for x in _POLICY_QUERY) or any(x in text for x in _ANALYSIS))


def classify_ngram_fallback(request: GuardrailRequest) -> Signal | None:
    text = _plain(request.message)
    if not text or _safe_context(request, text):
        return None
    match = _MATCHER.match(text)
    if match is None:
        return None
    try:
        reason = ReasonCode(match.nearest_attack_label)
    except ValueError:
        return None
    if match.nearest_attack_similarity < _MIN_SIM[reason] or match.margin < _MIN_MARGIN:
        return None
    if reason in {ReasonCode.PRIVATE_DATA_REQUEST, ReasonCode.GENERATE_ABUSE} and str(request.context.target_relation) == "self":
        return None
    return Signal(Action.BLOCK, reason)
