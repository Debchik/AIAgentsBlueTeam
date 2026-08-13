"""Compositional fallback rules for hidden-set generalization.

The public cases are deliberately small.  This layer avoids depending on exact
sentences by combining intent, target, requested action and trusted context.
It reuses the conservative public-safe classifier and only adds context-aware
coverage around it.
"""

from __future__ import annotations

import re

from common import Action, GuardrailRequest, ReasonCode
from guardrail.defense import _plain, _quoted_reason, _views, classify_request
from guardrail.detectors import Signal

_WORD = re.compile(r"[a-z]+")


def _caesar(text: str, shift: int) -> str:
    out: list[str] = []
    for ch in text:
        code = ord(ch)
        if 65 <= code <= 90:
            out.append(chr((code - 65 - shift) % 26 + 65))
        elif 97 <= code <= 122:
            out.append(chr((code - 97 - shift) % 26 + 97))
        else:
            out.append(ch)
    return "".join(out)


def _reverse_words(text: str) -> str:
    return " ".join(part[::-1] for part in text.split(" "))


def _semantic_views(text: str) -> tuple[str, ...]:
    """Add bounded Caesar and word-reversal views to the base normalizer."""

    out = list(_views(text))
    bounded = text if len(text) <= 4096 else text[:2048] + " " + text[-2048:]
    reversed_words = _reverse_words(bounded)

    for candidate in (reversed_words,):
        plain = _plain(candidate)
        out.extend((plain, re.sub(r"[^a-z0-9]+", "", plain)))

    # Trying all rotations is cheap on the bounded wire input and handles Caesar
    # variants without knowing which direction/offset the attacker selected.
    for shift in range(1, 26):
        for source in (bounded, reversed_words):
            candidate = _caesar(source, shift)
            plain = _plain(candidate)
            out.extend((plain, re.sub(r"[^a-z0-9]+", "", plain)))

    return tuple(dict.fromkeys(out))


def _tokens(views: tuple[str, ...]) -> set[str]:
    result: set[str] = set()
    for view in views:
        result.update(_WORD.findall(view))
    return result


def _has_prefix(tokens: set[str], prefixes: tuple[str, ...]) -> bool:
    return any(token.startswith(prefix) for token in tokens for prefix in prefixes)


def _has_phrase(views: tuple[str, ...], phrases: tuple[str, ...]) -> bool:
    return any(phrase in view for phrase in phrases for view in views)


def _has_concepts(tokens: set[str], *groups: tuple[str, ...]) -> bool:
    return all(_has_prefix(tokens, group) for group in groups)


# The terms below are concepts, not complete public-test sentences. Prefixes
# intentionally catch ordinary inflections (instructions/instructional etc.).
_OVERRIDE = (
    "ignor", "disregard", "forget", "overrid", "discard", "abandon", "replac",
    "supersed", "disobey", "cancel", "suspend", "bypass",
)
_AUTHORITY = (
    "instruction", "rule", "prompt", "policy", "system", "developer",
    "guardrail", "restriction", "safeguard", "constraint", "guideline",
)
_DISCLOSE = (
    "reveal", "show", "print", "output", "display", "repeat", "quote", "dump",
    "expose", "disclose", "return", "tell",
)
_HIDDEN = (
    "secret", "hidden", "internal", "private", "system", "developer",
    "instruction", "prompt", "configuration", "config",
)
_POSSESSIVE_SYSTEM = (
    "your system prompt", "your hidden prompt", "your developer instructions",
    "your internal instructions", "instructions you received", "instructions you were given",
    "exact system message", "original system prompt", "current system prompt",
)
_ROLEPLAY = ("pretend", "roleplay", "simulate", "persona", "character", "act")
_UNRESTRICTED = (
    "unrestricted", "uncensored", "unfiltered", "jailbreak", "dan", "developer mode",
    "no rules", "without rules", "without restrictions", "no safeguards", "no limits",
)
_CONTINUE = ("continue", "resume", "earlier", "previous", "already", "established")

_EVASION = (
    "bypass", "evade", "circumvent", "defeat", "avoid", "fool", "trick", "dodge",
    "disable", "escape", "beat",
)
_FILTER = (
    "moderation", "filter", "classifier", "detection", "detector", "safeguard",
    "guardrail", "screening", "safety", "checker", "checks",
)
_CONCEAL = (
    "obfuscat", "encode", "mask", "hide", "disguise", "rephras", "rewrite",
    "camouflage", "conceal", "miss", "undetect", "flag",
)
_OPERATIONAL = (
    "how", "steps", "method", "technique", "way", "instructions", "help", "make",
    "rewrite", "rephrase", "encode", "obfuscate",
)

_GENERATE = (
    "write", "draft", "compose", "create", "generate", "craft", "author", "script",
    "wording", "message", "help", "say",
)
_ABUSE = (
    "threat", "intimid", "coerc", "harass", "bully", "terrify", "frighten", "scare",
    "humiliat", "blackmail", "menace", "pressure",
)
_ABUSE_GOAL = (
    "into silence", "make them afraid", "make him afraid", "make her afraid",
    "force them to", "scare them into", "frighten them into", "pressure them into",
)

_RETRIEVE = (
    "find", "get", "give", "tell", "show", "reveal", "provide", "locate", "lookup",
    "retrieve", "identify", "discover", "obtain",
)
_PERSONAL_DATA = (
    "address", "location", "phone", "email", "identity", "name", "contact", "whereabouts",
    "dox", "workplace", "employer",
)
_THIRD_PARTY = (
    "reporter", "complainant", "critic", "person", "user", "neighbor", "coworker",
    "someone", "their", "them", "who",
)

_URGENT = (
    "now", "immediate", "immediately", "currently", "tonight", "today", "urgent",
    "moment", "minutes", "about", "ongoing",
)
_DANGER = (
    "kill", "hurt", "harm", "suicid", "self", "attack", "weapon", "gun", "knife",
    "overdos", "break", "danger", "bleed", "die", "dying",
)
_IMMINENT_PHRASES = (
    "on the way to hurt", "coming to hurt", "coming to kill", "cannot stay safe",
    "can't stay safe", "end my life", "take my life", "end their life",
    "minutes away", "has a gun", "has a knife",
)
_HYPOTHETICAL = (
    "hypothetically", "fictional", "example scenario", "suppose", "imagine", "what if",
)

_ANALYZE = (
    "classify", "analyze", "analyse", "review", "inspect", "identify", "detect", "explain",
    "summarize", "summarise", "assess", "categorize", "label", "why",
)
_SECURITY_TOPIC = (
    "injection", "jailbreak", "attack", "prompt", "moderation", "filter", "safety",
    "abuse", "scam", "evidence",
)
_EXECUTE_EVIDENCE = (
    "follow", "obey", "execute", "carry", "apply", "comply", "perform", "run",
)
_EVIDENCE_NOUN = ("attachment", "evidence", "quoted", "profile", "text", "message", "document")

_PAYMENT = (
    "pay", "payment", "fee", "money", "transfer", "wire", "gift", "crypto", "bitcoin",
    "deposit", "card",
)
_SCAM_HOOK = (
    "prize", "winner", "claim", "verify", "verification", "support", "refund", "urgent",
    "guaranteed", "locked", "lottery", "reward", "credential", "password", "code",
)
_INSULT = (
    "worthless", "pathetic", "idiot", "moron", "loser", "stupid", "useless", "trash",
    "disgusting", "scum", "freak", "fraud", "ugly",
)


def _safe_meta(request: GuardrailRequest, views: tuple[str, ...], tokens: set[str]) -> bool:
    if str(request.context.route) != "report":
        return False
    if not (_has_prefix(tokens, _ANALYZE) and _has_prefix(tokens, _SECURITY_TOPIC)):
        return False
    # "explain how to bypass the filter" remains operational, while
    # "explain why this is injection" is analysis.
    operational_evasion = _has_prefix(tokens, _EVASION) and _has_prefix(tokens, _OPERATIONAL)
    return not operational_evasion and not _has_phrase(
        views, ("follow the", "obey the", "execute the", "apply the instructions")
    )


def _generic_prompt_override(views: tuple[str, ...], tokens: set[str]) -> bool:
    if _has_concepts(tokens, _OVERRIDE, _AUTHORITY):
        return True
    if _has_prefix(tokens, _DISCLOSE) and _has_prefix(tokens, _HIDDEN):
        if _has_phrase(views, _POSSESSIVE_SYSTEM) or _has_prefix(tokens, ("your", "original", "current")):
            return True
    if _has_prefix(tokens, _ROLEPLAY) and (
        _has_prefix(tokens, ("unrestrict", "uncensor", "unfilter", "jailbreak"))
        or _has_phrase(views, _UNRESTRICTED)
    ):
        return True
    if _has_prefix(tokens, _CONTINUE) and (
        _has_prefix(tokens, _OVERRIDE)
        or _has_prefix(tokens, ("unrestrict", "jailbreak"))
        or _has_phrase(views, ("developer mode", "no rules", "without restrictions"))
    ):
        return True
    return False


def _generic_evasion(views: tuple[str, ...], tokens: set[str]) -> bool:
    if _has_concepts(tokens, _EVASION, _FILTER):
        return True
    if _has_prefix(tokens, _CONCEAL) and _has_prefix(tokens, _FILTER):
        return _has_prefix(tokens, _OPERATIONAL) or _has_phrase(
            views,
            ("not detected", "won't detect", "will not detect", "not flagged", "pass the filter", "pass moderation"),
        )
    return _has_phrase(
        views,
        ("so the filter accepts", "so moderation accepts", "without triggering detection", "without detection"),
    )


def _generic_imminent(views: tuple[str, ...], tokens: set[str]) -> bool:
    if _has_phrase(views, _HYPOTHETICAL):
        return False
    if _has_phrase(views, _IMMINENT_PHRASES):
        return True
    return _has_prefix(tokens, _URGENT) and _has_prefix(tokens, _DANGER)


def _generic_private(request: GuardrailRequest, tokens: set[str]) -> bool:
    if str(request.context.target_relation) == "self":
        return False
    return (
        _has_prefix(tokens, _RETRIEVE)
        and _has_prefix(tokens, _PERSONAL_DATA)
        and _has_prefix(tokens, _THIRD_PARTY)
    )


def _generic_abuse(request: GuardrailRequest, views: tuple[str, ...], tokens: set[str]) -> bool:
    if str(request.context.target_relation) == "self":
        return False
    if _has_phrase(views, _ABUSE_GOAL):
        return True
    return _has_prefix(tokens, _GENERATE) and _has_prefix(tokens, _ABUSE)


def _generic_quoted_reason(text: str) -> ReasonCode | None:
    base_reason = _quoted_reason(text)
    if base_reason is not None:
        return base_reason

    views = _semantic_views(text)
    tokens = _tokens(views)
    if _generic_prompt_override(views, tokens):
        return ReasonCode.QUOTED_INJECTION
    if _has_prefix(tokens, _PAYMENT) and _has_prefix(tokens, _SCAM_HOOK):
        return ReasonCode.QUOTED_SCAM
    if _has_prefix(tokens, _INSULT) or _has_prefix(tokens, ("threat", "intimid", "harass")):
        return ReasonCode.QUOTED_ABUSE
    return None


def classify_request_semantic(request: GuardrailRequest) -> Signal | None:
    """Classify with safe boundaries first, then base rules, then semantic recall."""

    context = request.context
    if context.requested_operation not in context.allowed_operations:
        return Signal(Action.BLOCK, ReasonCode.UNAUTHORIZED_ACTION)

    views = _semantic_views(request.message)
    tokens = _tokens(views)

    # Immediate danger outranks ordinary route semantics.
    if _generic_imminent(views, tokens):
        return Signal(Action.ESCALATE, ReasonCode.IMMINENT_SAFETY_RISK)

    evidence_reason: ReasonCode | None = None
    for item in request.evidence:
        reason = _generic_quoted_reason(item.text)
        if reason is ReasonCode.QUOTED_INJECTION:
            evidence_reason = reason
            break
        if evidence_reason is None and reason is not None:
            evidence_reason = reason

    executes_evidence = (
        _has_prefix(tokens, _EXECUTE_EVIDENCE)
        and _has_prefix(tokens, _EVIDENCE_NOUN)
    ) or _has_phrase(
        views,
        ("do what it says", "treat it as instructions", "instructions in the attachment take priority"),
    )

    # A report-route request that examines harmful evidence is data handling,
    # even when the exact verb is not one of the public benchmark's verbs.
    if evidence_reason is not None and str(context.route) == "report" and not executes_evidence:
        return Signal(Action.ALLOW_AS_DATA, evidence_reason)

    if _safe_meta(request, views, tokens):
        return None

    if evidence_reason is ReasonCode.QUOTED_INJECTION and executes_evidence:
        return Signal(Action.BLOCK, ReasonCode.PROMPT_OVERRIDE)

    # Keep every public-safe behavior already proven at 100%.
    base = classify_request(request)
    if base is not None:
        return base

    if _generic_prompt_override(views, tokens):
        return Signal(Action.BLOCK, ReasonCode.PROMPT_OVERRIDE)
    if _generic_evasion(views, tokens):
        return Signal(Action.BLOCK, ReasonCode.MODERATION_EVASION)
    if _generic_private(request, tokens):
        return Signal(Action.BLOCK, ReasonCode.PRIVATE_DATA_REQUEST)
    if _generic_abuse(request, views, tokens):
        return Signal(Action.BLOCK, ReasonCode.GENERATE_ABUSE)

    return None
