"""Conservative fallback classification for quoted evidence."""
from __future__ import annotations

import re
from common import Action, GuardrailRequest, ReasonCode
from guardrail.defense import _plain
from guardrail.detectors import Signal

_WORD = re.compile(r"[a-z]+")
_ANALYZE = ("analyze", "analyse", "classify", "review", "summarize", "summarise", "inspect", "assess", "detect", "explain")
_EXECUTE = ("follow", "obey", "execute", "apply", "perform", "comply")
_EVIDENCE = ("evidence", "attachment", "attached", "quoted", "profile", "document", "text", "message")
_CONTROL_SUBJECT = ("assistant", "model", "system", "ai")
_CONTROL = ("instruction", "priority", "obey", "follow", "override", "ignore", "must", "should")
_CREDENTIAL = ("password", "passcode", "otp", "credential", "pin", "verification", "recovery", "login")
_SCAM = ("urgent", "support", "locked", "prize", "refund", "winner", "claim", "payment", "fee", "gift", "crypto", "transfer")
_PAYMENT = ("pay", "payment", "fee", "money", "transfer", "wire", "gift", "crypto", "deposit")
_HOOK = ("prize", "winner", "claim", "verify", "support", "refund", "urgent", "locked")
_ABUSE = ("worthless", "pathetic", "idiot", "moron", "loser", "stupid", "useless", "trash", "disgusting", "threat", "intimidate", "harass", "hurt", "die")


def _tokens(text: str) -> set[str]:
    return set(_WORD.findall(_plain(text)))


def _has(tokens: set[str], group: tuple[str, ...]) -> bool:
    return any(token.startswith(prefix) for token in tokens for prefix in group)


def _all(tokens: set[str], *groups: tuple[str, ...]) -> bool:
    return all(_has(tokens, group) for group in groups)


def _reason(text: str) -> ReasonCode | None:
    tokens = _tokens(text)
    if _all(tokens, _CONTROL_SUBJECT, _CONTROL) and _has(tokens, ("instruction", "priority", "system", "user")):
        return ReasonCode.QUOTED_INJECTION
    if _all(tokens, _CREDENTIAL, _SCAM) or _all(tokens, _PAYMENT, _HOOK):
        return ReasonCode.QUOTED_SCAM
    if _has(tokens, _ABUSE):
        return ReasonCode.QUOTED_ABUSE
    return None


def classify_evidence_fallback(request: GuardrailRequest) -> Signal | None:
    if not request.evidence:
        return None
    message_tokens = _tokens(request.message)
    executes = _all(message_tokens, _EXECUTE, _EVIDENCE)
    analysis = _has(message_tokens, _ANALYZE) or str(request.context.route) == "report"
    for item in request.evidence:
        reason = _reason(item.text)
        if reason is None:
            continue
        if reason is ReasonCode.QUOTED_INJECTION and executes:
            return Signal(Action.BLOCK, ReasonCode.PROMPT_OVERRIDE)
        if analysis and not executes:
            return Signal(Action.ALLOW_AS_DATA, reason)
    return None
