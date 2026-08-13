"""Conservative benign-intent gates for trusted routes."""
from __future__ import annotations

from common import GuardrailRequest
from guardrail.defense import _plain

_POLICY_MARKERS = ("policy", "rule", "allowed", "permitted", "prohibited", "violate", "what counts as")
_POLICY_TOPICS = ("harassment", "abuse", "scam", "fraud", "prompt injection", "moderation", "personal data", "private data", "phone number", "address", "identity", "report", "safety")
_OPERATIONAL = ("steps to", "method to", "help me", "rewrite so", "rephrase so", "encode so", "give me", "find their", "tell me their", "follow the attached", "execute the attached")
_ACCOUNT_TERMS = ("account", "password", "login", "sign in", "2fa", "mfa", "authenticator", "recovery", "session", "device", "security key", "suspicious login")
_ACCOUNT_ACTIONS = ("secure", "protect", "recover", "reset", "change", "sign out", "remove", "revoke", "enable", "disable", "check", "review", "what should i do")
_PHYSICAL_DANGER = ("suicide", "self harm", "weapon", "gun", "knife", "attacking me", "outside my door", "overdose", "bleeding heavily", "cannot breathe", "can't breathe", "about to hurt", "about to kill")
_APPEAL_TERMS = ("appeal", "review decision", "review the decision", "why was", "content removed", "post removed", "account suspended", "account restricted", "moderation decision", "reconsider")
_ORDINARY_SUPPORT = ("language settings", "notification settings", "profile preference", "profile settings", "change my language", "update my profile", "privacy settings", "display settings")


def _has(text: str, phrases: tuple[str, ...]) -> bool:
    return any(p in text for p in phrases)


def is_high_confidence_utility(request: GuardrailRequest) -> bool:
    c = request.context
    if c.requested_operation not in c.allowed_operations or request.evidence:
        return False
    text = _plain(request.message)
    if _has(text, _OPERATIONAL):
        return False
    route = str(c.route)
    if route == "report":
        questionish = "?" in request.message or text.startswith(("is ", "are ", "can ", "may ", "does ", "what ", "when ", "why ", "should "))
        return questionish and _has(text, _POLICY_MARKERS) and _has(text, _POLICY_TOPICS)
    if route == "account_safety":
        return not _has(text, _PHYSICAL_DANGER) and _has(text, _ACCOUNT_TERMS) and _has(text, _ACCOUNT_ACTIONS)
    if route == "appeal":
        return _has(text, _APPEAL_TERMS)
    if route == "general" and str(c.target_relation) == "self":
        return _has(text, _ORDINARY_SUPPORT)
    return False
