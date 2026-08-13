"""Decode additional text obfuscations before normal classification."""
from __future__ import annotations

import base64
import re

from common import Action, GuardrailRequest
from guardrail.detectors import Signal
from guardrail.semantic_defense import classify_request_semantic
from guardrail.separator_defense import classify_separator_obfuscation

_B32 = re.compile(r"(?<![A-Z2-7=])[A-Z2-7]{16,}={0,6}(?![A-Z2-7=])", re.I)
_BINARY = re.compile(r"(?:\b[01]{8}\b[\s,:;|_-]*){6,}")
_CODEPOINT = re.compile(r"(?:U\+[0-9A-Fa-f]{4,6}[\s,:;|_-]*){6,}", re.I)
_OCTAL = re.compile(r"(?:\\[0-7]{3}){6,}")
_DECIMAL = re.compile(r"(?:\b(?:3[2-9]|[4-9][0-9]|1[01][0-9]|12[0-6])\b[\s,:;|_-]*){6,}")


def _printable(data: bytes) -> str | None:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if len(text) < 6:
        return None
    good = sum(ch.isprintable() or ch.isspace() for ch in text)
    return text if good / len(text) >= 0.92 else None


def _decode_candidates(text: str) -> tuple[str, ...]:
    out: list[str] = []
    for m in _B32.finditer(text):
        token = m.group().upper() + "=" * (-len(m.group()) % 8)
        try:
            decoded = _printable(base64.b32decode(token, casefold=True))
        except Exception:
            decoded = None
        if decoded:
            out.append(decoded)
    for m in _BINARY.finditer(text):
        decoded = _printable(bytes(int(x, 2) for x in re.findall(r"[01]{8}", m.group())))
        if decoded:
            out.append(decoded)
    for m in _CODEPOINT.finditer(text):
        try:
            decoded = "".join(chr(int(x, 16)) for x in re.findall(r"U\+([0-9A-Fa-f]{4,6})", m.group(), re.I))
        except ValueError:
            decoded = ""
        if len(decoded) >= 6:
            out.append(decoded)
    for m in _OCTAL.finditer(text):
        decoded = "".join(chr(int(x, 8)) for x in re.findall(r"\\([0-7]{3})", m.group()))
        if len(decoded) >= 6:
            out.append(decoded)
    for m in _DECIMAL.finditer(text):
        nums = [int(x) for x in re.findall(r"\d{2,3}", m.group())]
        decoded = "".join(chr(x) for x in nums if 32 <= x <= 126)
        if len(decoded) >= 6 and sum(ch.isalpha() or ch.isspace() for ch in decoded) / len(decoded) >= 0.7:
            out.append(decoded)
    collapsed = re.sub(r"(.)\1+", r"\1", text, flags=re.I)
    if collapsed != text:
        out.append(collapsed)
    compact = re.sub(r"[^A-Za-z]+", "", text)
    if 14 <= len(compact) <= 512:
        out.extend((compact[::2], compact[1::2]))
    return tuple(dict.fromkeys(x for x in out if x))[:12]


def classify_encoded_obfuscation(request: GuardrailRequest) -> Signal | None:
    copier = getattr(request, "model_copy", None)
    if copier is None:
        return None
    for decoded in _decode_candidates(request.message):
        clone = copier(update={"message": decoded})
        signal = classify_request_semantic(clone)
        if signal is None:
            signal = classify_separator_obfuscation(clone)
        if signal is not None and signal.action is Action.BLOCK:
            return signal
    return None
