"""Combine the hidden-set fallback detectors in one conservative stage."""
from __future__ import annotations

from common import GuardrailRequest
from guardrail.detectors import Signal
from guardrail.encoded_defense import classify_encoded_obfuscation
from guardrail.ngram_defense import classify_ngram_fallback


def classify_hidden_fallback(request: GuardrailRequest) -> Signal | None:
    signal = classify_encoded_obfuscation(request)
    if signal is not None:
        return signal
    return classify_ngram_fallback(request)
