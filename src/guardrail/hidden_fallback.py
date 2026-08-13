"""Combine conservative hidden-set fallback detectors."""
from __future__ import annotations

from common import GuardrailRequest
from guardrail.detectors import Signal
from guardrail.encoded_defense import classify_encoded_obfuscation
from guardrail.ngram_defense import classify_ngram_fallback
from guardrail.vector_detector import create_starter_prototype_detector

_VECTOR = create_starter_prototype_detector()


def classify_hidden_fallback(request: GuardrailRequest) -> Signal | None:
    signal = classify_encoded_obfuscation(request)
    if signal is not None:
        return signal

    signal = classify_ngram_fallback(request)
    if signal is not None:
        return signal

    return _VECTOR.detect(request.message)
