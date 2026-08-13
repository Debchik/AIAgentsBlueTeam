"""Orchestration for the competition guardrail."""

from __future__ import annotations

from collections.abc import Sequence

from common import GuardrailDecision, GuardrailRequest
from guardrail.detectors import Detector, OrderedKeywordDetector, Signal
from guardrail.normalization import normalize_text
from guardrail.policy import StarterPolicy
from guardrail.semantic_defense import classify_request_semantic
from guardrail.separator_defense import classify_separator_obfuscation
from guardrail.vector_detector import create_starter_prototype_detector


class StarterGuardrail:
    """Classify requests while preserving the starter injectable test surface."""

    def __init__(
        self,
        detectors: Sequence[Detector] | None = None,
        policy: StarterPolicy | None = None,
    ) -> None:
        self._uses_default_pipeline = detectors is None
        self._detectors = (
            tuple(detectors)
            if detectors is not None
            else (
                OrderedKeywordDetector(),
                create_starter_prototype_detector(),
            )
        )
        self._policy = policy or StarterPolicy()

    def check(self, request: GuardrailRequest) -> GuardrailDecision:
        if self._uses_default_pipeline:
            signal = classify_request_semantic(request)
            if signal is None:
                signal = classify_separator_obfuscation(request)
            signals = () if signal is None else (signal,)
            return self._policy.decide(signals, request.context.route)

        views = [normalize_text(request.message)]
        views.extend(normalize_text(evidence.text) for evidence in request.evidence)
        flattened = " ".join(view.control_stripped for view in views)

        signals: list[Signal] = []
        for detector in self._detectors:
            signal = detector.detect(flattened)
            if signal is not None:
                signals.append(signal)

        return self._policy.decide(signals, request.context.route)
