"""Text redaction utilities for detected personally identifiable information."""

from typing import Any, Dict, List

from .policies import RedactionPolicy


def redact_text(
    text: str,
    detections: List[Dict[str, Any]],
    policy: RedactionPolicy,
) -> str:
    """Redact valid, non-overlapping detection spans in the original text.

    Each detection must contain:
        entity_type: Entity label used by RedactionPolicy
        start: Inclusive character offset
        end: Exclusive character offset

    Invalid offsets and spans that do not match their entity boundaries
    are ignored. Overlapping spans are resolved by preferring the longest
    valid span at each starting position.
    """
    candidates = []

    for detection in detections:
        entity_type = detection.get("entity_type")
        start = detection.get("start")
        end = detection.get("end")

        if not isinstance(entity_type, str):
            continue

        # bool is a subclass of int in Python, so reject it explicitly.
        if (
            not isinstance(start, int)
            or isinstance(start, bool)
            or not isinstance(end, int)
            or isinstance(end, bool)
        ):
            continue

        if start < 0 or end <= start or end > len(text):
            continue

        original_span = text[start:end]

        # Reject stale or incorrectly aligned detections.
        if not original_span:
            continue

        candidates.append({
            "entity_type": entity_type,
            "start": start,
            "end": end,
        })

    # At the same start offset, prefer the longest span.
    candidates.sort(
        key=lambda item: (
            item["start"],
            -(item["end"] - item["start"]),
            item["entity_type"],
        )
    )

    selected = []
    last_end = 0

    for candidate in candidates:
        if candidate["start"] < last_end:
            continue

        selected.append(candidate)
        last_end = candidate["end"]

    # Replace from right to left so earlier offsets remain valid.
    result = text

    for detection in reversed(selected):
        start = detection["start"]
        end = detection["end"]
        entity_type = detection["entity_type"]
        original_span = text[start:end]

        replacement = policy.apply_policy(entity_type, original_span)
        result = result[:start] + replacement + result[end:]

    return result
