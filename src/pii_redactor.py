"""End-to-end PII detection and redaction pipeline."""

from typing import Any, Dict

from .detection import detect_pii_regex
from .policies import RedactionPolicy
from .redaction import redact_text


class PIIRedactor:
    """Detect PII in text and redact it according to configured policies."""

    def __init__(self, policy: RedactionPolicy = None):
        self.policy = policy if policy is not None else RedactionPolicy()

    def process_text(self, text: str) -> Dict[str, Any]:
        """Return redacted text and metadata without original PII values."""
        if not isinstance(text, str):
            raise TypeError("text must be a string")

        detections = detect_pii_regex(text)
        redacted_text = redact_text(text, detections, self.policy)

        # Deliberately omit detection["text"] to avoid returning raw PII.
        metadata = [
            {
                "entity_type": detection["entity_type"],
                "start": detection["start"],
                "end": detection["end"],
                "source": detection.get("source", "unknown"),
            }
            for detection in detections
        ]

        return {
            "redacted_text": redacted_text,
            "detections": metadata,
            "detection_count": len(metadata),
        }
