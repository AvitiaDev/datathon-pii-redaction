"""End-to-end PII detection and redaction pipeline."""

from typing import Any, Dict

from .detection import detect_pii_regex
from .policies import RedactionPolicy
from .redaction import redact_text


class PIIRedactor:
    """Detect PII in text and redact it according to configured policies."""

    def __init__(self, policy: RedactionPolicy = None, detector=None, audit_log=None):
        self.policy = policy if policy is not None else RedactionPolicy()
        # Any callable text -> detections (regex, ML, or hybrid).
        self.detector = detector if detector is not None else detect_pii_regex
        # Optional src.audit.AuditLog: records a signed, PII-free event per call.
        self.audit_log = audit_log

    def process_text(self, text: str) -> Dict[str, Any]:
        """Return redacted text and metadata without original PII values."""
        if not isinstance(text, str):
            raise TypeError("text must be a string")

        detections = self.detector(text)
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

        if self.audit_log is not None:
            self.audit_log.record(
                text, redacted_text, detections,
                detector=getattr(self.detector, "__name__", "custom"),
            )

        return {
            "redacted_text": redacted_text,
            "detections": metadata,
            "detection_count": len(metadata),
        }
