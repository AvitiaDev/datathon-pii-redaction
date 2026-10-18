"""Verification provider abstraction.

Each provider implements:
  check(value: str, **kwargs) -> VerificationResult

Result states:
  verified      – provider returned a documented positive result
  not_verified  – provider returned a documented negative or mismatch
  inconclusive  – provider could not establish the requested result
  unavailable   – provider not configured or unreachable
  error         – unexpected failure

Personal data is never logged. Only counts, statuses, and safe summaries
are written to any output. API credentials are read from environment vars
or Streamlit secrets only.
"""

from __future__ import annotations

import os
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


# ── Result dataclass ─────────────────────────────────────────────────────────

@dataclass
class VerificationResult:
    provider: str
    status: str  # verified | not_verified | inconclusive | unavailable | error
    summary: str
    checks_performed: list[str] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds"))
    details: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {
            "provider": self.provider,
            "status": self.status,
            "summary": self.summary,
            "checks_performed": self.checks_performed,
            "timestamp": self.timestamp,
            # details excluded — may contain sensitive information
        }


# ── CURP local format validation ─────────────────────────────────────────────

# Official CURP structure from RENAPO documentation.
_CURP_RE = re.compile(r"^[A-Z]{4}\d{6}[HM][A-Z]{2}[B-DF-HJ-NP-TV-Z]{3}[A-Z0-9]\d$")
_CURP_DICT = "0123456789ABCDEFGHIJKLMN#OPQRSTUVWXYZ"


def _curp_check_digit_ok(curp: str) -> bool:
    """Validate the RENAPO check digit (position 17)."""
    if len(curp) != 18:
        return False
    try:
        s = sum(_CURP_DICT.index(ch) * (18 - i) for i, ch in enumerate(curp[:17]))
        expected = (10 - s % 10) % 10
        return int(curp[17]) == expected
    except (ValueError, IndexError):
        return False


def validate_curp_format(curp: str) -> VerificationResult:
    """Local structural validation only — not an authoritative verification."""
    curp = curp.strip().upper()
    checks = []

    if len(curp) != 18:
        return VerificationResult(
            provider="local_format_check",
            status="not_verified",
            summary=f"CURP must be 18 characters (got {len(curp)})",
            checks_performed=["length"],
        )

    checks.append("length")

    if not _CURP_RE.match(curp):
        return VerificationResult(
            provider="local_format_check",
            status="not_verified",
            summary="CURP does not match the official structural pattern",
            checks_performed=checks + ["regex_pattern"],
        )
    checks.append("regex_pattern")

    if not _curp_check_digit_ok(curp):
        return VerificationResult(
            provider="local_format_check",
            status="not_verified",
            summary="CURP check digit is invalid",
            checks_performed=checks + ["check_digit"],
        )
    checks.append("check_digit")

    # Extract date from positions 4-9 (YYMMDD) and validate plausibility.
    # CURP layout: CCCC[4] YYMMDD[4-9] X[10] EE[11-12] CCC[13-15] V[16] D[17]
    try:
        yy, mm, dd = int(curp[4:6]), int(curp[6:8]), int(curp[8:10])
        year = 2000 + yy if yy <= 9 else 1900 + yy  # heuristic: <=09 → 2000s
        datetime(year, mm, dd)
        checks.append("date_plausibility")
    except ValueError:
        return VerificationResult(
            provider="local_format_check",
            status="not_verified",
            summary="CURP contains an implausible date",
            checks_performed=checks + ["date_plausibility"],
        )

    return VerificationResult(
        provider="local_format_check",
        status="inconclusive",
        summary=(
            "CURP passes all local format checks (length, pattern, check digit, date). "
            "This is NOT an official RENAPO verification — it only confirms the structure is valid."
        ),
        checks_performed=checks,
    )


# ── RFC local format validation ───────────────────────────────────────────────

_RFC_RE = re.compile(r"^[A-Z&Ñ]{3,4}\d{6}[A-NP-Z1-9][A-Z1-9][0-9A]$")
_RFC_DICT = "0123456789ABCDEFGHIJKLMN&OPQRSTUVWXYZ"


def validate_rfc_format(rfc: str) -> VerificationResult:
    """Local SAT structural validation — not an official SAT lookup."""
    rfc = rfc.strip().upper()
    checks: list[str] = []

    if len(rfc) not in (12, 13):
        return VerificationResult(
            provider="local_format_check",
            status="not_verified",
            summary=f"RFC must be 12 (moral) or 13 (physical) characters (got {len(rfc)})",
            checks_performed=["length"],
        )
    checks.append("length")

    if not _RFC_RE.match(rfc):
        return VerificationResult(
            provider="local_format_check",
            status="not_verified",
            summary="RFC does not match the official SAT structural pattern",
            checks_performed=checks + ["regex_pattern"],
        )
    checks.append("regex_pattern")

    # Validate check digit for 13-char RFC (physical persons)
    if len(rfc) == 13:
        try:
            s = sum(_RFC_DICT.index(ch) * (13 - i) for i, ch in enumerate(rfc[:12]))
            rem = s % 11
            expected = "A" if rem == 10 else ("0" if rem == 0 else str(11 - rem))
            if rfc[12] != expected:
                return VerificationResult(
                    provider="local_format_check",
                    status="not_verified",
                    summary="RFC check digit is invalid",
                    checks_performed=checks + ["check_digit"],
                )
            checks.append("check_digit")
        except ValueError:
            pass  # character not in dict — already caught by regex above

    return VerificationResult(
        provider="local_format_check",
        status="inconclusive",
        summary=(
            "RFC passes local format checks. "
            "This is NOT an official SAT verification — it only confirms the structure."
        ),
        checks_performed=checks,
    )


# ── INE format validation ─────────────────────────────────────────────────────

_INE_RE = re.compile(r"^[A-Z]{6}\d{8}[HM]\d{3}$")


def validate_ine_format(ine: str) -> VerificationResult:
    """Local INE credential key structural check only."""
    ine = ine.strip().upper()
    checks: list[str] = []

    if len(ine) != 18:
        return VerificationResult(
            provider="local_format_check",
            status="not_verified",
            summary=f"INE credential key must be 18 characters (got {len(ine)})",
            checks_performed=["length"],
        )
    checks.append("length")

    if not _INE_RE.match(ine):
        return VerificationResult(
            provider="local_format_check",
            status="not_verified",
            summary="INE credential key does not match expected pattern (LLLLLLDDDDDDDDXDDD)",
            checks_performed=checks + ["regex_pattern"],
        )
    checks.append("regex_pattern")

    return VerificationResult(
        provider="local_format_check",
        status="inconclusive",
        summary=(
            "INE credential key passes local structural check. "
            "This does NOT verify document authenticity, biometrics, or a government record."
        ),
        checks_performed=checks,
    )


# ── RENAPO CURP external provider (unavailable — requires institutional agreement) ──

class RENAPOProvider:
    """Placeholder for the official RENAPO CURP verification web service.

    Access requires an institutional agreement with RENAPO/SEGOB.
    See: https://www.gob.mx/segob/renapo/articulos/
           renapo-firma-convenio-de-coordinacion-con-la-universidad-de-guadalajara-
           para-otorgarle-servicios-web-de-curp

    The government consultation page (https://www.gob.mx/curp/) is a web portal,
    not an API endpoint. Scraping it, bypassing CAPTCHA, or automating it via HTTP
    would violate the RENAPO terms of service (privacy notice:
    https://www.gob.mx/curp/privacidadintegral/).

    Configure with:
        RENAPO_API_KEY      — API key issued under the institutional agreement
        RENAPO_API_URL      — endpoint provided in the agreement (no default)
        RENAPO_API_TIMEOUT  — seconds (default 10)
    """

    NAME = "renapo_curp"

    @classmethod
    def _is_configured(cls) -> bool:
        return bool(os.environ.get("RENAPO_API_KEY") and os.environ.get("RENAPO_API_URL"))

    @classmethod
    def verify(cls, curp: str) -> VerificationResult:
        # External verification stays disabled until the contracted API
        # schema and response semantics have been validated.
        if os.environ.get("ENABLE_UNVERIFIED_EXTERNAL_CHECKS") != "1":
            return VerificationResult(
                provider=cls.NAME,
                status="unavailable",
                summary="External RENAPO lookup is disabled pending API contract validation.",
                checks_performed=[],
            )

        if not cls._is_configured():
            return VerificationResult(
                provider=cls.NAME,
                status="unavailable",
                summary=(
                    "RENAPO CURP verification is not configured. "
                    "Access requires an institutional agreement with RENAPO/SEGOB. "
                    "Set RENAPO_API_KEY and RENAPO_API_URL to enable."
                ),
                checks_performed=[],
            )

        # ── real call (only reached when credentials are configured) ──────────
        import json
        import urllib.request

        timeout = int(os.environ.get("RENAPO_API_TIMEOUT", "10"))
        url = os.environ["RENAPO_API_URL"]
        key = os.environ["RENAPO_API_KEY"]

        try:
            req = urllib.request.Request(
                url,
                data=json.dumps({"curp": curp}).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {key}",
                },
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))

            # Interpret the response according to the contracted API schema.
            # Status codes and fields depend on the specific agreement.
            exists = data.get("exists") or data.get("found") or data.get("valid")
            if exists is True:
                return VerificationResult(
                    provider=cls.NAME,
                    status="verified",
                    summary="RENAPO confirmed the CURP exists in the national registry.",
                    checks_performed=["renapo_registry_lookup"],
                )
            elif exists is False:
                return VerificationResult(
                    provider=cls.NAME,
                    status="not_verified",
                    summary="RENAPO returned no match for this CURP.",
                    checks_performed=["renapo_registry_lookup"],
                )
            else:
                return VerificationResult(
                    provider=cls.NAME,
                    status="inconclusive",
                    summary="RENAPO response was received but could not be interpreted.",
                    checks_performed=["renapo_registry_lookup"],
                )

        except TimeoutError:
            return VerificationResult(
                provider=cls.NAME,
                status="error",
                summary="RENAPO API request timed out.",
                checks_performed=["renapo_registry_lookup"],
            )
        except Exception as exc:
            # Never include CURP value in the error message.
            return VerificationResult(
                provider=cls.NAME,
                status="error",
                summary=f"RENAPO API request failed: {type(exc).__name__}",
                checks_performed=["renapo_registry_lookup"],
            )


# ── Metamap / generic identity API stub ──────────────────────────────────────

class MetamapIDProvider:
    """Placeholder for a commercial document-verification provider.

    Candidates evaluated (none currently configured):

    1. Veriff (https://veriff.com)
       - Supports: MX passport, INE/IFE, CURP, driver's license, plus 10,000+
         other document types globally.
       - Verification types: OCR field extraction, document authenticity
         (security features, MRZ, chip), face match, liveness.
       - API: REST, well-documented; test/sandbox environment available.
       - Pricing: per-session (pay-as-you-go); enterprise negotiated.
       - Data retention: configurable; GDPR/LGPD compliant.
       - Consent requirement: explicit end-user consent required before capture.
       - Note: requires accepting their Data Processing Agreement (DPA).

    2. Truora (https://docs.truora.com)
       - Focuses on LATAM; supports CURP, RFC, INE, NSS, and background checks
         via official Mexican government sources.
       - Plans include a developer sandbox.
       - Verification types: structured data checks against RENAPO/SAT/IMSS
         records, not document image analysis.
       - Data retention: configurable per account settings.
       - Pricing: per-check; developer tier available.
       - Note: most relevant for this project. Covers CURP/RFC/INE via APIs
         without needing direct RENAPO institutional agreement.

    3. IDnow (https://www.idnow.io)
       - Supports EU + select LATAM documents; less MX-focused.
       - Verification types: automated + assisted; eIDAS-compliant for EU.

    Chosen for initial stub: Truora, because it offers LATAM-native coverage
    including CURP, RFC, and INE lookups via documented REST endpoints,
    and a developer sandbox.

    Configure with:
        TRUORA_API_KEY       — key from https://dashboard.truora.com
        TRUORA_API_URL       — base URL (default https://api.checks.truora.com,
                               verified from https://docs.truora.com 2026-10)
        TRUORA_API_TIMEOUT   — seconds (default 10)

    IMPORTANT — UNVERIFIED REQUEST SCHEMA:
        The request payload below uses field names (check_type, national_id_type)
        and Content-Type (application/json) that could NOT be independently
        confirmed against Truora's live documentation as of 2026-10.
        The verified documented fields for POST /v1/checks are:
          country (enum, required), type (enum, required), national_id (string),
          user_authorized (boolean, required).
        Content-Type per docs is application/x-www-form-urlencoded.
        The fields check_type and national_id_type do NOT appear in the official
        schema. This stub must be re-validated against Truora's current API
        before enabling live requests.
    """

    NAME = "truora"

    @classmethod
    def _is_configured(cls) -> bool:
        return bool(os.environ.get("TRUORA_API_KEY"))

    @classmethod
    def verify_curp(cls, curp: str) -> VerificationResult:
        if not cls._is_configured():
            return VerificationResult(
                provider=cls.NAME,
                status="unavailable",
                summary=(
                    "Truora CURP check not configured. "
                    "Set TRUORA_API_KEY to enable. "
                    "See https://docs.truora.com for sandbox credentials."
                ),
                checks_performed=[],
            )
        return cls._check("curp", curp)

    @classmethod
    def verify_rfc(cls, rfc: str) -> VerificationResult:
        if not cls._is_configured():
            return VerificationResult(
                provider=cls.NAME,
                status="unavailable",
                summary="Truora RFC check not configured. Set TRUORA_API_KEY.",
                checks_performed=[],
            )
        return cls._check("rfc", rfc)

    @classmethod
    def _check(cls, doc_type: str, value: str) -> VerificationResult:
        # The Truora request and response schema is not validated. Do not
        # make live requests unless explicitly enabled for controlled testing.
        if os.environ.get("ENABLE_UNVERIFIED_EXTERNAL_CHECKS") != "1":
            return VerificationResult(
                provider=cls.NAME,
                status="unavailable",
                summary="External Truora lookup is disabled pending API contract validation.",
                checks_performed=[],
            )

        import json
        import urllib.request

        # Base URL verified from docs.truora.com (2026-10): api.checks.truora.com
        # The previous default of "https://api.truora.com" was incorrect.
        base = os.environ.get("TRUORA_API_URL", "https://api.checks.truora.com").rstrip("/")
        key = os.environ["TRUORA_API_KEY"]
        timeout = int(os.environ.get("TRUORA_API_TIMEOUT", "10"))
        endpoint = f"{base}/v1/checks"
        # UNVERIFIED SCHEMA: field names check_type and national_id_type were not
        # found in Truora's documented API as of 2026-10.  Verified fields are:
        # country, type (enum: person|vehicle|company), national_id, user_authorized.
        # This payload must be re-validated before enabling live requests.
        payload = {
            "check_type": "national_id",   # [UNVERIFIED: not in docs; may be 'type']
            "country": "MX",
            "national_id": value,
            "national_id_type": doc_type.upper(),  # [UNVERIFIED: not in docs]
        }
        try:
            req = urllib.request.Request(
                endpoint,
                data=json.dumps(payload).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "Truora-API-Key": key,
                },
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))

            # UNVERIFIED RESPONSE MAPPING: Truora top-level check statuses are:
            # not_started | in_progress | completed | error | delayed.
            # "not_found" is a dataset-level status, not the top-level status.
            # Mapping "not_found" to not_verified is therefore likely incorrect;
            # a completed check with no matching record may still return "completed"
            # with dataset-level details.  This mapping must be re-validated.
            # A completed check only means processing finished. Without a
            # validated outcome schema, neither completed nor not_found can
            # establish that the submitted identity was verified.
            status_map = {
                "error": "error",
            }
            api_status = data.get("check", {}).get("status", "unknown")
            status = status_map.get(api_status, "inconclusive")
            return VerificationResult(
                provider=cls.NAME,
                status=status,
                summary=f"Truora {doc_type.upper()} check status: {api_status}",
                checks_performed=[f"truora_{doc_type}_lookup"],
            )

        except TimeoutError:
            return VerificationResult(
                provider=cls.NAME, status="error",
                summary=f"Truora API request timed out ({timeout}s)",
                checks_performed=[f"truora_{doc_type}_lookup"],
            )
        except Exception as exc:
            return VerificationResult(
                provider=cls.NAME, status="error",
                summary=f"Truora API error: {type(exc).__name__}",
                checks_performed=[f"truora_{doc_type}_lookup"],
            )


# ── Facade ────────────────────────────────────────────────────────────────────

def run_document_checks(entity_type: str, value: str) -> dict[str, VerificationResult]:
    """Run all applicable checks for a given entity type.

    Returns a dict of {check_name: VerificationResult}.
    Never logs the raw value.
    """
    results: dict[str, VerificationResult] = {}

    if entity_type == "CURP":
        results["format_check"] = validate_curp_format(value)
        results["renapo_lookup"] = RENAPOProvider.verify(value)
        results["truora_lookup"] = MetamapIDProvider.verify_curp(value)

    elif entity_type == "RFC":
        results["format_check"] = validate_rfc_format(value)
        results["truora_lookup"] = MetamapIDProvider.verify_rfc(value)

    elif entity_type == "ID_NUMBER":
        # INE voter key (18 chars matching INE pattern)
        if len(value) == 18 and _INE_RE.match(value.upper()):
            results["ine_format_check"] = validate_ine_format(value)
        else:
            results["id_format_check"] = VerificationResult(
                provider="local_format_check",
                status="inconclusive",
                summary="No local format rule for this ID_NUMBER subtype.",
                checks_performed=[],
            )

    else:
        results["format_check"] = VerificationResult(
            provider="local_format_check",
            status="unavailable",
            summary=f"No verification checks defined for entity type '{entity_type}'.",
            checks_performed=[],
        )

    return results
