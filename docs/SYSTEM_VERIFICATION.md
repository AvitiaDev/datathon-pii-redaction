# System Verification Reference

This document describes the document-verification subsystem of the PII
Redaction Pipeline: the local format validators, external API provider stubs,
the `VerificationResult` datatype, and known limitations.

---

## Table of Contents

1. [Design Goals](#design-goals)
2. [VerificationResult dataclass](#verificationresult-dataclass)
3. [Local Format Validators](#local-format-validators)
   - [CURP](#curp)
   - [RFC](#rfc)
   - [INE Credential Key](#ine-credential-key)
4. [Two-Digit-Year Century Heuristic](#two-digit-year-century-heuristic)
5. [External Providers](#external-providers)
   - [RENAPOProvider](#renapoprovider)
   - [MetamapIDProvider (Truora stub)](#metamapidprovider-truora-stub)
6. [Facade: run_document_checks](#facade-run_document_checks)
7. [What Verification Does NOT Confirm](#what-verification-does-not-confirm)
8. [Configuration](#configuration)
9. [Test Coverage](#test-coverage)
10. [Adding a New Provider](#adding-a-new-provider)

---

## Design Goals

1. **Never claim more than what is tested.** A local format check reaching
   `inconclusive` is explicitly different from `verified`.
2. **No PII in logs or error messages.** All summaries use counts, types, and
   status codes — never the raw document value.
3. **Graceful degradation.** Unconfigured providers return `unavailable`
   immediately without making any network requests.
4. **Testable without external services.** The full validator suite runs under
   `python3 -m unittest` with no API keys.

---

## VerificationResult dataclass

Defined in [`app/verification.py`](../app/verification.py).

```python
@dataclass
class VerificationResult:
    provider: str          # e.g. "local_format_check", "renapo_curp", "truora"
    status: str            # see table below
    summary: str           # human-readable; must NOT contain the raw value
    checks_performed: list[str]
    timestamp: str         # ISO-8601 UTC
    details: dict          # internal; excluded from as_dict()
```

### Status values

| Status | Meaning |
|--------|---------|
| `verified` | External provider confirmed the identifier exists in a registry |
| `not_verified` | Structural error found (wrong length, bad check digit, impossible date) or external provider returned no match |
| `inconclusive` | All local checks passed but no registry lookup was performed |
| `unavailable` | Provider not configured or not reachable |
| `error` | Unexpected failure (network timeout, malformed response, exception) |

### `as_dict()`

Returns a serialisable dict **excluding** `details` (which may contain
provider-specific fields that could inadvertently expose sensitive data).

Fields returned: `provider`, `status`, `summary`, `checks_performed`,
`timestamp`.

---

## Local Format Validators

All local validators are in `app/verification.py` and share the same contract:

- Input: a string value (stripped and uppercased internally)
- Output: a `VerificationResult` with `provider="local_format_check"`
- Maximum status: `inconclusive` — local checks can never return `verified`

### CURP

**Function:** `validate_curp_format(curp: str) -> VerificationResult`

**Official specification:** RENAPO CURP layout (18 characters):

```
Position  0-3   Initial consonants (surname, name, consonant extraction)
Position  4-5   Birth year (YY, two digits)
Position  6-7   Birth month (MM)
Position  8-9   Birth day (DD)
Position 10     Sex (H = hombre/male, M = mujer/female)
Position 11-12  State of birth (two-letter code)
Position 13-15  Three consonants from full name
Position 16     Differentiating consonant or digit
Position 17     Check digit (0–9)
```

**Validation steps (in order):**

| Step | Check performed | Failure status |
|------|----------------|----------------|
| 1 | Length = 18 | `not_verified` |
| 2 | Regex pattern `^[A-Z]{4}\d{6}[HM][A-Z]{2}[B-DF-HJ-NP-TV-Z]{3}[A-Z0-9]\d$` | `not_verified` |
| 3 | RENAPO check digit algorithm (position 17) | `not_verified` |
| 4 | Date plausibility: `datetime(year, mm, dd)` must not raise `ValueError` | `not_verified` |
| — | All pass | `inconclusive` |

### RFC

**Function:** `validate_rfc_format(rfc: str) -> VerificationResult`

**SAT specification:** 12 characters (moral/legal entities) or 13 characters
(physical persons). Homoclave is 3 characters; check digit is the 13th character
for physical persons.

**Validation steps:**

| Step | Check performed |
|------|----------------|
| 1 | Length ∈ {12, 13} |
| 2 | Regex pattern `^[A-Z&Ñ]{3,4}\d{6}[A-NP-Z1-9][A-Z1-9][0-9A]$` |
| 3 | SAT check digit (13-char only; derived from a position-weighted sum mod 11) |

### INE Credential Key

**Function:** `validate_ine_format(ine: str) -> VerificationResult`

**INE specification:** 18 characters, pattern `LLLLLLDDDDDDDDXDDD`
(6 letters, 8 digits, sex indicator H/M, 3 digits).

No check digit algorithm is public for INE credential keys; validation stops at
the regex pattern check.

---

## Two-Digit-Year Century Heuristic

CURP encodes birth year as two digits (YY, positions 4–5).  Because a CURP does
not embed a century marker, a heuristic is required:

```python
# app/verification.py ~line 106
year = 2000 + yy if yy <= 9 else 1900 + yy
```

### Behaviour by range

| YY value | Computed year | Notes |
|----------|--------------|-------|
| 00 | 2000 | ✅ Correct for persons born 2000 |
| 01–09 | 2001–2009 | ✅ Correct for persons born 2001–2009 |
| 10–99 | 1910–1999 | ⚠️ Always mapped to 1900s |

### Known limitation

People born in 2010 or later have YY values of `10`–`99`.  The heuristic maps
these to 1910–1999. The computed year is wrong (e.g. 2015 → 1915), but the
calendar date is valid (1915-01-01 is a real date), so `datetime()` does not
raise `ValueError`. Validation reaches `inconclusive` without detecting the
century error.

**Consequence:** A CURP for a person born in 2015 passes all local format
checks and returns `inconclusive` — which is still correct behaviour, because
`inconclusive` only means "structure is valid", not "registry confirmed".
The correct birth year can only be confirmed by a RENAPO registry lookup.

### What the heuristic correctly detects

The date-plausibility check **does** catch genuinely impossible calendar dates:

- Month 00 or 13+ (filtered by the regex before reaching the date check)
- Day 00 (invalid in `datetime`)
- Day 30 in February (e.g. `AAAA300230HDFRRT07` returns `not_verified`)
- Day 29 in February of a non-leap year

### Regression tests

`TestCURPDateExtraction` in `tests/test_ui_pipeline.py` covers:

- `test_impossible_date_feb30_is_rejected` — `AAAA300230HDFRRT07` → `not_verified`
- `test_date_check_fires_after_check_digit` — ordering of checks_performed
- `test_demo_curp_date_passes_plausibility` — demo CURP `MAHA900515MCHRRN03` → `inconclusive`
- `test_century_heuristic_2000s_cutoff` — YY=09 → 2009, no date error
- `test_century_heuristic_documented_limitation` — YY=15 → 1915, still calendar-valid → no date error

---

## External Providers

### RENAPOProvider

**Class:** `RENAPOProvider` in `app/verification.py`

**What it would verify:** Existence of a CURP in the national civil registry
(RENAPO — Registro Nacional de Población).

**Why it is unavailable by default:**

The official RENAPO consultation API (`gob.mx/curp`) is a captcha-protected
web portal, not a public REST API. API access requires an **institutional
agreement with RENAPO/SEGOB**. There is no developer sandbox or self-service
registration. Attempting to scrape or automate the portal violates RENAPO's
terms of service and privacy notice.

> Reference:
> https://www.gob.mx/segob/renapo/articulos/renapo-firma-convenio-de-coordinacion-con-la-universidad-de-guadalajara-para-otorgarle-servicios-web-de-curp

**Configuration:**

```bash
export RENAPO_API_KEY="<key from institutional agreement>"
export RENAPO_API_URL="<endpoint from institutional agreement>"
export RENAPO_API_TIMEOUT=10   # optional, default 10s
```

**Behaviour without credentials:** Returns `unavailable` immediately; no HTTP
request is made.

**Response interpretation (when configured):**

The provider maps the API response field `exists` / `found` / `valid` to
`verified` (True), `not_verified` (False), or `inconclusive` (absent/unknown).

### MetamapIDProvider (Truora stub)

**Class:** `MetamapIDProvider` in `app/verification.py`

**What it would verify:** CURP and RFC existence via the Truora commercial API,
which routes requests to RENAPO and SAT sources respectively.

**Why Truora was selected:**

Among evaluated providers (Veriff, Truora, IDnow), Truora offers:

- Native LATAM coverage including CURP, RFC, NSS, INE lookups
- Documented REST API with developer sandbox
- No requirement for a direct RENAPO institutional agreement (Truora holds the
  integration)
- Per-check pricing with a developer tier

**Configuration:**

```bash
export TRUORA_API_KEY="<key from https://dashboard.truora.com>"
export TRUORA_API_URL="https://api.checks.truora.com"  # verified 2026-10
export TRUORA_API_TIMEOUT=10                            # optional, default 10s
```

**Behaviour without credentials:** Returns `unavailable` immediately; no HTTP
request is made.

**Endpoint called (when configured):** `POST /v1/checks`

> **⚠️ UNVERIFIED SCHEMA (as of 2026-10):**
> The request payload and response mapping below could NOT be fully verified
> against Truora's live documentation. The items marked `[UNVERIFIED]` require
> re-validation against current Truora docs before enabling live requests.

**Request payload (PARTIALLY UNVERIFIED):**

The Truora Checks API documented required fields are `country`, `type` (enum:
`person|vehicle|company`), and `user_authorized` (bool). The `national_id`
field is documented. The fields `check_type` and `national_id_type` were
**not found** in the official schema; the current stub uses them but they may
cause API errors. The verified `Content-Type` per docs is
`application/x-www-form-urlencoded`.

```json
{
  "check_type": "national_id",   // [UNVERIFIED: may not be a valid field]
  "country": "MX",               // [VERIFIED]
  "national_id": "<value>",      // [VERIFIED]
  "national_id_type": "CURP"     // [UNVERIFIED: may not be a valid field]
}
```

**Response status mapping (PARTIALLY UNVERIFIED):**

The documented top-level check `status` values are:
`not_started | in_progress | completed | error | delayed`.

> **Note:** `not_found` is a **dataset-level** status (inside `statuses[]`),
> not the top-level `check.status`. The mapping below may be incorrect for
> the "record not found" case; it must be validated with a live sandbox test.

| Truora `check.status` | VerificationResult status | Verified? |
|-----------------------|--------------------------|-----------|
| `completed` | `verified` | ✅ documented final status |
| `not_found` | `not_verified` | ⚠️ [UNVERIFIED: not a top-level status] |
| `error` | `error` | ✅ documented final status |
| anything else | `inconclusive` | — fallback |

**Error handling:** Timeouts → `error` with `"timed out"` in summary. JSON
parse errors → `error`. Network errors → `error` with `type(exc).__name__`.
The raw CURP/RFC value never appears in error summaries.

**Mock tests available** (no API key required):

- `test_mocked_success_response` — simulates `completed` → `verified`
- `test_mocked_not_found_response` — simulates `not_found` → `not_verified`
- `test_mocked_timeout` — simulates `TimeoutError` → `error`
- `test_mocked_malformed_response` — simulates HTML error page → `error`

> These mock tests validate the *current stub's behaviour*, not that the stub
> correctly implements the Truora API protocol.

---

## Facade: run_document_checks

```python
run_document_checks(entity_type: str, value: str) -> dict[str, VerificationResult]
```

Runs all applicable checks for a given entity type and returns a dictionary
of `{check_name: VerificationResult}`.

| Entity type | Checks returned |
|-------------|----------------|
| `CURP` | `format_check`, `renapo_lookup`, `truora_lookup` |
| `RFC` | `format_check`, `truora_lookup` |
| `ID_NUMBER` | `ine_format_check` (if 18-char INE pattern) or `id_format_check` (otherwise) |
| anything else | `format_check` with status `unavailable` |

The raw value is passed to each check but never logged or included in results.

---

## What Verification Does NOT Confirm

Even a `verified` result from an external provider does **not** confirm:

- The document is authentic (not forged or altered)
- The document belongs to the person presenting it
- The document is currently valid (not expired or revoked)
- Any biometric match (face, fingerprint, liveness)
- The person's current address, employment, or identity attributes beyond the
  registry record

A `verified` status from this pipeline means only: *"the identifier was found
in the specified external registry at the time of the query."*

An `inconclusive` status from a local format check means only: *"the
identifier is structurally plausible."*

**Always disclose these limitations to end users and downstream systems.**

---

## Configuration

Summary of all supported environment variables:

| Variable | Provider | Required | Default | Description |
|----------|----------|----------|---------|-------------|
| `RENAPO_API_KEY` | RENAPOProvider | For live use | — | Bearer token from institutional agreement |
| `RENAPO_API_URL` | RENAPOProvider | For live use | — | API endpoint from institutional agreement |
| `RENAPO_API_TIMEOUT` | RENAPOProvider | No | `10` | Request timeout in seconds |
| `TRUORA_API_KEY` | MetamapIDProvider | For live use | — | API key from dashboard.truora.com |
| `TRUORA_API_URL` | MetamapIDProvider | No | `https://api.checks.truora.com` | Base URL (verified 2026-10) |
| `TRUORA_API_TIMEOUT` | MetamapIDProvider | No | `10` | Request timeout in seconds |

Credentials are read at call time from `os.environ`. They can also be set via
Streamlit secrets (`st.secrets`) if the UI is deployed on Streamlit Cloud;
the current implementation reads `os.environ` only — Streamlit secrets
integration is left as a future enhancement.

---

## Test Coverage

`tests/test_ui_pipeline.py` contains the following test classes for
verification:

| Class | Tests |
|-------|-------|
| `TestCURPValidation` | Length, pattern, check digit, provider label, `as_dict` schema |
| `TestCURPDateExtraction` | Impossible date (Feb 30), check ordering, demo CURP, century heuristic |
| `TestRFCValidation` | Length, pattern, check digit, not claimed verified |
| `TestINEValidation` | Length, pattern, provider label |
| `TestRENAPOProvider` | Unavailable without credentials, summary wording, no HTTP call |
| `TestTruoraProvider` | Unavailable, mocked success/not-found/timeout/malformed |
| `TestRunDocumentChecks` | All entity types, result types, no verified without API |
| `TestNoLeakInErrorMessages` | CURP/RFC not in error summaries, no raw text in metadata |

Run all tests:

```bash
python3 -m unittest discover -s tests -v
```

Expected output: **118 tests, 0 failures, 0 errors**.

---

## Adding a New Provider

1. Add a class to `app/verification.py` following the pattern of
   `RENAPOProvider` or `MetamapIDProvider`:
   - `_is_configured()` classmethod — returns `bool`
   - `verify(value)` or `verify_<type>(value)` classmethod — returns `VerificationResult`
   - Never log the raw `value` in any branch
   - Return `unavailable` immediately if `_is_configured()` is False

2. Wire it into `run_document_checks()` by adding a new key to the results dict
   for the relevant entity type.

3. Add unit tests:
   - `test_returns_unavailable_without_credentials`
   - `test_no_network_call_without_credentials` (using `patch("urllib.request.urlopen")`)
   - At least one mocked success and one mocked failure/error response

4. Update this document and `docs/UI.md`.
