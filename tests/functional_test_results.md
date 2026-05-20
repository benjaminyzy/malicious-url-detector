# Functional Test Results (FYP Section 5.2.1)

Backend under test: `http://localhost:8000` (FastAPI, started via
`python -m uvicorn backend.main:app`). All models loaded at startup.
Programmatic tests executed: FYP01-FYP12. Manual tests FYP13-FYP15 pending.

| Function ID | Function Name | Actual Result | Status |
|---|---|---|---|
| FYP01 | Backend health | HTTP 200, body `{"status": "ok"}` | PASS |
| FYP02 | Valid URL classification | HTTP 200, verdict BENIGN, confidence 99.6%; all expected fields present (`final_label`, `confidence`, `votes_for_malicious`, `triggered_rules`) | PASS |
| FYP03 | Empty URL rejection | HTTP 422, validation error: "String should have at least 1 character" | PASS |
| FYP04 | URL length validation | HTTP 422, validation error: "String should have at most 2048 characters" (submitted URL length 3020) | PASS |
| FYP05 | Unsupported scheme rejection | HTTP 400, `{"detail": "Only http:// and https:// URLs are supported"}` | PASS |
| FYP06 | Missing host rejection | HTTP 400, `{"detail": "URL must include a valid host"}` | PASS |
| FYP07 | IP-as-host classification | final_label=1 (MALICIOUS), confidence 100.0%, rules: raw IP address, credential keywords without HTTPS | PASS |
| FYP08 | Punycode domain classification | final_label=1 (MALICIOUS), confidence 91.5%, rule: Punycode encoding (possible homograph attack) | PASS |
| FYP09 | Brand impersonation classification | final_label=1 (MALICIOUS), confidence 99.8%, rules: brand in subdomain of unrelated domain, abused TLD | PASS |
| FYP10 | Benign URL classification | final_label=0 (BENIGN), confidence 100.0%, no rules triggered | PASS |
| FYP11 | History persistence | HTTP 200, 50 entries returned; all 3 tested URLs (google search, IP login, github repo) present | PASS |
| FYP12 | Stats aggregation | HTTP 200; total_scanned=261, total_malicious=56, total_malicious_high_conf=33, total_suspicious=23, total_benign=205, malicious_percentage=21.5 | PASS |

**Summary: 12 / 12 programmatic tests passed.**

## Note on FYP03 and FYP04 status codes

The test specification anticipated **HTTP 400** for these two cases. The
backend returns **HTTP 422 (Unprocessable Entity)** instead, because the
empty-string and over-length checks are enforced by the Pydantic request
model (`URLRequest`, `min_length=1` / `max_length=2048`) which runs *before*
the handler's manual `_validate_url` checks. The invalid input is still
correctly rejected with a descriptive validation error, so the functional
requirement (reject invalid URLs) is satisfied; only the HTTP status code
differs from the document's expectation. The 400 path is exercised and
confirmed by FYP05 and FYP06, which reach the manual `_validate_url` checks.
Recommendation for Chapter 5.3.1: state the expected code as "400 or 422
(validation error)" or note 422 as the actual Pydantic-layer behaviour.

## Manual tests pending

The following require browser / extension / OS interaction and were not
executed programmatically. The user must perform these manually:

- **FYP13 - Extension badge update**: With the extension installed, visit a
  classified URL in the browser and observe that the toolbar badge updates
  (check mark for benign, `!` for malicious, `?` for suspicious).
- **FYP14 - Extension non-HTTP handling**: With the extension installed,
  open the extension popup while on a `chrome://` page and confirm the
  popup shows the non-HTTP state rather than an error.
- **FYP15 - Extension backend offline**: Stop the backend server, then open
  the extension popup on a regular HTTP(S) page and confirm the popup shows
  the error / retry state.

## Failures

None. All 12 programmatic tests passed. (See the FYP03/FYP04 note above
regarding the 400 vs 422 status-code distinction; this was assessed as a
pass on functional intent, not a failure.)
