# Feedback: CRLF/desync heuristic false positives (v3.7.2)

> **Resolved in v3.8.0.** All five over-flagging behaviors below were fixed: header-block-only reflection (FP1), clean `505`/`417` rejections no longer flagged (FP2/FP3), HTTP/2/3 targets skip the response-splitting probe with residual findings caveated as "HTTP/1.1 downgrade path only" (FP4), and version-token-gated security-header disclosure (FP5). See CHANGELOG `[3.8.0]`.

**Source:** Adobe Express Info Video assessment (PASS-31703), 2026-09-18.
**Tool version:** terminus 3.7.2 (commit e6427fc).
**Command:**
```
terminus scan -f <targets> --header-file <auth> -x http://127.0.0.1:8080 -k \
  --http2-desync-check --crlf-desync-check \
  --detect-ssrf --detect-host-injection --detect-xff-bypass --detect-csrf \
  --check-security-headers --rate-limit 3/s -t 4 -o out --output-format all
```
Targets: `https://audio-video-api.adobe.io/v1/voices`, `.../v1/internal/voices`,
`https://dc-api.adobe.io/discovery` (openresty edge, HTTP/2).

## Summary

`crlf_desync.desync_detected` reported `true` on two endpoints and the run surfaced
`[CRLF Desync Suspected]` / `[CRLF: Injection Reflected]`. All of these were adjudicated
**false positives** after manual reproduction on the wire. Four distinct over-flagging behaviors,
each with a proposed fix below.

---

## FP 1: "CRLF injection marker reflected" fires on request-path echo in an error body

**What terminus reported:**
```
[CRLF Desync Suspected] CRLF injection marker reflected in response (path CRLF interpreted)
crlf_desync.crlf_injection_reflected = true
```

**Ground truth (reproduced):**
```
GET /v1/voices%0d%0aEIV-Injected:%20marker123   (via Burp, HTTP/2)
-> HTTP/2 404
   content-type: application/json;charset=UTF-8
   body: {"timestamp":...,"status":404,"error":"Not Found",
          "path":"/v1/voices%0d%0aEIV-Injected:%20marker123"}
```
The injected marker appears only inside the JSON `path` field of a Spring-style error body,
with the CRLF still **percent-encoded and inert**. It never became a response header. No
response splitting occurred.

**Why it is a false positive:** the detector treats "my marker string appears anywhere in the
response" as reflection. A framework echoing the requested path in an error body (very common:
Spring Boot, many API gateways) is benign when the CRLF is URL-encoded and the content type is
not HTML.

**Proposed fix:**
- Only set `crlf_injection_reflected=true` when the injected header name appears **as an actual
  response header** (parse the response header block), not when the marker appears in the body.
- If body reflection is worth reporting at all, downgrade it to a separate low-signal
  "path reflected in error body" note, and suppress it when (a) the reflected CRLF is still
  percent-encoded, and (b) `Content-Type` is not `text/html`.

## FP 2: malformed-HTTP-version status change flagged as desync

**Reported:**
```
[CRLF Desync Suspected] Malformed HTTP version (HTTP/13.37) anomaly: probe status Some(505) vs baseline Some(200)
malformed_version_anomaly = true
```
**Ground truth:** `505 HTTP Version Not Supported` is the RFC-correct response to `HTTP/13.37`.
A status change from baseline is expected and secure, not a desync signal.

**Proposed fix:** do not treat a `505` (or `400/501`) response to a deliberately malformed
version as an anomaly. Only flag when the malformed version yields a response that indicates the
version was *silently accepted / mis-parsed* (e.g. `200` with the body served, or a timing/socket
anomaly), not when the server rejects it cleanly.

## FP 3: Expect-header status change flagged as desync

**Reported:**
```
[CRLF Desync Suspected] Expect header anomaly: probe status Some(417) vs baseline Some(500)
```
**Ground truth:** `417 Expectation Failed` is the correct response to an unsupported `Expect`
value. Benign.

**Proposed fix:** treat `417` to an `Expect` probe as expected behavior; only flag when the
Expect probe produces a smuggling-relevant signal (hang, split, or differential body).

## FP 4: HTTP/2 target not accounted for in CRLF logic

All targets negotiated **HTTP/2**. Classic CRLF request/response splitting is structurally
impossible over HTTP/2 (binary framing, not CRLF-delimited). The CRLF-desync module still ran its
CRLF heuristics and flagged them.

**Proposed fix:** when the negotiated protocol is h2/h3, skip (or clearly caveat) the CRLF
response-splitting heuristics, and label any residual finding as "HTTP/1.1 downgrade path only".

## FP 5 (minor): "Server header exposes version information" with no version present

**Reported:** `[Security: Server header exposes version information]`
**Ground truth:** header is `Server: openresty` with **no version string**.

**Proposed fix:** only flag "version information" when the `Server` (or `X-Powered-By`) value
contains a version token (e.g. matches `/\d+\.\d+/`). Otherwise report the softer
"server software disclosed" at a lower severity.

---

## Net impact

For this target the CRLF/desync module produced 100% false positives (5 flag types, 0 real
issues). The fixes above are about tightening the reflection check to response headers, and
suppressing expected/secure status responses and h2 targets from the desync heuristics.
Raw run artifacts: `terminus-desync-20260918T203429Z.{json,txt,csv,db,html}`.

---

## Addendum 2026-09-18: FP5 confirmed across 6 hosts

Full-endpoint sweep (17 prod endpoints). "Server header exposes version information" fired on every
host whose `Server` value was one of: `openresty`, `adobe`, `AmazonS3`. None of these carry a version
token. The flag should require a version pattern (e.g. `/\d+(\.\d+)+/`) in the `Server`/`X-Powered-By`
value; a bare software name should be a lower-severity "server software disclosed" note at most.

Also: the CORS flag "CORS allows all origins (*)" is accurate but should distinguish severity by
whether `Access-Control-Allow-Credentials: true` co-occurs. `ACAO:*` alone (seen on dc-api.adobe.io)
is spec-acceptable; `ACAO:*` + `ACAC:true` (seen on audio-video-api.adobe.io) is the real defect.
Consider splitting into two flags: "wildcard CORS" (info) vs "wildcard CORS with credentials" (finding).
