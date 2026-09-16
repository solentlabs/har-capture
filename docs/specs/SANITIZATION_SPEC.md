# Sanitization Spec

## Purpose

This spec describes the three-engine sanitization pipeline that processes HAR files to remove PII. It covers the
HAR-level engine (headers, cookies, POST data, query params), the HTML content engine (multi-pass scanner pipeline), and
the heuristic engine (safe value check, entropy, credential prefix, adjacency, domain detectors). It documents the
two-pass model (auto-sanitize + interactive review) and the format-preserving hasher.

## Key Files

| File                                         | Role                                                                               |
| -------------------------------------------- | ---------------------------------------------------------------------------------- |
| `src/har_capture/sanitization/har.py`        | HAR-level orchestration, organized into 9 logical groups                           |
| `src/har_capture/sanitization/html.py`       | HTML/content engine, multi-pass scanner pipeline                                   |
| `src/har_capture/sanitization/heuristics.py` | Heuristic engine: entropy analysis, credential prefix, adjacency, domain detectors |
| `src/har_capture/sanitization/collector.py`  | Redaction/flag collection during sanitization                                      |
| `src/har_capture/sanitization/report.py`     | SanitizationReport data structures, `ReviewOutcome`                                |
| `src/har_capture/sanitization/review.py`     | Recording the review in a sanitized file (`record_review`), compressed copy        |
| `src/har_capture/patterns/hasher.py`         | Salted format-preserving hashing (SHA-256)                                         |

## Architecture Overview

```text
                    ┌────────────────────────────┐
                    │      Pattern Loading       │
                    │  pii.json + sensitive.json │
                    │  + domain patterns         │
                    └────────────┬───────────────┘
                                 │
              ┌──────────────────┴────────────────────┐
              │         Pass 1: Auto-Sanitize         │
              │                                       │
              │  ┌─────────────────────────────────┐  │
              │  │    HAR Engine (har.py)          │  │
              │  │    Headers → Cookies → POST →   │  │
              │  │    URLs → JSON bodies           │  │
              │  └──────────────┬──────────────────┘  │
              │                 │                     │
              │  ┌──────────────▼──────────────────┐  │
              │  │    Content Engine (html.py)     │  │
              │  │    Sequential scanner passes    │  │
              │  │    (heuristic engine embedded   │  │
              │  │     in web storage + pipe-      │  │
              │  │     delimited passes)           │  │
              │  └─────────────────────────────────┘  │
              └──────────────────┬────────────────────┘
                                 │
                                 ▼
              ┌───────────────────────────────────────┐
              │    Pass 2: Interactive Review         │
              │    apply_user_redactions(report)      │
              │  Replace in strings, same salt        │
              └───────────────────────────────────────┘
```

## HAR Engine (har.py)

### Logical Groups

The file is organized into 9 groups:

1. **HAR Structure Validation** — `validate_har_structure()`, `check_har_types()`, `HarSizeError`, `HarValidationError`
1. **Pattern Loading** — `_load_sensitive_headers()`, `_load_sensitive_field_patterns()` (module-level caching)
1. **Core Redaction Utilities** — `_redact_value()`, `is_sensitive_field()`, `is_flaggable_field()`,
   `sanitize_header_value()`
1. **Request Sanitization** — Headers, cookies, POST data (form/JSON), query strings, URL paths
1. **Response Sanitization** — Headers, cookies, content (`route_body()`: JSON by content, else by type, sniffed when
   the type says nothing)
1. **Text Outside the HTML Engine** — `_sanitize_body_string()`: the pattern-file pass (custom patterns, cards, SSNs),
   MACs, IPv6 and IPv4, emails, phone numbers, and the positional passes between them
1. **Pass 1b Propagation** — `_is_propagation_eligible()`, `_propagation_search_keys()`, `_propagate_redacted_values()`
1. **Main Entry Points** — `sanitize_entry()`, `sanitize_har()`, `sanitize_har_file()`
1. **Pass 2** — `apply_user_redactions()`, `appears_sanitized()`

### Entry Points

```python
# File-level sanitization (primary API)
def sanitize_har_file(
    input_path: str | Path,
    output_path: str | Path | None = None,
    *,
    salt: str | None = "auto",
    custom_patterns: str | dict[str, Any] | None = None,
    max_size: int | None = DEFAULT_MAX_HAR_SIZE,
    validate: bool = True,
    heuristics: HeuristicMode = HeuristicMode.DISABLED,
) -> tuple[str, SanitizationReport]:
    """Load HAR, validate, sanitize, embed metadata, write output."""

# In-memory sanitization
def sanitize_har(
    har_data: dict,
    *,
    salt: str | None = "auto",
    custom_patterns: str | dict[str, Any] | None = None,
    heuristics: HeuristicMode = HeuristicMode.DISABLED,
) -> tuple[dict, SanitizationReport]:
    """Sanitize a parsed HAR dict, return (sanitized_data, report)."""

# Single-entry sanitization
def sanitize_entry(
    entry: dict[str, Any],
    *,
    salt: str | None = "auto",
    custom_patterns: str | dict[str, Any] | None = None,
    collector: RedactionCollector | None = None,
    heuristics: HeuristicMode = HeuristicMode.DISABLED,
    _skip_copy: bool = False,
) -> dict[str, Any]:
    """Sanitize one HAR entry (request + response)."""
```

### Type Boundary

`sanitize_har()` (and so `sanitize_har_file()`), `validate_har()` and `analyze_har_file()` first run
`check_har_types()`: a field either tool reads that is present has its HAR 1.2 type, or the call raises
`HarValidationError` naming the field (`log.entries[3].request.headers`). `null` is accepted only where both tools read
the field as absent: `queryString`, `cookies`, `postData`, `postData.text`/`mimeType`, content
`text`/`mimeType`/`encoding`, and a query/cookie pair's name or value. A required container (`log`, `entries`, an entry,
`request`, `response`, `headers`, `content`), a header's name or value, a URL and a form parameter's name may not be
`null`. An absent field is not rejected here — `validate_har_structure()` judges presence. `sanitize_entry()` checks its
entry against the same table (paths start at `entry`). One boundary, rather than a check in each walker, gives both
tools the same answer. Across the CMM fleet (480 HARs, 26,253 entries) no field breaks the rule.

### TLS Certificate Names

After the request and response, `sanitize_entry` reads the entry's `_securityDetails` (`_sanitize_security_details`,
[ADR-17](../ARCHITECTURE_DECISIONS.md#adr-17-a-device-cas-certificate-name-is-a-device-identity)). In `subjectName` and
`issuer`, a name that is wholly a MAC in any layout, and a colon or hyphen MAC inside a name (`certificate_name_macs()`,
shared with `validate`), is hashed in place with `hash_mac` in its own layout and counted under `mac_address`; a MAC
placeholder and a constant MAC are kept. A non-empty self-signed name (`subjectName` equal to `issuer`) holding no MAC,
other than `localhost` and `localhost.localdomain`, is offered for review as `device_name` at LOW confidence.
`protocol`, `validFrom`, `validTo` and the entry's `serverIPAddress` are kept.

### Header Sanitization

Headers are classified into four tiers from `sensitive.json`:

1. **Full redact** (`headers.full_redact`): X-Auth-Token, X-Api-Key, etc. — entire value replaced.
1. **Scheme redact** (`headers.scheme_redact`): Authorization-style headers (RFC 7235 syntax: `Scheme credentials`). The
   scheme token is preserved when it matches a recognized RFC scheme (`Basic`, `Bearer`, `Digest`, `NTLM`, `Negotiate`,
   `OAuth`); the credential after the first whitespace is redacted. Unknown schemes (or values with no whitespace) fall
   through to full redaction so a non-standard leading token can't escape. Preserving the scheme lets downstream
   consumers classify the auth mechanism from a single authenticated request without needing a `401 + WWW-Authenticate`
   exchange.
1. **Cookie redact** (`headers.cookie_redact`): Cookie, Set-Cookie, Set-Cookie2 — cookie names preserved, values
   redacted. The header names have different grammars (RFC 6265 sec. 4.2.1 vs sec. 4.1.1). One function,
   `cookie_segment_actions()`, classifies each `;`-separated segment for the sanitizer (`_sanitize_cookie_header`) and
   `validate` alike, so both read the same segments as cookie data:
   - **Request `Cookie`**: a list of cookie pairs. Every `name=value` segment is cookie data, so every value is redacted
     — including a cookie whose name happens to be a reserved attribute word (`path=…` in a request header is a cookie,
     not an attribute). A valueless segment is a nameless cookie and is redacted whole, except a valueless `Secure`,
     `HttpOnly` or `Partitioned`: the fleet's recorders write those there (7,882 segments across the fleet, in raw
     captures too), and they are not data.
   - **Response `Set-Cookie` / `Set-Cookie2`**: one cookie pair followed by `;`-separated attributes. A value whose
     every segment is a valid RFC 6265 attribute (`is_set_cookie_attribute()`: valueless `Secure` / `HttpOnly` /
     `Partitioned`, a `Path` starting with `/`, a `Max-Age` of digits, a `SameSite` or `Priority` from its enumeration,
     an `Expires` date, a `Domain` hostname) holds no cookie and is kept whole — `Path=/foo; HttpOnly`,
     `Secure; HttpOnly`. Otherwise the **first** segment is the cookie, whatever its name (`Secure=abc; Path=/` redacts
     `abc` and keeps `Path=/`; a first segment with no `=` is a nameless cookie and is redacted whole). Reserved
     attributes after it (`Path`, `Domain`, `Expires`, `Max-Age`, `SameSite`, `Secure`, `HttpOnly`, `Partitioned`,
     `Priority` — matched case-insensitively per sec. 5.2) survive **verbatim**, spacing included: they scope the
     cookie, they are not secrets, and a redacted `Path` makes downstream tooling read the cookie's scope wrong.
     Preserving them reveals nothing new — a cookie's `Domain` is a suffix of the request host and its `Path` a prefix
     of the request path, both of which the HAR already carries unredacted in the URL and `Host` header; the remaining
     attributes are dates, flags and enum tokens. They are kept by name, not checked against the RFC grammar: a reserved
     attribute after the cookie is never cookie data, and the fleet holds no raw `Expires`, `Max-Age`, `SameSite` or
     `Domain` value to prove a stricter rule would keep real ones (it holds only 68 raw `Path` values). An *unreserved*
     `k=v` segment in the attribute position is still redacted — an unknown key there gets no free pass; a valueless
     token after the cookie has no value half to redact and is kept.
   - Serialized attribute metadata (`HttpOnly: true, Secure: true`) is not attribute syntax: as a request segment or a
     Set-Cookie's first segment it is redacted like any nameless cookie.
1. **All other headers**: Passed through unmodified — except the URL-valued headers `Referer`, `Location` and
   `Content-Location`, whose URL first gets the [query parameter rules](#url-sanitization) (`_sanitize_headers`).

### Field Sensitivity Classification

```python
def is_sensitive_field(name: str) -> bool:
    """100% confidence — auto-redact. Matches: password, secret, token, key, auth."""

def is_flaggable_field(name: str) -> bool:
    """Lower confidence — flag for review. Matches: username, domain, account_id."""
```

Patterns loaded from `sensitive.json` `fields.auto_redact_patterns` and `fields.flag_patterns`; a custom file's legacy
`fields.patterns` list joins the auto-redact tier. `credential` names a credential only as a field's last word
(`credentials?$`: `userCredential`, `user_credentials`), so a field naming a kind or encoding of credential
(`credential_encoding`, `credentialType`) is not one.

**ADR-12 accounting** (`credential` as the last word): *redacts less.* CMM's catalog holds 24 `credential_encoding`
values (two distinct, encoding names) that a bare `credential` pattern would make `validate` errors and `check_for_pii`
findings; no key across the 480 fleet HARs or the catalog holds a credential under `credential` anywhere but last.
*Fidelity:* those values are kept.

Callers can extend these per-call via `sanitize_post_data(..., custom_patterns=...)` or
`sanitize_html(..., custom_patterns=...)`. The extension is additive (never replacing built-ins) and is applied via a
`ContextVar`-scoped override that both public entry points enter at the top of the call. Inner helpers
(`_sanitize_form_urlencoded`, `_sanitize_json_recursive`, `_sanitize_xml_fields`, the inline-script `setItem` scanner,
and any other site that calls `is_sensitive_field` / `is_flaggable_field`) pick up the active set automatically, with no
signature plumbing. Because `ContextVar` is thread- and asyncio-scoped, concurrent callers observe only their own
patterns.

### POST Data Sanitization

```python
def sanitize_post_data(
    post_data: dict[str, Any] | None,
    hasher: Hasher | None = None,
    collector: RedactionCollector | None = None,
    *,
    custom_patterns: str | dict[str, Any] | None = None,
    heuristics: HeuristicMode = HeuristicMode.DISABLED,
) -> dict[str, Any] | None:
```

1. **Form params** (`postData.params`): In the [query tree's order](#url-sanitization): `is_sensitive_field()`
   (auto-redact); a value that is a `base64(user:pass)` credential (`is_base64_credential()`) is redacted as `AUTH` —
   before an identity-style name is considered, so base64-wrapped credentials in device-specific or identity-named
   fields do not slip past field-name redaction; a base64 JSON or URL payload value is sanitized inside; then
   `is_flaggable_field()` (flag). A parameter whose name is not recognized in a **login-shaped** form (any parameter
   name in the form matches a sensitive or flaggable pattern) whose value is base64 decoding to printable text
   (`is_base64_decodable_text()`) is flagged for review at MEDIUM confidence, category `credential` — not auto-redacted,
   since base64-decodable alone is not a 100%-confidence signal. This is the backstop for vendor credential fields the
   name patterns don't know yet (the Sercomm/Hitron `pws` class; `pws` itself is a built-in auto-redact pattern).
1. **JSON body** (`_rewrite_json`): a body that parses as a JSON object or array is JSON **whatever its type** — a
   `text/plain` XHR body, or jQuery's `application/x-www-form-urlencoded` default around `JSON.stringify` — as
   `validate` reads it. It gets the [JSON traversal](#json-body-traversal) rules and is written back as a response is.
1. **URL-encoded body** (`_sanitize_form_urlencoded`): Detected via content type, parsed and redacted. The same
   `base64(user:pass)` value fallback and login-shaped flag heuristic apply (checking the raw and percent-decoded
   forms). Redaction hashes the **percent-decoded** value, so the placeholder assigned to a secret in the text copy
   matches the one assigned to the same secret in `postData.params` (which HAR stores decoded) — encoding differences
   must not break correlation. A field **name** is judged percent-decoded too (`p%61ssword`, `user%5Bpass%5D`), as
   `validate` and HAR's decoded `postData.params` read it; the written pair keeps the raw name. A value is judged by its
   field name and the credential shapes, as a query parameter's is: a MAC, IP address or email in the value of a field
   whose name is not sensitive is neither redacted nor reported by `validate`. Across the CMM fleet none of 709 form
   bodies and none of 6,234 query values holds one.
1. **XML body** (`_sanitize_xml_fields`, then `sanitize_html`): a markup type (`mime_kind()`: `text/xml`,
   `application/xml`, any `+xml` such as `application/soap+xml`) — the predicate `validate`'s XML check uses too. Its
   elements and attributes are first redacted by name, parsed by `parse_xml()`, the one parse `validate`'s XML check
   uses: a lone surrogate is read as U+FFFD, so one stray code unit does not switch off every field in the body (a
   changed body is re-serialized with U+FFFD in its place). The body is then delegated to the HTML content engine, which
   runs the full scanner pipeline. XML POST bodies from device APIs (e.g., modem XML getter/setter endpoints) are
   sanitized identically to XML response content.
1. **Raw text**: sanitized as a text response body is (`_sanitize_body_string`): the pattern-file pass, the string
   patterns and the positional passes, labeled serials among them.

**Per-call `custom_patterns`** extends the auto-redact and flag regex sets across all five branches (params, form, JSON,
XML, text) via a `ContextVar`-scoped override entered at the top of `sanitize_post_data`. The dict shape mirrors
`sensitive.json`, e.g. `{"fields": {"auto_redact_patterns": ["vendorpw"]}}`. Module-global patterns are never mutated;
the override is scoped per thread / asyncio task. Compiled regex pairs are cached per canonical key so repeated calls
with the same extension avoid recompilation. `sanitize_html` enters the same scope, so the XML branch's delegation to
the HTML engine honors the override end-to-end.

### URL Sanitization

**Query parameters** — the same rules wherever a query appears: the request URL (`_sanitize_url_query_params`), the
parsed `queryString` array (`_sanitize_query_string_array`), the URL-valued headers `Referer`, `Location` and
`Content-Location` (`URL_VALUED_HEADERS`, handled in `_sanitize_headers`), and the response's `redirectURL` — HAR's copy
of `Location`. A credential or sensitive parameter in one request's URL is repeated in the next request's `Referer`, and
a redirect's `Location` can carry one, so each is held to the same standard as the request URL. Only the query is
rewritten: the rest of the URL — scheme case, an empty `;` or `#`, a relative path — comes back byte-identical.

Each raw `&`-separated segment is read by `find_query_credential()` (`patterns/redaction.py`). It is the one definition
of a URL credential, shared with the validator's `check_url` / `check_query_string` and the
[credential annotation](#url-credential-location-annotation), so they cannot disagree about which query shapes carry
one. It recognizes three shapes of `base64(user:pass)`:

| Shape                   | Example                   | Kept verbatim |
| ----------------------- | ------------------------- | ------------- |
| Bare segment            | `?YWRtaW46cGFzcw==`       | nothing       |
| Marker-prefixed segment | `?login_YWRtaW46cGFzcw==` | `login_`      |
| Keyed value             | `?t=YWRtaW46cGFzcw==`     | `t=`          |

A marker is a letter-led alphanumeric run ending in `_`; `_` is outside the standard base64 alphabet, so the boundary is
unambiguous. When a segment is both keyed and marker-shaped (`login_x=<b64>`), the keyed reading wins. The credential is
recognized through the transport damage a URL does to it: percent-encoding (`%3D` padding, `%2B`), a raw `+` (read as a
base64 character, never as a space), and the two things URLSearchParams does before Playwright records the `queryString`
array — `+` decoded to a space, and padding split off into the value at the first `=`. The array entry is rejoined into
its segment (`query_param_segment()`) before reading, so both representations get the same answer and the same hash.

Stripped or miscounted padding is restored only for a candidate of at least 11 characters without padding (the length of
`base64("admin:pw")`) whose decoded text is printable. Below that, short hex and alphanumeric tokens — cache-busters,
short commit SHAs — decode to a colon-bearing string by chance (`?v=0406a0` does), so a credential shorter than
`admin:pw` whose padding was stripped is not recognized.

One decision tree serves the URL string and the array (`_classify_query_param`), per parameter:

1. A bare or marker-prefixed credential → `AUTH_<hash>`, marker kept. Any `=` inside it is padding, so the name rules
   below must not read it as `key=value`. A segment shaped exactly like a hash placeholder (uppercase prefix, `_`,
   lowercase hex — `AUTH_d2c6b8e4`) is never read as a marker plus a credential, so re-sanitizing a sanitized file
   leaves it alone; a real credential behind a placeholder-like marker (`AUTH_<b64>`) is still caught. A doubled
   separator (`/a??<b64>`, `k==<b64>`) stays in the kept prefix.
1. A bare base64-wrapped payload (`find_query_payload()`: base64 of a JSON object or array, or of a URL) → sanitized
   inside and wrapped again (see below).
1. A blank value — empty, or only `=` (the padding remnant a parser leaves behind) → unchanged.
1. Sensitive parameter name → `FIELD_<hash>`.
1. A keyed credential under any other name → `AUTH_<hash>`, key kept. This includes a flaggable name: `?user=<b64>` is a
   credential, not an identity to review.
1. A keyed base64-wrapped payload → sanitized inside and wrapped again, key kept.
1. Flaggable name → flagged for review.

**Base64-wrapped payloads.** Decoded, base64 of a JSON object or of a URL has a colon, so a bare `user:pass` test reads
it as a credential. Text that decodes to structure (a JSON object or array, parsed or not, or a URL) is never a
credential on any surface: `is_base64_credential()` itself rejects it. In a query, a payload that parses
(`find_query_payload()`) is sanitized inside — a JSON payload with the JSON rules, a URL payload with these query rules
— and `validate` checks inside it with the matching checks (`check_json_fields`, `check_url`), in the same order as this
tree: a payload under an identity-style name is checked inside, not flagged by name. A payload with nothing to redact
stays byte-identical. A rewritten one is encoded in the original's form: unpadded only where the original visibly
stripped its padding (no `=` where its length needed one), percent-encoded where the original was, JSON as
[the body rules](#response-content-dispatch) write it. A POST field (form params or an urlencoded body) follows the same
tree: a credential-named field is redacted whole, a `base64(user:pass)` value is a credential before an identity-style
name is considered, and a payload value is sanitized inside.

**Pass 1 is final inside a payload.** Its values are stored base64, beyond the reach of the passes that work on the
HAR's text: Pass 1b cannot propagate a redacted value into one, and Pass 2 could not apply a review decision there. So
nothing inside a payload is offered for review (`RedactionCollector.flags_muted()`), and a secret inside one is redacted
by Pass 1's rules or not at all. `validate` reports only the errors it finds inside a payload for the same reason: an
identity-style field there has no review to clear it. The accepted cost, recorded under ADR-12: a session token another
surface redacted survives inside a payload unless the payload's own rules catch it; the fleet holds no such payload.

**ADR-12 accounting** (three rules widen redaction: the marker shape, URL-valued headers, and a credential under an
identity-style name):

- *Leak closed:* Arris SB8200 URL-token firmware logs in with `?login_<base64(user:pass)>`; without the marker shape the
  admin password is recoverable from the URL, the `queryString` array, and every later `Referer`. Without the header
  rule, a sensitive parameter (`?password=…`) or credential in a URL-valued header or `redirectURL` is cleaned only when
  [Pass 1b](#pass-1b-redacted-value-propagation) happens to match it — never for a value under 16 characters or one
  whose encoding differs from the request URL's. And without the credential-first order, `?user=<b64>` is offered for
  review as a username while the validator reports it as a credential.
- *Fidelity cost:* none beyond the value itself. The marker, the key and the segment count survive, so the auth flow
  reads the same and a consumer can still see which request carried the login; a header's URL keeps its path and every
  non-sensitive parameter.
- *Cannot-be-structure proof:* the credential tail must decode strictly to UTF-8 `user:pass` and not be a base64 JSON or
  URL payload (see Base64-wrapped payloads above). A restored one must additionally clear the length floor and be
  printable, so restoration adds no structure redaction. Across the request-URL query segments of 481
  cable_modem_monitor fleet HARs (11,065), `find_query_credential()` matches 14 — all `admin:` credentials, 5 bare and 9
  marker-prefixed — and nothing else. The header rule adds no new detection: it applies the URL's own rules to the URLs
  in `Referer`, `Location`, `Content-Location` and `redirectURL`, and over the same fleet it redacts no header value.
  `?user=<b64>` passes the same credential proof as any other keyed value.

**Userinfo password.** A URL's userinfo (RFC 3986: the `user:password` part ahead of the host) carries a credential by
position (`split_url_password()`, shared with `check_url`); the password becomes `AUTH_<hash>` and the user, host and
rest of the URL are untouched. The authority ends at the first `/`, `?` or `#`, and its userinfo runs to the authority's
**last** `@` — how browsers parse it — so a password holding `@` is redacted whole and an email-address username is
still a username. A scheme-relative reference (`//user:password@host/…`, which a `Location` header may carry) counts
too. It applies wherever the query rules do, and inside a base64-wrapped URL payload. Browsers strip userinfo from the
requests they send, so it arrives in a `Location` header or a wrapped URL.

**ADR-12 accounting** (a new detection, and the POST order):

- *Leak closed:* without the userinfo rule a userinfo password survives every sanitize run. Without the POST order, a
  POST field with an identity-style name holding `base64(user:pass)` is flagged for review, where the same value in a
  query is redacted.
- *Fidelity cost:* none beyond the password; the URL's structure survives.
- *Cannot-be-structure proof:* RFC 3986 gives the text between `scheme://user:` and the authority's `@` no other
  meaning. No URL across the cable_modem_monitor fleet's request URLs, `Referer`, `Location`, `Content-Location` or
  `redirectURL` values carries userinfo, so the rule changes no fleet capture.

**URL path** (`_sanitize_url_path`):

- UUIDs, API keys, long tokens, device serial patterns are flagged (not auto-redacted)
- Path segments preserved for URL readability
- A segment that exactly matches a value already redacted elsewhere in the capture is replaced by
  [Pass 1b](#pass-1b-redacted-value-propagation) after all entries are sanitized — no detection rule is involved, and
  segment count is preserved

### JSON Body Traversal

```python
def _sanitize_json_recursive(data, hasher, collector, _depth=0, *, served=False):
```

Traverses objects and arrays recursively. Every string leaf goes through the
[string patterns](#string-pattern-sanitization). Each object member is decided by its **original key**, first rule wins:

1. **Sensitive key** (`is_sensitive_field()`) holding a string → `FIELD_<hash>`.

1. **Identity key** holding a value of that identity's shape (`classify_identity_field()`, `patterns/redaction.py`,
   shared with `validate`):

   - A MAC key (`MAC_KEY_RE`: `mac`, `macAddress`, `CmMacAddress`, `hw_addr`, a glued prefix like `wanmacaddr`) with a
     MAC in any layout — colon, hyphen, bare 12-hex, dotted — → a MAC placeholder in the value's own layout (with a
     salt; static mode writes `XX:XX:XX:XX:XX:XX`, see [MAC layout](#format-preserving-hasher-hasherpy)). A constant MAC
     (`is_constant_mac()`) is kept.
   - A serial key (`SERIAL_KEY_RE`: `serial`, `serialNumber`, `StatusSoftwareSerialNum`, `cmserialnumber`, and the exact
     bare key `sn`) with one whitespace-free token of five or more characters carrying a digit → `SERIAL_<hash>`.
     Placeholders (`-`, `N/A`) and labels (`Seriennummer`) carry no digit and stay.

   A key is read as its words (camelCase humps, acronyms and digit runs, lowercased and joined with `_`), and the
   identity must end it: `serialNumberLabel` and `MacAddressFilterEnabled` name something about the identity. A word
   starting `hmac` names a message authentication code, and `snr` is a signal ratio; neither counts.

1. **Flaggable key** (`is_flaggable_field()`) holding a non-empty string → traversed, then flagged for review as the
   output holds it (after the string patterns), so choosing to redact it in the review removes it. A value the string
   patterns turned wholly into a placeholder (a username that is just an email) is not offered — nothing is left to
   review, and in static mode redacting `x@x.invalid` would rewrite every static email placeholder. The field's flag
   takes over a narrower flag on the same text (a username that is exactly a phone number is a `field` item). SSID keys
   and served prose below are flagged the same way.

1. **SSID key** (`is_ssid_key()`: one of the key's words is `ssid` — `ssid`, `ssid_24g`, `guestSSID`) holding a network
   name that is not a safe value (the call's `safe_value_patterns`, domain and custom ones included) or a placeholder →
   flagged for review (`wifi_ssid`, MEDIUM), never auto-redacted: the name identifies a network rather than
   authenticating to it. The HTML engine auto-redacts a *labeled* SSID on a page (passes 7a, 7c, 16), so one network
   name could be `WIFI_<hash>` there and raw under a JSON key; across the fleet, 307 distinct raw names sit under JSON
   SSID keys in 29 captures, every one offered for review, and none is also redacted on a page of the same capture.
   Auto-redacting JSON SSID keys would name no leak and cost those 307 names, so the rule is review-only (ADR-12).

1. Anything else → traversed.

The key rules judge string values only; a number, boolean, null or container under a credential- or identity-named key
is traversed, not redacted, and `validate` reports none. Across the fleet such values are 54 booleans (`auth`,
`has_credentials`) and nothing else.

A sensitive key holding an empty string, or exactly the placeholder this rule writes (`FIELD_<hex>`, `***FIELD***`,
`[REDACTED]`) that `validate` also accepts, is left as it is: there is no secret to replace, so HNAP's `"Password": ""`
stays empty and a sanitized value is not hashed again. Anything else is replaced, including a real value that merely
looks redacted (`TP_LINK_20231105`, `WIFI_Home2024`, `00000000`). Across the fleet's already-sanitized fixtures this
stops 480 of the sanitizer's own placeholders being hashed again (46 in POST JSON, 434 in responses), 27 empty passwords
in POST JSON stay empty, and 4 look-alike values under a credential key are replaced.

Every other route keeps an empty value the same way: an empty form field (`params` and urlencoded text), query
parameter, cookie or credential header comes back empty and is not counted (`_redact_value()` returns it unchanged). A
placeholder there would invent a submission the capture never made: an empty default password would read as a real one,
and capture-completeness would count it as a login.

A value a **response** serves under a credential-named key is judged by its shape too (`credential_value_action()`,
shared with `validate` and `check_for_pii`), because there the key is often a firmware translation table's label for UI
text about credentials — `PAGE_GENERAL_SET_PASSWORD`, and in one table a bare `password` or `passphrase`. A button word
(`Yes`, `No`) is kept; prose (words on both sides of a space) is offered for review as `credential` at LOW confidence
(shown, not pre-selected for redaction), with the string patterns still applied inside it; anything else is replaced.
Prose whose format proves it a credential is replaced too: a PEM block — a BEGIN and an END line with base64 body text
between them, however laid out (flattened to spaces with its headers, written with literal `\n` escapes, split into
short groups), or a BEGIN line, header lines and a base64 run with no END line (a truncated key still counts); each END
is paired with the last BEGIN before it, so the scan is linear — or a known auth scheme followed by credentials (`Basic`
and base64 of `user:pass`, auth-params, or a token68 of 16+ characters holding a digit or symbol or mixing case), while
`Basic settings`, `Bearer token` and `OAuth 2.0` stay prose. Prose the review cannot reach — inside a base64-wrapped
body, where flags are muted — is replaced. A value a client **submits** (a POST body) is replaced whatever its shape:
there the key names the field the credential is typed into. And a served prose value equal to a credential the capture
submits — `_scan_submitted_credentials()`: POST JSON members, form data and the `queryString` array under a credential
name, read before sanitizing so either entry order matches — is that credential echoed back and is replaced in place,
not offered. A button word stays kept even then: a `Yes` submitted under `PasswordEnable` does not make every served
`Yes` a secret. Nothing is replaced by substring: a submitted `my home` leaves the text "Welcome to my home network"
alone. XML, multipart and base64-wrapped request bodies, and a URL query with no `queryString` array, are not read for
this; a served copy of a value submitted only there is judged by its shape, so prose is offered for review, ADR-12's
default (the fleet's requests hold none of these).

**ADR-12 accounting** (served credential-named values by shape):

- *Evidence:* across the 480 fleet HARs and CMM's catalog, 107 credential-named keys hold 3,027 values. Every
  non-placeholder value a response serves under one sits in one of three translation tables (923, 1,149 and 1,331
  members), byte-identical across the capture folders that hold it — firmware text, not a user's secret: 1,220 prose
  strings, 442 single-word labels, 48 `Yes`/`No`. Of the credentials clients submit, none is prose or a button word.
- *Fidelity:* the 48 button words are kept, and the 1,220 prose strings reach the review (10–26 distinct per affected
  capture, median 13) instead of becoming `FIELD_<hash>`. Single-word labels are replaced: by shape they cannot be told
  from a password.
- *Leak stance:* no raw credential served in a response exists in the fleet to test prose against (every one is already
  a placeholder), and a WPA passphrase may contain spaces, so prose is offered for review, not kept.

Every string — each value, and each object key — is the unit of text: it gets the positional passes the HTML engine runs
(labeled serials, vendor serials, structural credentials) interleaved with the
[string patterns](#string-pattern-sanitization) in the HTML engine's order (see
[Response Content Dispatch](#response-content-dispatch)), exactly the text `validate` checks. So a client table keyed by
MAC or address (`{"3C:7A:8A:12:34:56": {...}}`) keeps its shape with the key hashed. Two keys that hash to one
placeholder — the same MAC in two cases, or any two MACs in static mode — keep both members: the later key gets a `~2`
(`~3`, …) suffix rather than overwriting the first.

- The key rules reach 50 levels (`JSON_MAX_DEPTH`, where `validate`'s field checks and `check_for_pii` stop too).
  Deeper, every key and string still gets the text passes (`_sanitize_deep_strings`, iterative), so anything
  `validate`'s text checks would find is rewritten at any depth. Text nested more than 400 levels (`JSON_MAX_NESTING`)
  is not JSON for either tool (`parse_json_container()`) and takes the text path: re-serializing it would exhaust
  Python's recursion
- An object repeating a key parses as a `JsonObjectWithDuplicates`: the last value of each key, as every JSON parser
  (and so every consumer of the capture) reads it, with the earlier pairs kept as `shadowed`. `validate` checks those
  too. When any shadowed value has something to redact or to offer for review (probed with a throwaway collector, so it
  is neither counted nor flagged), the sanitizer re-serializes the body, so it never passes through: the duplicate
  members collapse to the one every parser reads, and the body takes the default layout, since text that repeats a key
  cannot be reproduced. A shadowed value that would be offered for review is dropped rather than kept, because the
  review never sees it while `validate` reports it. A body whose repeated keys hide nothing is written back
  byte-identical
- Malformed JSON is caught and logged: a POST body is left as-is, a response body takes the text path (sanitization
  continues)

**ADR-12 accounting** (identity keys by their words, keys as text):

- *Leak closed:* a serial or MAC under a key that is not a plain identity name — HNAP's `StatusSoftwareSerialNum`,
  `CmMacAddress` holding a bare-hex MAC — which `validate` reports as errors; and a MAC, address or email used as an
  object key, which `validate` reports.
- *Fidelity cost:* none beyond the values. A MAC placeholder keeps the value's layout, so a parser of the field still
  parses it; a hashed key keeps the object's shape and its correlation with the same value elsewhere.
- *Cannot-be-structure proof:* the key states what the value is, and the value must also have that identity's shape, so
  a label, flag or placeholder under an identity key (`"serialNumber": "-"`) is kept. Across 480 cable_modem_monitor
  fleet HARs, 54 serials under HNAP identity keys are redacted, and 70 values under plain identity keys (`mac`,
  `serial`, `sn`, …) are kept — 54 are `-` and 16 are `SERIAL_` placeholders already in the capture. No fleet JSON body
  has a MAC, address or email as a key.

### Response Content Dispatch

```python
def _sanitize_response_content(content, collector, custom_patterns, heuristics, url_credential):
```

**1. Undo the transport encoding** (`decode_transport_body()`, `patterns/redaction.py`). HAR's `encoding: base64` is how
the recorder stored the bytes, not what the server sent
([ADR-16](../ARCHITECTURE_DECISIONS.md#adr-16-transport-encoding-is-not-content)). A `base64` body is decoded with the
mime type's declared charset, else as strict UTF-8. When that fails and the type declares text (`mime_kind()`: `text/*`,
JSON, XML, JavaScript, form data), the bytes are read as latin-1: capture stores a page base64 exactly when its bytes
are not UTF-8, whatever charset it declares ([`_patch_missing_bodies`](CAPTURE_SPEC.md#eager-response-body-capture)),
and latin-1 maps every byte. The decoded body is sanitized as that text and **written back as plain text with `encoding`
dropped**, so Pass 1b and Pass 2's review replacement reach it like any other body.

**Binary** is a `base64` body whose bytes are not text: they do not decode under a type that does not declare text, or
they decode to text holding NUL. Binary is written back exactly as recorded — the sanitizer does not touch it and
`validate` does not scan it, because both read bodies through the same decoder. A body that is an `AUTH_<hash>`
placeholder still marked `encoding: base64` (a state no decoder accepts) has its `encoding` dropped, so the output is
valid.

**2. One dispatch on the text** (`_sanitize_body_text`), in order:

1. **A base64-wrapped structured payload** (`decode_base64_payload()`): text that is itself base64 of a JSON object or
   array, or of a URL. Its colon would read as `user:pass`, but it is data. The wrapped text goes through this same
   dispatch — a URL gets the [query rules](#url-sanitization) first — so every check `validate` runs on it has a remedy,
   and is wrapped again in base64 (see [Base64-wrapped payloads](#url-sanitization) for the form it is written in). A
   payload with nothing to redact is left byte-identical.
1. **A bare base64 credential** → `AUTH_<hash>`, unless it is a server token — see
   [Server-Token Preservation](#server-token-preservation).
1. **The engine for the body** (`route_body()`, `patterns/redaction.py`, the one routing decision shared with
   `validate`): text that parses as a JSON object or array → JSON traversal, **whatever its type declares** — HNAP
   answers JSON as `text/html`, and a markup engine reads no keys. Otherwise, by `mime_kind()`: a markup type (HTML,
   XML, any `+xml` such as `image/svg+xml`) → `sanitize_html()`; any other text type (`text/*`, JSON that does not
   parse, JavaScript, form data) → the text path. A type that says nothing about its text — `application/octet-stream`,
   HNAP's `x-unknown`, none — is sniffed: text opening with `<` → `sanitize_html()`, else the text path. `validate`
   scans every body whatever its type, so every text a body can carry reaches an engine.

The positional passes the HTML engine runs — labeled serials (`redact_labeled_serials()`, pass 2), vendor serials
(`redact_vendor_serials()`, 2e) and structural credentials (`redact_structural_credentials`, pass 7c) — run on every
other route too (`_sanitize_body_string`), interleaved with the string patterns in the HTML engine's order: MAC (1),
labeled and vendor serials (2, 2e), IPv6 and IPv4 (6, 4, 5), structural credentials (7c), then email (11) and the rest.
So a value two passes could claim gets one placeholder on every route — a MAC after a serial label is a MAC, an address
in a password's element is an address — on the unit of text `validate` checks: a text body's whole text, and each
decoded string of a JSON body (every value and key). Reading JSON one decoded string at a time means an escape
(`\u003c`, `\/`) hides no markup from either tool, and no match can pair a label in one string with a value in the next
— on the raw JSON text a structural value could run through a closing quote, and its replacement would break the
document. The JSON route then parses the text (`parse_json_container()`: nesting too deep for the parser counts as not
JSON, never a crash) and runs `_sanitize_json_recursive()`. JSON with nothing to redact is written back byte-identical.
Changed JSON is re-serialized in whichever layout `json.dumps` can write that reproduces the original exactly — compact,
default spacing, or a 2- or 4-space indent; non-ASCII escaped or as-is; `/` escaped as PHP writes it (`\/`) — inside the
original's surrounding whitespace. Anything else (another indent, a number spelled `1.50`) falls back to default spacing
with non-ASCII as written. The text path is `_sanitize_body_string()`, over the whole body whatever its size, as
`validate` scans it: across the cable_modem_monitor fleet, `text/javascript` bodies over 1 MB hold 48 MACs and 12 IP
addresses.

**Real shapes.** The Sercomm DM1000's `setup.cgi?todo=…` responses are `applation/json` stored with `encoding: base64`:
transport base64 around plain JSON. Arris SB8200 fragments (`pageheaderA.htm`, `footer.htm`) are HTML served as
`application/octet-stream` and stored base64; HNAP `x-unknown` bodies carry markup the same way. Read without decoding,
their transport base64 matches `base64(user:pass)` whenever the text holds a colon (CSS, `http://`), which would replace
the whole body with `AUTH_<hash>`, and one without a colon would pass every pass unscanned, while `validate` decodes and
scans both.

**ADR-12 accounting** (the dispatch redacts in bodies no other route reaches):

- *Leak closed:* PII in transport-encoded markup and text bodies, in bodies of types that say nothing about their text
  (`application/octet-stream`, `x-unknown`), in form data, SVG, `application/javascript`, and declared JSON that does
  not parse, and vendor serials in JSON — all reported by `validate`.
- *Fidelity cost:* none beyond the redacted values, and a gain: transport-encoded fragments are not destroyed, and JSON
  with nothing to redact is not re-serialized. A transport-encoded body is written as the text it decodes to, not its
  base64; for a latin-1 read that text stands in for bytes that were not UTF-8, and they are recovered by encoding it as
  latin-1. The cost: a transport-encoded body whose text is literally `user:pass` is not replaced — the base64 that
  matches `is_base64_credential()` is the recorder's, and the same text served plainly is not replaced either.
- *Cannot-be-structure proof:* the engines and their rules are the same on every route; the dispatch decides only which
  text reaches them. One rule goes the other direction: a MAC that is one byte repeated — broadcast `ff:ff:…`, zero
  `00:00:…` — is a protocol constant, and scripts compare against it (`if (mac == 'ff:ff:ff:ff:ff:ff')`), so neither
  tool treats it as PII (`is_constant_mac()`). Across 480 cable_modem_monitor fleet HARs: 180 transport-encoded text
  bodies (`applation/json`, `application/octet-stream`, `x-unknown`), 16 more already reduced to an `AUTH_` placeholder,
  1,942 binary bodies (images, fonts) that stay untouched, and no base64-wrapped JSON or URL payload in any body or
  query. In script bodies, `application/javascript` adds 25 private and 14 public IP redactions (example addresses in
  comments among them — known patterns always apply), while 342 constant MACs across script and markup bodies (296 zero,
  46 broadcast) are kept.

**ADR-12 accounting** (text that parses as JSON routes as JSON whatever its type):

- *Leak closed:* HNAP serves JSON as `text/html`, and the HTML engine reads no keys: a serial under
  `StatusSoftwareSerialNum` (54 across the fleet) is left by that engine, while `validate`, which parses the body,
  reports it as an error.
- *Fidelity cost:* the JSON key rules apply to these bodies, and they include the credential-name rule: across the
  fleet, 220 strings under credential-named keys in HNAP `text/html` JSON, all UI copy from translation bundles (132
  phrases, 88 single words; none a token with a digit). The key survives, so the structure a consumer reads is intact.
  Under the served-value rule above, the phrases reach the review and button words are kept; single words are replaced.
- *Cannot-be-structure proof:* only text that parses as a JSON object or array is rerouted, and the rules that then
  apply are the JSON engine's. The HTML engine's passes `validate` checks for all run on this route too — address and
  MAC passes through the same regexes ([String Pattern Sanitization](#string-pattern-sanitization)), labeled serials,
  structural credentials and vendor serials on the raw text. Across the fleet, the JSON route drops no redaction the
  HTML engine would make in these bodies; the IPv6 constants below are kept by both.

### String Pattern Sanitization

Every text outside the HTML engine — a text body, each JSON string value and object key, and POST text that is not JSON,
form data or markup — takes one path, `_sanitize_body_string()` (above): the pattern-file pass (`pii.json`'s patterns
with no pass of their own, custom ones included; see [Pass 0](#html-content-engine-htmlpy)), the string patterns below,
and the positional passes between them. Its address passes are the HTML engine's passes 1 and 4–6 and 11, with the same
regexes (`patterns/redaction.py`), the same validity rules and placeholders, and the same order — IPv6 ahead of IPv4, so
an IPv4-mapped `::ffff:1.2.3.4` is hashed as one address — so whether a value is redacted never depends on which engine
its body routes to. The preserved gateway addresses are `pii.json`'s plus any the call's `custom_patterns` add, on both
routes (a per-call scope, like the field patterns'):

| Pattern       | Detection                                                                             | Redaction                              |
| ------------- | ------------------------------------------------------------------------------------- | -------------------------------------- |
| MAC addresses | `MAC_RE` (see [MAC addresses](#mac-addresses)); constants kept                        | `hasher.hash_mac()`                    |
| Private IPs   | `PRIVATE_IP_RE` with octets ≤ 255 (`is_private_ip_in_range`); preserved gateways kept | `hasher.hash_ip(ip, is_private=True)`  |
| Public IPs    | `PUBLIC_IP_RE`, less version strings (`is_valid_ip_address()`)                        | `hasher.hash_ip(ip, is_private=False)` |
| IPv6          | `IPV6_RE` candidates `is_ipv6_host_address()` accepts (`::`, `::1` kept)              | `hasher.hash_ipv6()`                   |
| Emails        | `EMAIL_RE` (RFC 5321 simplified)                                                      | `hasher.hash_email()`                  |
| Phone numbers | US/CA formats **with a separator, parens, or leading +**                              | Flagged, not auto-redacted             |

Card- and SSN-shaped numbers are the pattern file's (`credit_card_*`, `ssn`), handled by the pattern-file pass with the
HTML engine's rules, so a domain that leaves them out of `include_patterns` leaves them out on every route. A
private-range match is an address when every octet is 255 or less: zero-padded as some devices print it
(`192.168.001.100`) it is redacted, and `192.168.1.999` is not an address on either route. The same holds inside an
IPv4-mapped IPv6 address: `::ffff:192.168.001.100` is one address, hashed whole as IPv6 rather than its tail as IPv4.

**ADR-12 accounting** (IPv6 and `10.x` in JSON and text bodies):

- *Leak closed:* across 480 cable_modem_monitor fleet HARs, JSON bodies hold 960 IPv6 addresses (478 global, 482
  link-local — an EUI-64 link-local address embeds the device's MAC) and JSON and text bodies hold 197 `10.x` addresses
  (180 and 17), all redacted by this path. `validate` reports no private IPv4.
- *Fidelity cost:* none beyond the addresses, which get the placeholders the HTML engine writes. As on the HTML route, a
  `10.255.x.x` placeholder already in a capture is hashed again (2,942 in the fleet's already-sanitized fixtures; see
  [Idempotency Boundary](#idempotency-boundary)).
- *Cannot-be-structure proof:* the detection is the HTML engine's, applied to text that never reached it; an IPv6
  candidate is an address only when `ipaddress` parses it, so clock times and MACs stay.

**IPv6 constants are kept** (`is_ipv6_host_address()`), by both engines. The unspecified `::` ("none configured") and
loopback `::1` identify no device — they are IPv6's `0.0.0.0` and `127.0.0.1`, which the IPv4 passes keep — and a
`2001:db8::` placeholder in their place reads as a real address. Keeping them redacts less, which ADR-12 makes the
default: across the fleet they occur 281 times in HTML bodies and 2,929 times in JSON and text bodies, and no fleet
value of either is PII. The static-mode placeholder `::` is therefore stable.

**Phone numbers require formatting**: a bare 10–11 digit run never matches — separator-free runs are constants,
counters, or frequencies far more often than phone numbers (the CM2500 firmware's md5.js init constants, e.g.
`1732584193` = 0x67452301, would otherwise be flagged 31× per review).

### MAC Addresses

One definition, `MAC_RE` in `patterns/redaction.py`, serves `_sanitize_body_string`, the HTML engine's pass 1 and
pipe-delimited scanner, `har-capture validate` and `check_for_pii` (whose `pii.json` `mac_address` regex carries it
verbatim; a test pins the two): six hex pairs joined by `:` or `-`, wherever they occur. No boundary is required on
either side — `wanmac3C:7A:8A:12:34:56` and `3C:7A:8A:12:34:56Enabled` are MACs glued to identifiers. A longer separated
run is read six pairs at a time. Bare (`3C7A8A123456`) and dotted (`3c7a.8a12.3456`) MACs carry no separator run and are
not matched in text; `is_mac_value()` and `mac_layout()` recognize them where a value is already known to be a MAC. A
MAC that is one byte repeated — broadcast `ff:ff:ff:ff:ff:ff`, zero `00:00:00:00:00:00` — is a protocol constant, not an
identity, and is left alone by both tools (`is_constant_mac()`; see
[Response Content Dispatch](#response-content-dispatch)).

**Known limit — glued placeholders.** A placeholder glued to a neighbour can complete a new match that `validate` and
`check_for_pii` then report and no sanitize run clears (ADR-14): five MAC groups glued to an IPv4 address
(`3C:11:22:33:44:8.8.8.8`, whose address placeholder completes a sixth group), a hex pair glued to a MAC placeholder
(`ff-02:da:…`), an email placeholder followed by more text under a serial-named key. The fuzz harness builds these from
its vocabulary; the fleet holds none — after sanitize, neither tool finds a MAC, IP address or IPv6 address anywhere in
the 480 fleet captures. Neither checker skips a match overlapping a placeholder, and bounding the MAC run would reopen
the glued-identifier leak above, so a capture that holds such a shape is reported by `validate` and fixed by hand.

**ADR-12 accounting** (MACs with no boundary):

- *Leak closed:* a MAC written directly against an identifier character (`cm_mac_<MAC>`, `HWaddr<MAC>`, `wanmac<MAC>`),
  which a `\b`-bounded pattern misses and `validate` reports.
- *Fidelity cost:* none beyond the MAC; the identifier around it is untouched.
- *Cannot-be-structure proof:* the matched text is the same six colon- or hyphen-joined hex pairs as a free-standing
  MAC, and exactly what `validate` reports; what it is glued to does not change what it is. Across the
  cable_modem_monitor fleet, all 11,953 such runs sit between punctuation or whitespace, so dropping the boundary
  redacts nothing the fleet contains.

**IP address heuristic** (`is_valid_ip_address()`):

- All octets \< 20 → likely version string (e.g., `5.7.1.5`) → skip
- 10.x.x.x → always IP (private range)
- Repeated octets (8.8.8.8) → always IP
- First octet ≥ 20 → always IP

**Credit card validation**: Luhn checksum verification before redacting — reduces false positives on random 16-digit
numbers.

## HTML Content Engine (html.py)

### Scanner Pipeline

The engine runs sequential passes over HTML/JavaScript content (numbered 0–16 in the code, with sub-passes like 0b, 2c,
7a/7b, 8b). Each pass uses regex substitution with callback functions that invoke the hasher.

| Pass | Scanner                        | Pattern                                                  | Redaction                               |
| ---- | ------------------------------ | -------------------------------------------------------- | --------------------------------------- |
| 0    | Custom patterns                | Domain-specific PII regex                                | Per-pattern prefix                      |
| 0b   | Web storage                    | `localStorage.setItem('KEY', 'VALUE')`                   | Auto-redact if key is sensitive         |
| 1    | MAC addresses                  | `MAC_RE` (see [MAC addresses](#mac-addresses))           | `hasher.hash_mac()`                     |
| 2    | Serial numbers (inline)        | `\bSN\b\|S/N\|Serial Number` + value with a digit        | `hasher.hash_value(val, "SERIAL")`      |
| 2c   | JS serial variables            | Names with serial+Number/Num/No or ending in serial      | `hasher.hash_value(val, "SERIAL")`      |
| 2d   | WPS / pairing / default PINs   | Known PIN label + 8-digit value                          | `hasher.hash_value(val, "PIN")`         |
| 2e   | Vendor-format serials          | High-confidence serial_number detectors, per token       | `hasher.hash_value(val, "SERIAL")`      |
| 3    | Account/subscriber IDs         | `ACCOUNT_LABEL_RE`: label, separator, tags, value to tag | `hasher.hash_value(val, "ACCOUNT")`     |
| 4    | Private IPs                    | `PRIVATE_IP_RE`, octets ≤ 255 (preserves gateway IPs)    | `hasher.hash_ip(ip, is_private=True)`   |
| 5    | Public IPs                     | `PUBLIC_IP_RE`, less version strings                     | `hasher.hash_ip(ip, is_private=False)`  |
| 6    | IPv6 addresses (runs before 4) | `IPV6_RE` + `is_ipv6_host_address()`; `::`, `::1` kept   | `hasher.hash_ipv6()`                    |
| 7    | Passwords/passphrases          | `PASSWORD_FIELD_RE`; bare `key`: `KEY_FIELD_RE`, offered | `hasher.hash_value(val, "PASS")`        |
| 7a   | SSID text labels               | SSID labels in HTML text nodes                           | `hasher.hash_value(val, "WIFI")`        |
| 7b   | JS password objects            | JavaScript object password fields                        | `hasher.hash_value(val, "PASS")`        |
| 7c   | Structural label/value         | Value alone in its own element; SSID-named elements      | `hasher.hash_value(val, "PASS"/"WIFI")` |
| 8    | Password inputs                | `<input type="password" value="...">`                    | `hasher.hash_value(val, "PASS")`        |
| 8b   | SSID inputs                    | SSID-related input fields                                | `hasher.hash_value(val, "WIFI")`        |
| 9    | Session tokens                 | `SESSION_TOKEN_RE`: 20+ char value after a label         | `hasher.hash_value(val, "TOKEN")`       |
| 10   | CSRF tokens                    | CSRF tokens in meta tags                                 | `hasher.hash_value(val, "CSRF")`        |
| 11   | Email addresses                | `EMAIL_RE`: `user+tag@sub.domain.co.uk`                  | `hasher.hash_email()`                   |
| 12   | Config paths                   | `.cfg` file references                                   | `hasher.hash_value(val, "CONFIG")`      |
| 13   | Password script variables      | `script_variables.password` names (domain file)          | `hasher.hash_value(val, "PASS")`        |
| 14   | Pipe-delimited variables       | `script_variables.pipe_delimited` names (domain file)    | Per-value heuristic analysis            |
| 15   | SSID fields in JS              | `ssid_24g: 'value'`, `guest_ssid: 'value'`               | `hasher.hash_value(val, "WIFI")`        |

**Pass 0 — pattern-file regexes** (`redact_pattern_file_matches()`: every `pii.json` pattern without a dedicated pass,
and custom ones): each match is hashed with the pattern's prefix, except the built-in number patterns, which keep one
rule so a value is treated alike on every route: a card-shaped number (`credit_card_*`) is hashed only when it passes
the Luhn check (`luhn_valid()`), and an SSN-shaped one (`ssn`) is offered for review as `ssn`, never hashed. Under
`--patterns base` this keeps the fleet's 8 card-shaped numbers in HTML bodies, all of which fail the Luhn check; the
fleet holds no SSN-shaped value. The `network-device` domain does not include these patterns. The same pass runs on
every other route (`_sanitize_body_string`), so a custom pattern matches anywhere in body text, as
[CUSTOM_PATTERNS.md](../CUSTOM_PATTERNS.md) says. Form fields and URL query values are not body text: they are judged by
their field names (see [POST Data Sanitization](#post-data-sanitization)).

**Pass 2c precision rule:** Matches variable names containing the compound `serial` + `number`/`num`/`no` (with optional
separator), and names ending with `serial`. Does NOT match `serial` followed by unrelated suffixes (`Protocol`, `Port`,
`Baud`, `ization`). Bare `serial` is excluded — too ambiguous for auto-redact.

**Pass 2e — delimiter-aware vendor serials** (`redact_vendor_serials`): applies the **high-confidence** `serial_number`
detectors from the loaded domain patterns (known vendor serial layouts, e.g. the Netgear 13-char format) to
delimiter-bounded candidate tokens (`VENDOR_SERIAL_TOKEN_RE` in `patterns/loader.py`) anywhere in the content. A
fullmatch auto-redacts as `SERIAL_<hash>` — in **every** heuristic mode, since this is what covers a serial with no
label at all, such as the serial inside the CM2500's `RouterStatus.htm` `tagValueList` blob, where FLAG-mode review
would otherwise be the only barrier and a skipped review would ship the raw value. The token extraction is the boundary
guard: a serial-shaped substring of a longer identifier, hex run, or base64 blob is never a candidate. The same helper
runs for non-HTML text body and each decoded JSON string (`_sanitize_body_string`; Netgear also serves pipe-delimited
blobs from `.js` files). `har-capture validate` applies the same detectors to the same token extraction and errors on an
unredacted match — see
[VALIDATION_SPEC](VALIDATION_SPEC.md#check_contentcontent-location-findings-custom_patterns-keywords) and
[ADR-13](../ARCHITECTURE_DECISIONS.md#adr-13-high-confidence-vendor-serial-formats-are-deterministic--auto-redact-and-validate-error-delimiter-aware).

### Sibling-Element and Structural Label/Value Rules

**Sibling-element rule (passes 2, 2d):** The tag chain between a label and its value — tags written as `<`, `_TAG_RUN`,
`>`, each followed by optional whitespace — permits whitespace between tags, so label/value pairs rendered in sibling
elements match (e.g. Technicolor .jst on the XB6/XB7/XB8/XB10 family renders
`<span class="readonlyLabel">Serial Number:</span>` with the value in a following sibling `<span class="value">`). In
passes 2 and 2d the separator-plus-tag run is captured and re-emitted verbatim, so redaction replaces only the value and
preserves the intermediate markup — sanitized fixtures keep their DOM structure. The same whitespace-tolerant chain is
used by the `serial_number` / `wps_pin` patterns in `pii.json` (`check_for_pii`) and the `SERIAL_PATTERNS` detectors in
`validation/secrets.py`.

**Serial label and value (pass 2).** One pattern, `SERIAL_LABEL_RE` in `sanitization/html.py`, serves pass 2, `validate`
(which imports it) and `check_for_pii` (whose `pii.json` `serial_number` regex carries it verbatim; a test pins the two)
— so a labeled serial `validate` reports is one a sanitize run removes. The labels are `Serial Number`, `SerialNum`,
`Serial No`, `SN` and `S/N` at a word boundary, and a bare `Serial` or `Serial ID` when a separator follows it
(`Serial:`, so prose about a serial port is not a label); the label's own closing tags may precede its separator
(`<b>Serial Number</b>: VALUE`); the value must carry a digit, as every real serial does, and is not the local part of a
whole email after the label (`Serial Number: admin123@example.com` is an email, for the email pass), while a serial
followed by `@host` (`4131N12345678@cm1`) is still a serial. A table's label cell and value cell are one more sibling
pair (`</td><td>` is a hop of the tag chain), and the chain hops only tags, so a following row's label text stops it.

**ADR-12 accounting** (the shared serial label):

- *Leak closed:* a serial whose label element closes before the colon (`<b>Serial Number</b>: X`), or labeled
  `Serial No`, `Serial ID` or a bare `Serial:`, which `validate` reports. Across the fleet pass 2 makes 412 matches;
  `validate` reports 76 labeled serials on raw captures, and none after sanitize.
- *Fidelity:* the digit rule keeps words in label position — across the cable_modem_monitor fleet, 132 digit-free values
  (`Status`, identifiers, labels, status words such as `Disabled`) — and every one of the fleet's 69 real labeled
  serials carries a digit.
- *Cannot-be-structure proof:* the label declares the value a serial; the digit rule is what separates a serial from a
  word in the same position. The closing-tag allowance adds no pass 2 match across the fleet.

**Structural label/value rule (pass 7c).** A bare tag chain is too loose for credential labels: its `\s*` also runs
through ordinary prose, so gateway help text like
`$.i18n("<strong>Password:</strong> Enter the Password you registered")` matches the word "Enter". Credential and SSID
labels therefore use a *structural* rule instead of a lexical one — the value must occupy its **own element**:

```text
LABEL:  </tag>  <tag>  VALUE  </tag>
        ^^^^^^  ^^^^^         ^^^^^
        closes  opens         value is the element's entire text content
```

Help-text prose shares a text node with its `<strong>` label; a sticker value sits alone in `<span class="value">`.
Requiring label-close then value-open then text then element-close is what separates them. Across the committed fleet
captures this matches the four Device Label blocks and nothing else; looser variants also match minified jQuery and i18n
prose.

Pass 7c applies four patterns, all defined once in `sanitization/html.py` and **imported** by `validation/secrets.py`
and `check_for_pii` so the three detection paths cannot diverge:

| Pattern                   | Shape                                                               | Prefix |
| ------------------------- | ------------------------------------------------------------------- | ------ |
| `SIBLING_PASSWORD_RE`     | `password`/`passphrase`/`psk`/`wpa key` label, value in own element | `PASS` |
| `SIBLING_SSID_RE`         | `ssid`/`network name`/`wi-fi network` label, `:` or `-` separator   | `WIFI` |
| `SSID_ATTRIBUTE_RE`       | Element whose `class`/`id` names it an SSID holder                  | `WIFI` |
| `iter_ssid_option_values` | `<option>` text inside an SSID-named `<select>`                     | `WIFI` |

The value must also be a **single whitespace-free token**. The element rule alone matches ordinary gateway markup that
the fleet captures happen not to contain — `<dt>Password:</dt><dd>Not set</dd>` and
`<div class="hint">Must be at least 8 characters</div>`. Every real sticker value is one token; every prose and status
false positive is not. The accepted cost is that an SSID containing a space is not matched.

Guards, all applied by `is_structural_value_sensitive()` so the sanitizer, `validate`, and `check_for_pii` agree:

- Bare `key` is dropped from the password vocabulary — a false-positive magnet across element boundaries (`metaKey`)
- `<th>` is excluded from `SSID_ATTRIBUTE_RE`: a column heading is not a value ("Source SSID Index")
- An attribute whose SSID token carries a helper suffix (`ssid_help`, `ssid-label`, `ssidTitle`, `ssid_desc`) names copy
  *about* an SSID, not one — matching `ssid` as a bare substring would redact "Choose a name for your network"
- Text ending in a separator is excluded — that is a label (`<span id="priwifinet">Private Wi-Fi Network- </span>`)
- `<option value="">` is a chooser placeholder (`-- Select --`), never a network
- Bare integers in an option list are row indices, mirroring the universal `^\d+$` entry in `SAFE_PATTERNS`
- Known-safe status words (`Enabled`, `Disabled`, `N/A`) are rejected via `is_safe_value()`
- Values passing `is_redacted()` are left untouched. These rules match on markup structure rather than value shape, so a
  placeholder in the value element matches as readily as a credential; without the guard, re-sanitizing a fixture would
  rewrite `[REDACTED]` to `PASS_<hash>` and churn captures that were already safe

**Mime-type symmetry.** `validate` checks every response body, but `sanitize_html` runs only for HTML/XML. The pass is
therefore exposed as `redact_structural_credentials()` and applied to non-HTML text bodies too, so validate can never
report an error that no sanitize run could clear.

**Why the heuristic engine does not cover this.** The engine classifies both kinds of value correctly when handed them
(`wifi_ssid` for a default SSID, `credential` for a three-word passphrase), but HTML label/value text is never routed to
`analyze_value` — in `html.py` heuristics reach only `_sanitize_pipe_value` and the Web Storage scanner — so pass 7c
behaves the same in all three heuristic modes. Routing span text through the engine would flag ~25% of all label/value
pairs on the Technicolor captures (`System Uptime`, `DHCP Lease Time`, `BOOT Version`, `Model`), shredding diagnostic
data in `REDACT` and flooding the review UI in `FLAG`.

**Pass 3 — account IDs** (`ACCOUNT_LABEL_RE`): the label, its separator, any tags opening the value's element and an
opening quote are kept as written, and the value runs to the next tag, whitespace, quote, `&` or `;`, so the markup,
script or query around it survives (`<p>Account ID: <b>ACCOUNT_…</b></p>`, `deviceId = "ACCOUNT_…";`,
`?deviceid=ACCOUNT_…&x=1`). A value `is_redacted()` recognizes is kept. `pii.json`'s `account_id` regex carries
`ACCOUNT_LABEL_RE` verbatim (a test pins the two), so `check_for_pii` reports exactly what this pass replaces.

### Idempotency Boundary

Passes that emit a `PREFIX_<hash>` placeholder (serial, WPS PIN, account, password, SSID, token, CSRF, config, vendor JS
vars, and the structural pass 7c) skip values `is_redacted()` already recognizes. Re-sanitizing an already-sanitized
capture is therefore a byte-level no-op, even under the default random salt, and a placeholder can never be re-hashed.
Pass 2 additionally admits `_` into its value class: without it the pass would match only the `SERIAL` prefix of its own
output and prepend a fresh hash on every run, growing `SERIAL_<hash>_<hash>_<hash>...` without bound.

The **format-preserving** passes (MAC, private IP, public IP, IPv6, email) deliberately do *not* take that guard and
remain non-idempotent. Their placeholders are valid-looking values inside reserved ranges, so the guard cannot tell a
placeholder from a real value: `02:aa:bb:cc:dd:ee` is a legitimate locally-administered MAC and `10.255.62.183` a
legitimate private address, and both would pass through unredacted. Skipping them would be a leak, not a fidelity gain;
re-hashing costs no structure — the same format stays in the same position — so under ADR-12 these passes re-hash. Two
tests (`ipv6_compressed`, `test_full_flow_with_user_redactions`) pin this and fail if the guard is extended to these
passes.

Salt regeneration is a separate matter and is not a defect: `salt="auto"` mints a fresh salt per invocation and the salt
is deliberately never persisted. Idempotency here comes from *skipping* already-redacted values, not from reproducing
the same hash.

### Web Storage Scanner (Pass 0b)

Detects `localStorage.setItem()` and `sessionStorage.setItem()` in inline scripts:

- **Tier A**: Key matches `is_sensitive_field()` (password, token, secret, api_key, auth_token, csrf_token) →
  auto-redact value
- **Tier B**: Value contains IPs/MACs → handled by subsequent passes
- **Tier C**: Heuristic analysis if enabled (`FLAG` or `REDACT` mode)

### Pipe-Delimited Scanner (Pass 14)

Handles vendor-specific data structures like Netgear's tagValueList (`"val1|val2|val3"`):

1. Match a variable assignment whose name a pattern file lists in `script_variables.pipe_delimited` (PATTERN_SPEC); the
   core names none, so without `--patterns network-device` (or a file of your own) no blob is read
1. Split value by `|` delimiter
1. For each value, judged without its surrounding whitespace:
   - Skip if empty or matches safe values (`sensitive.tagValueList.safe_values`)
   - Skip if already redacted (contains hash prefix or format-preserving pattern)
   - Auto-redact if MAC pattern, serial number pattern (`SN-`, `S/N-`, `SN_`, `S-N-`)
   - If heuristics enabled: run through `analyze_value()` from heuristics.py
1. Reassemble the pipe-delimited string with each value's whitespace written back around the value or its placeholder —
   the blob's spacing is not the pass's to change (19 Netgear captures in the CMM fleet space their `tagValueList`
   values)

### `sanitize_html()` Signature

```python
def sanitize_html(
    html: str,
    salt: str | None = "auto",         # Salt mode
    custom_patterns: dict | str | None = None,  # Domain patterns
    collector: RedactionCollector | None = None, # Shared collector
    heuristics: HeuristicMode = HeuristicMode.DISABLED,  # Heuristic mode
) -> str:
```

### `check_for_pii()` — CI/PR Validation

```python
def check_for_pii(content: str, filename: str = "", custom_patterns: str | dict | None = None) -> list[dict]:
    """Detect unsanitized PII in fixture files. Returns list of findings."""
```

Used in CI to check test fixtures for PII. It reads what the sanitizer reads — a JSON fixture one decoded string at a
time, any other content whole — and judges each match's value, not the label around it, against the allowlist (a
`pii.json` pattern's `value_group`), so a sanitized `Serial Number: SERIAL_<hash>` is clean. It reports only what a
sanitize run clears: a match the sanitizer's own pass keeps — a Luhn-failing card-shaped number, an SSN-shaped one
(offered for review), a constant MAC, a preserved gateway address, a dotted-quad version string, an IPv6 candidate that
is not a host address (a MAC, a clock time, `::`, `::1`) — is not reported, and a MAC is not reported a second time as
an IPv6 candidate. A fixture that parses as JSON also has its identity fields checked with `validate`'s predicate
(`unredacted_identity()`: a serial or MAC under a key naming it, less the sanitizer's own placeholders), and its
credential fields with the sanitizer's own field names (`is_sensitive_field()`, custom `fields` patterns included): a
value that is neither empty nor allowlisted — one the sanitizer replaces and `validate` reports, judged as a served
value (`credential_value_action()`: a button word or prose is not reported) — is reported as `credential_field`. Both
stop at `JSON_MAX_DEPTH`. A consumer names a credential field in `fields`, not with a `pii` regex pairing a key and its
value (`"field": "value"`): a regex cannot pair across the decoded strings a JSON fixture is read as.

The HTML engine's own patterns — passwords after a label (`password_field`), password inputs, session and CSRF tokens,
account IDs, WPS PINs, config paths (`HTML_ONLY_PATTERNS`), and password script variables a pattern file names
(`script_password`) — are reported only in content the sanitizer routes to that engine, read as it reads a body with no
type (`route_body()`: JSON by content, `<` opens markup, else text). Elsewhere their regexes match source code: across
the sanitized fleet, outside that content, they match 21,287 `password_field`, 3,061 `session_token` and 22 `account_id`
values, every one in a JavaScript or CSS body (`key:!0`, `auth = crc_sign(…)`), and none in a JSON or POST body. Running
those passes on the text route would hash about 24,000 code tokens (ADR-12: no leak named, fidelity lost), so they are
the HTML engine's alone.

A JSON fixture is read in one pass over its string literals, in document order, so each finding is reported on the line
its own literal starts on — every occurrence of a repeated value on its own line, however the literal is escaped (`:`,
PHP's `\/`, an escaped quote). Line numbers come from one index of the newline offsets, so the cost stays linear in the
fixture's size.

**Tag runs are quote-aware and bounded.** Every regex that reads inside a tag — the tag chains of passes 2, 2d and 3,
the sibling and SSID attribute rules, password and SSID inputs, CSRF meta tags — writes an attribute run as `_TAG_RUN`:
an attribute's quoted value, which may hold `<` or `>` (an `onkeyup="if(this.value.length<8)…"` handler), or any
character but `<`, `>` or a quote, so an unquoted value may hold `(`, `)`, `;`, `{` or `}` (`onfocus=clear()`,
`style=font-weight:bold;`: 1,045 fleet tags hold such a value — 292 `<li>`, 247 `<a>`, 227 `<input>`, 63 `<font>` among
them). A quote opens a value only right after `=` (`=\s*`, the quote JS-escaped or not: `class=\"v\"` in a
`document.write` string, the shape of 32,000 fleet `<td>` tags), so script is not read as a tag: a
`'<input type="password" …'` string in code cannot start a match that pairs the code's string quotes and walks on to a
later `value=` (a run that paired any quotes would make 17 such false redactions across the fleet). Each quoted value is
bounded at 2,048 characters, so one stray quote cannot run a match across the document. A tag whose run is broken — a
stray quote not after `=` (`<font color="red"">`), or a quoted value over 2,048 characters (none of the fleet's tags
holds one) — is not read, and its value is kept. An attribute quote in a password input, SSID input, CSRF meta tag or
SSID attribute may be JS-escaped too, at any depth (`value=\"…\"`). A quoted value runs to the quote that opened it, so
`value="ab'cd"` is one value, and a backslash run belongs to it only before an ordinary character, so the run escaping
the closing quote stays in place. Unquoted, a value stops at whitespace or the tag's `>`, so the markup after the tag
survives. An SSID `<select>` body stops at the next `<select`. A regex with a run on each side of an anchor
(`<input RUN type=password RUN value=`, the CSRF meta tag, the SSID attribute and select rules) runs only to the first
copy of the anchor (`_tag_run_to`): with two free runs, one unclosed tag repeating the anchor would retry the second run
from every copy (five seconds for 56 KB, two minutes for 224 KB). An unquoted "anything but `>`" run would scan a series
of unclosed `<input` or `<a` tags to the end of the body from every `<`: quadratic, and cubic where two runs share a tag
(three minutes for 40 KB of unclosed password inputs). A test pins the rule, and every `pii.json` pattern that reads a
tag is the sanitizer's compiled regex verbatim (`SERIAL_LABEL_RE`, `ACCOUNT_LABEL_RE`, `WPS_PIN_LABEL_RE`,
`PASSWORD_INPUT_RE`, `CSRF_META_RE`), as are the labeled password and session-token patterns (`PASSWORD_FIELD_RE`,
`SESSION_TOKEN_RE`).

**Labeled values keep their separator and quote.** Passes 7 (labeled passwords) and 9 (session tokens) replace only the
value: `passphrase: 'x'` becomes `passphrase: 'PASS_…'`, not `passphrase=PASS_…'`. The value stops at a quote however
deeply it is escaped: in `password=\"hunter2x\"` and `password=\\\"hunter2x\\\"` it is `hunter2x`. A backslash run
belongs to the value only before an ordinary character, so in `"password=abc\\";` the escaped backslash before the
closing quote stays and the string still closes.

**A labeled value is data, not markup or code** (`_LABELED_SEPARATOR`, shared by passes 7 and 9 and `pii.json`). Spacing
entities after the separator are separator (`Password:&nbsp;hunter2` takes `hunter2`; `Password:&nbsp;&nbsp;</td>` has
no value). An unquoted value that is code by syntax — a negation (`password:!0`), an entity, or a call
(`c.getPasswordField(`, `cookie=function(e,t,n)`) — is not taken; a quoted value always is. Across the fleet these are
181 matches, every one spacing or minified script: 145 `Password:&nbsp;…` cells in 19 captures and 36 code values. The
trade: an unquoted password that begins with `!` or `&`, or reads as a call (`abc(`), is left; the fleet has none. `key`
is a credential label glued to a word (`wifikey`, `wifi0_wpapsk_key`, `passkey`); a bare `key` is a script variable as
often as a label — all 44 of its unredacted fleet matches are JavaScript assignments — so its value is offered for
review (`credential`, LOW) instead (`KEY_FIELD_RE`), and `check_for_pii` does not report it. What remains: a glued
`…Key=` followed by a minified member expression (`Key=Y.util…;`, 8 matches in 4 captures) still reads as a credential.

## Heuristic Engine (heuristics.py)

### Analysis Pipeline

```python
def analyze_value(
    value: str,
    values_context: list[str] | None = None,
    value_index: int | None = None,
    extra_safe_patterns: list[re.Pattern] | None = None,
    compiled_detectors: list[CompiledDetector] | None = None,
) -> tuple[bool, ConfidenceLevel, str, str]:
    """Returns (should_flag, confidence, category, reason)."""
```

Detection pipeline (in order):

1. **Skip empty/safe values** — Check against 25+ compiled safe patterns (status words, dates, versions, UUIDs, dB
   values, uptime durations, etc.) plus domain `extra_safe_patterns`
1. **Run domain detectors** — If `compiled_detectors` provided, first matching detector wins. Checks: length bounds,
   letter requirement, regex patterns, CamelCase
1. **Entropy check** — Shannon entropy calculation. Returns `(True, reason)` if entropy ≥ threshold AND mixed character
   types
1. **Credential prefix check** — Regex `^(?:pass(?:word|wd)?|pwd|secret|token|key|auth)[\d!@#$%^&*]+$`
1. **Adjacency check** — If `values_context` provided, checks neighbors for redacted prefixes
1. **Combine signals** — `should_flag = detector OR entropy OR credential OR adjacent`
1. **Determine category** — Priority: credential_prefix > detector > entropy > suspicious
1. **Assign confidence** — Based on signal combination (see table below)

### Entropy Analysis

```python
def calculate_entropy(value: str) -> float:
    """Shannon entropy via character frequency analysis."""

def is_high_entropy(value: str) -> tuple[bool, str]:
    """Returns (is_high, reason_string)."""
```

Thresholds and bounds:

- Default entropy threshold: **2.8** bits/char
- Mixed threshold (3+ char types): **2.0** bits/char
- Minimum length: **8** chars
- Maximum length: **64** chars
- Character types: lowercase, uppercase, digits, special

A value is high-entropy if:

- Length in bounds AND entropy ≥ 2.8 AND 2+ character types
- OR: 3+ character types AND entropy ≥ 2.0

### Credential Prefix Detection

```python
# Pattern: pass123, token42, key!2024, secret789, auth42
_CREDENTIAL_PREFIX_RE = re.compile(
    r"^(?:pass(?:word|wd)?|pwd|secret|token|key|auth)[\d!@#$%^&*]+$",
    re.IGNORECASE
)
# Length bounds: 4-32 chars
```

### Adjacency Detection

Checks if the value at `value_index` in `values_context` is adjacent to an already-redacted value:

Redacted prefixes checked: `MAC_`, `PASS_`, `TOKEN_`, `SERIAL_`, `WIFI_`, `DEVICE_`, `CC_`, `ACCOUNT_`, `CRED_`,
`SENSITIVE_`, `FIELD_`, `AUTH_`, `COOKIE_`, `STORAGE_`, `CONFIG_`

Also checks static placeholders: `XX:XX:XX:XX:XX:XX`, `0.0.0.0`

Returns `(True, "adjacent to redacted value (before/after)")` if a neighbor is redacted.

### Confidence Scoring

```python
def get_confidence_for_value(
    detector_matched: bool,
    entropy_matched: bool,
    adjacent_matched: bool,
    detector_confidence: str | None = None,
) -> ConfidenceLevel:
```

| Signals                     | Result |
| --------------------------- | ------ |
| Adjacent + detector/entropy | HIGH   |
| Detector (high confidence)  | HIGH   |
| Detector (medium) alone     | MEDIUM |
| High entropy alone          | MEDIUM |
| Adjacent alone              | LOW    |
| Nothing matches             | LOW    |

### Domain Detectors

Each detector from domain JSON is compiled into a `CompiledDetector`:

```python
@dataclass
class CompiledDetector:
    category: str            # "wifi_ssid", "device_name", etc.
    confidence: str          # "low", "medium", "high"
    min_length: int
    max_length: int
    requires_letter: bool
    patterns: list[tuple[re.Pattern, str]]  # (compiled_regex, reason)
    camelcase: bool          # Enable CamelCase matching
```

Detection loop for each detector:

1. Check `len(value)` against `min_length` / `max_length`
1. If `requires_letter`: check value contains alphabetic chars
1. Run each regex pattern — first match wins
1. If `camelcase=True` and no pattern matched: check CamelCase pattern `^[A-Z][a-z]+[A-Z][a-zA-Z0-9]*$`

CamelCase examples: `HomeNetwork`, `MyWiFi`, `GuestAccess`

### Heuristic Modes

| Mode       | Pipe-delimited behavior                   | HAR field behavior                |
| ---------- | ----------------------------------------- | --------------------------------- |
| `DISABLED` | No heuristic analysis — skip              | No heuristic flags or redactions  |
| `FLAG`     | Flag values for review, preserve original | Interactive mode (user decides)   |
| `REDACT`   | Auto-redact suspicious values             | Aggressive automated sanitization |

Known patterns (MACs, IPs, emails) are **always** auto-redacted regardless of heuristic mode.

### Safe Value Patterns (25+ built-in)

Categories:

- **Status**: Good, Bad, OK, Error, Connected, Disconnected, Active, Inactive, Online, Offline, Ready, Not Ready
- **Technical**: Numeric (123, 0, 11), dB values (-70dBm, 50dB), interface names (eth0, wlan0, br0)
- **Versions**: 1.0, 2.3.4, v1.2.3
- **Time/Date**: HH:MM, ISO 8601, ctime, RFC 2822, uptime durations
- **Network/Config**: DHCP Client, QAM256, ATDMA, 802.11ac, WPA2, subnet masks
- **Placeholders**: UUIDs, IPv6 (with optional %zone-id), already-redacted values — including multi-word prefixes
  (`SERIAL_NUMBER_...`) and comma/space-separated **lists** of placeholder addresses (`192.0.2.182, 192.0.2.51`), which
  would otherwise clear the entropy bar and re-flag the sanitizer's own replacement values for review

### ReDoS Prevention

- SSID detector enforces `max_length=32` — strings longer than 32 chars are immediately rejected
- All domain detectors have length bounds
- Test suite verifies malicious input (e.g., `A * 150`) processes in \< 0.1s

## Format-Preserving Hasher (hasher.py)

### Construction

```python
hasher = Hasher.create(salt)  # salt = "auto" | None | custom_string
```

- `"auto"` / `"random"`: Generate `secrets.token_hex(16)` — 32 hex chars, cryptographically secure
- `None`: Static placeholders mode (XX:XX:XX:XX:XX:XX, 0.0.0.0, etc.)
- Custom string: Deterministic — same salt + same value = same hash

### Hash Methods

| Method                           | Input                  | Output Format                    | Reserved Range                |
| -------------------------------- | ---------------------- | -------------------------------- | ----------------------------- |
| `hash_mac(mac)`                  | `AA:BB:CC:DD:EE:FF`    | `02:xx:xx:xx:xx:xx`, layout kept | IEEE locally administered bit |
| `hash_ip(ip, is_private=True)`   | `192.168.1.100`        | `10.255.x.x`                     | RFC 1918                      |
| `hash_ip(ip, is_private=False)`  | `8.8.8.8`              | `192.0.2.x`                      | RFC 5737 TEST-NET-1           |
| `hash_ipv6(ipv6)`                | `fe80::1`              | `2001:db8::xxxx:xxxx`            | RFC 3849 documentation        |
| `hash_email(email)`              | `admin@example.com`    | `user_hash@redacted.invalid`     | RFC 2606 `.invalid` TLD       |
| `hash_value(val, prefix)`        | `SECRET123`            | `TOKEN_a1b2c3d4`                 | N/A (prefix-based)            |
| `hash_generic(val, prefix)`      | (alias for hash_value) |                                  |                               |
| `hash_sensitive_value(val, cat)` | `HomeNetwork`          | `WIFI_a1b2c3d4`                  | Category → prefix mapping     |

### Algorithm

```text
input = normalize(value)  # MAC: separators stripped, uppercased; email: lowercased
digest = SHA-256(salt + ":" + prefix + ":" + input)
output = format(digest[:N])  # N bytes depending on output format
```

**MAC layout.** With a salt, `hash_mac` writes its placeholder in the input's layout — `02:a1:…`, `02-a1-…`, bare
`02a1b2c3d4e5`, or dotted `02a1.b2c3.d4e5` — because the placeholder occupies the value's structural position (ADR-12
rule 1): a consumer that parses a bare 12-hex MAC field must still parse its placeholder. Hex is lowercase; a value in
no uniform MAC layout (mixed separators, or not a MAC) gets the colon form. Static mode (`salt=None`) always writes
`XX:XX:XX:XX:XX:XX`.

The digest is taken over the MAC's digits as uppercase colon pairs, whatever the input layout. Every layout of one MAC
therefore shares its digits (`AA:BB:CC:DD:EE:FF` → `02:df:f0:2a:db:05`, `aabbccddeeff` → `02dff02adb05` under one salt).
The placeholder *string* differs by layout, so a colon MAC and its hyphen spelling correlate by digits rather than
byte-for-byte. `allowlist.json` recognizes the colon and hyphen placeholders, which text scans meet. Bare and dotted
placeholders are not in the global allowlist: `02deadbeef12` is as likely a password as a placeholder.

### Category-to-Prefix Mapping

```python
# In hash_sensitive_value():
CATEGORY_PREFIX_MAP = {
    "wifi_ssid": "WIFI",
    "credential": "CRED",
    "device_name": "DEVICE",
    "suspicious": "SENSITIVE",
    "serial_number": "SERIAL",
    "account": "ACCOUNT",
    "field": "FIELD",
    "phone": "PHONE",
    "ssn": "SSN",
}
# Unknown categories → "SENSITIVE"
```

Every prefix emitted here must be listed in `allowlist.json` `hash_prefixes` so downstream tools recognize the
placeholder as already redacted. Pass 2 user redactions route through this same map.

### Internal Caching

Per-hasher instance cache (`dict[str, str]`) keyed by `PREFIX:value` (for MACs, the normalized digits plus the output
layout):

- Ensures the same value always maps to the same hash within a session **for a given prefix**
- Grows unbounded (acceptable for typical HAR sizes)
- Enables correlation preservation: if `AA:BB:CC:DD:EE:FF` appears in 50 entries, it maps to the same
  `02:xx:xx:xx:xx:xx` every time (and the same digits in any other layout)

The prefix is part of the cache key, so a value redacted on two surfaces under different prefixes receives two different
placeholders — a session token in a response body becomes `FIELD_<a>` while the same token in an `Authorization` header
becomes `AUTH_<b>`. Correlation therefore holds within a surface, not across surfaces. This is a property of the current
design, not a guarantee the spec makes: a reader cannot conclude from a sanitized HAR that `FIELD_<a>` and `AUTH_<b>`
are the same secret. [Pass 1b](#pass-1b-redacted-value-propagation) is unaffected — it reuses whichever placeholder the
value was first given, so a propagated copy always matches its source.

### Static Fallbacks (salt=None)

| Type    | Static Value        |
| ------- | ------------------- |
| MAC     | `XX:XX:XX:XX:XX:XX` |
| IP      | `0.0.0.0`           |
| IPv6    | `::`                |
| Email   | `x@x.invalid`       |
| Generic | `***PREFIX***`      |

## Two-Pass Model

### Pass 1: Auto-Sanitize

Entry point: `sanitize_har()` or `sanitize_har_file()`

For each HAR entry:

1. Deep copy the entry (original preserved)
1. `_sanitize_request()` → headers, cookies, POST data, query strings, URL path
1. `_sanitize_response()` → headers, cookies, content (MIME-dispatched)
1. Collect redactions and flags in `RedactionCollector`

Output: Sanitized HAR + `SanitizationReport` containing:

- `auto_redacted_counts`: Dict of category → count
- `flagged`: List of flagged values with category, confidence, reason, context
- `salt`: Session salt (for Pass 2 consistency)

Metadata embedded via `_embed_sanitization_metadata()`:

```json
{
  "log": {
    "_har_capture": {
      "sanitization": {
        "salt_mode": "salted",
        "heuristics": "flag",
        "redaction_counts": {"mac": 12, "ip": 8, "email": 3},
        "review": "completed"
      },
      "_client_side_cookies": ["credential"],
      "_sanitized_credentials": [{"entry_index": 1, "location": "url_query_param"}]
    }
  }
}
```

### Pass 1b: Redacted-Value Propagation

A value redacted on one surface can appear verbatim on another that carries no field name to match — most commonly a URL
path segment (`DELETE /rest/v1/user/3/token/<token>`), where the sanitizer has no label to key on. The strict field-name
rules never see it, so the same secret ends up redacted in the response body and the `Authorization` header but live in
the path.

After every entry is sanitized, `sanitize_har` sweeps the whole HAR once and replaces any remaining verbatim occurrence
of an already-redacted value with the placeholder that value was already assigned.

**This is not a detection rule.** Eligibility is established entirely by the strict rules in Pass 1 — the value is
already known to be a secret. The only question the sweep answers is whether a textual match elsewhere in the file is
necessarily the *same* secret rather than a coincidence.

**Eligibility** (`_is_propagation_eligible`) — all four must hold:

| Criterion                                     | Excludes                                                        |
| --------------------------------------------- | --------------------------------------------------------------- |
| 16+ characters                                | `0`, `1`, `admin` — replacing these globally would wreck a HAR  |
| Character set `[A-Za-z0-9._~+/=:-]`, no space | Phrases and values carrying quoting or structural characters    |
| Contains at least one digit                   | `GetDeviceInformation`, `configurationSettings` — identifiers   |
| Not `is_safe_value()`                         | IPv6, CIDR, timestamps, versions, already-redacted placeholders |

The digit requirement is the operative form of "must not be word-shaped." Method names, config keys, and API identifiers
are alphabetic; opaque tokens carry digits. It deliberately excludes all-letter hex (`deadbeefcafebabe`), which falls
back to review.

**Failing eligibility is not a leak** — the value stays flagged for interactive review, and Pass 2 resolves it if the
user confirms. That is what allows the bar to be strict: a false negative costs one review item, while a false positive
would rewrite unrelated bytes across the file.

Structure is preserved because the substitution is one token for one token: path segment count, query shape, and
delimiters are untouched.

**Needle expansion and ordering** (`_propagation_search_keys`). Each eligible value contributes two needles — its
literal form and its percent-encoded form (`quote(value, safe="")`) — both mapping to the same placeholder. A secret
that had to be escaped to sit in a URL path is otherwise missed entirely, against the rule the form-urlencoded branch
also follows: an encoding difference must not break correlation.

Needles are applied **longest first**. When one redacted value is a prefix of another (a token and a token-plus-suffix),
replacing the shorter first would substitute inside the longer one and emit a corrupted hybrid — neither placeholder nor
original, leaking the remaining suffix. Ordering by descending length makes the result independent of which surface the
sanitizer reached first.

Matching is **exact and case-sensitive**. A copy of a secret that differs only in case is not replaced; case-folding a
global find-replace would widen collision risk, which is precisely what the eligibility rules exist to constrain.

```python
def _is_propagation_eligible(value: str) -> bool:
    """True if a redacted value is safe to replace globally across the HAR."""

def _propagation_search_keys(registry: dict[str, str]) -> list[tuple[str, str]]:
    """Expand eligible values into (needle, placeholder) pairs, longest needle first."""

def _propagate_redacted_values(har_data: dict, registry: dict[str, str]) -> int:
    """Replace remaining verbatim occurrences of redacted values. Returns replacement count."""
```

The registry (`RedactionCollector.redacted_values`) maps original value → assigned placeholder and is populated by
`_redact_value` on every auto-redaction, so a value keeps the placeholder its first surface gave it. The sweep runs
before `_embed_sanitization_metadata`, and its replacement count is recorded under the `propagated` category in
`auto_redacted_counts`. It is one substring scan per needle over the serialized HAR, so it costs needles × size: across
the fleet no capture has more than 5 needles (0.05 s at most); a synthetic capture whose session cookie rotates on each
of 8,000 requests takes about 19 s. A multi-needle matcher is not built for a shape the fleet does not have.

**Review queue.** An eligible value with no surviving occurrence is withdrawn from `report.flagged`
(`RedactionCollector.drop_flagged()`) — presenting it would ask the user for a decision that cannot change the output.
Survival is judged on every string in the HAR, each JSON body's decoded strings included (`_readable_text`): a copy the
sweep's needles do not match — `\/` in a PHP body, an ASCII-escaped JSON string — keeps the value offered, since the
review replaces those forms ([Pass 2](#pass-2-interactive-review)). A copy inside a base64-wrapped payload is not read:
neither the sweep nor the review can rewrite it there, so offering the value would promise a redaction that cannot
happen (base64-wrapped payloads occur nowhere in the fleet). Only flagged values are searched, so the check costs one
scan per flagged, redacted value, not per redacted value (which a session cookie rotating per request would make
quadratic). Values that failed eligibility, and values that were only ever flagged (never auto-redacted), stay in the
queue untouched.

### URL Credential Location Annotation

`sanitize_har` pre-scans the **original** entries (before sanitization replaces credentials with `AUTH_<hash>`
placeholders) and writes `_sanitized_credentials` to `log._har_capture`. This allows downstream consumers to identify
auth entries without pattern-matching the placeholder — `AUTH_<hash>` contains an underscore that falls outside the
base64 alphabet and breaks regex-based detection in the sanitized HAR.

**Algorithm** (`_scan_url_credentials`):

1. Called on `har_data["log"]["entries"]` before the sanitization loop runs.
1. For each entry, take the first credential `iter_url_credentials()` (`patterns/redaction.py`) finds: it reads the raw
   URL query string segments, then the structured `queryString` array, with `find_query_credential()` — every shape in
   [URL Sanitization](#url-sanitization). The query is split at `?` and `#` rather than parsed with `urlparse`, which
   raises on URLs it cannot parse. The scan skips malformed entries (not a dict, no request, a non-string URL,
   `queryString` not a list) so it never raises; rejecting them is structure validation's job.
1. Return `{entry_index: credential}`. The keys become `{"entry_index": i, "location": "url_query_param"}` annotations;
   the values feed [server-token preservation](#server-token-preservation). One scan serves both.

**Output**:

- Empty list (`[]`) means no URL query param credentials were detected.
- Always present after `sanitize_har` — even when empty.
- Sanitizing a file that already carries the annotation keeps its entries (those naming an existing entry; malformed
  items and indices past the entries are dropped) alongside the ones this run finds: an `AUTH_` placeholder is not
  recognizable as a credential, so without the merge a re-sanitized URL-token capture would lose the only record of its
  login. `annotated_url_credential_entries()` (`patterns/redaction.py`) is the one reader, shared by the merge,
  `validate` and [capture-completeness](VALIDATION_SPEC.md#capture-completeness-validation).

```python
def _scan_url_credentials(entries: list) -> dict[int, str]:
    """Map entry index to the URL credential its request carries."""
```

### Server-Token Preservation

For `url_token` auth flows the server responds with an opaque session token in the response body after receiving a
`base64(user:pass)` URL credential. That token is a server-issued artifact, not a user secret, and must be preserved for
HAR replay fidelity.

**Problem**: After the [dispatch](#response-content-dispatch) rules out base64-wrapped JSON and URL payloads, the
response-body credential guard (`_sanitize_body_text`) fires on any remaining body that `is_base64_credential()` matches
— including server tokens that happen to decode to the `x:y` format.

**Heuristic** (`_is_echoed_credential`): When the entry's request URL contained a base64 credential, the response body
is only redacted if it **echoes** that credential:

- body equals the raw URL credential exactly, or
- body equals `btoa(username)`, `btoa(password)`, or `btoa(username:password)` derived from the decoded credential.

Otherwise the body is a server-generated token and is preserved unchanged.

When no URL credential context is available (e.g. `sanitize_entry` called in isolation), the conservative fallback
applies: any response body matching `is_base64_credential()` is redacted.

**Helpers**:

```python
def iter_url_credentials(request: Mapping) -> Iterator[QueryCredential]:  # patterns/redaction.py
    """Yield every base64(user:pass) credential in a HAR request's query."""

def _is_echoed_credential(body: str, url_credential: str) -> bool:
    """True if body echoes the URL credential or a decoded component of it."""
```

**Context threading**: `sanitize_har` takes the `{entry_index: credential}` map from the pre-scan, then passes
`_url_credential` through `sanitize_entry → _sanitize_response → _sanitize_response_content` for each entry that had a
URL credential.

### Cookie Origin Annotation

`sanitize_har` compares cookie names across all entries to detect cookies set client-side (via JavaScript) rather than
via `Set-Cookie` response headers. The result is written to `log._har_capture._client_side_cookies`.

**Algorithm** (`_detect_client_side_cookies`):

1. Scan every response `Set-Cookie` header across all entries; collect cookie names into a set.
1. Scan every request `Cookie` header across all entries; collect cookie names in first-appearance order (deduped).
1. Return names present in request cookies but absent from the `Set-Cookie` set.

**Output**:

- Cookie names only — no values are written.
- Empty list (`[]`) means all cookies in the capture were server-set.
- Order matches first appearance in request `Cookie` headers across the capture.

**Helpers**:

```python
def _parse_cookie_names(cookie_header_value: str) -> list[str]:
    """Parse names from a Cookie request header (name=value; name2=value2)."""

def _parse_set_cookie_name(set_cookie_value: str) -> str | None:
    """Parse the cookie name from a Set-Cookie response header value."""

def _detect_client_side_cookies(entries: list[dict]) -> list[str]:
    """Return cookie names from request headers never set by any Set-Cookie response."""
```

### Pass 2: Interactive Review

Entry point: `apply_user_redactions(report)`

1. User reviews flagged items and sets status: `USER_REDACTED` or `USER_SKIPPED`. Each value is one item: every
   occurrence counts once (a field's flag on its whole value and a narrower pass's flag on the same text are one
   occurrence), and the item takes the label — category and confidence — of its most confident occurrence, the first on
   a tie, so an API key seen first as a `username` is still offered as an API key. A value under three characters is
   never offered.
1. For each `USER_REDACTED` item, longest original value first — an offered value can contain another (a username
   holding a phone number), and replacing the inner one first would leave the outer unmatched:
   - Recreate hasher with original salt from report
   - Hash value: `hasher.hash_sensitive_value(original_value, category)` — the same
     [category→prefix map](#category-to-prefix-mapping) as Pass 1, so user redactions carry recognized placeholder
     prefixes (`CRED_`, `SERIAL_`, ...); a prefix built from the raw category name (`CREDENTIAL_`, `SERIAL_NUMBER_`)
     would not be recognized as redacted everywhere.
   - Collect every form the value can take in a HAR string (`_user_redaction_forms`): as written; percent-encoded as a
     URL path, query value or form body writes it (`quote`, `quote(safe="")`, `quote_plus`); JSON-escaped as a body
     inside the string writes it (`\"`, `\u00e9`, PHP's `\/`).
1. Replace every form with its placeholder inside each string value (`_replace_in_string_values`), one matcher per call,
   longest form first at each position. Keys, numbers and other JSON structure are never touched, so redacting `login=1`
   cannot rewrite every `1` in the file.
1. Refresh the embedded metadata's `user_redacted` / `user_skipped` counts — the metadata is embedded at the end of Pass
   1, before any review decision exists, so a reviewed artifact would otherwise report `user_redacted: 0`
1. Return modified data

**Recording the review:** `record_review(har_path, report, outcome, compressed_path=None)` (`sanitization/review.py`) is
the file side of Pass 2. It applies the user's redactions (`apply_user_redactions`), writes the outcome to
`log._har_capture.sanitization.review` with the `user_redacted` / `user_skipped` counts, replaces the `.sanitized.har`
atomically (LF line endings), and then **regenerates the `.har.gz`** — the one the capture flow names, or an existing
`<har_path>.gz` sibling. Without the regeneration, a `.gz` compressed before the review keeps every value the review
scrubbed, in exactly the artifact contributors upload. A regeneration failure raises `StaleCompressedError` naming the
stale file, and the CLI exits non-zero with that name; `har-capture validate` backstops the pair with a
[freshness check](VALIDATION_SPEC.md#compressed-artifact-freshness-check).

Every ending is recorded, a review that redacted nothing included — a skipped or cancelled review, or one nobody could
be asked for, is exactly what a recipient needs to see. `ReviewOutcome` (`sanitization/report.py`):

| `review`       | Written by                          | Meaning                                                                            |
| -------------- | ----------------------------------- | ---------------------------------------------------------------------------------- |
| `none_flagged` | Pass 1 (`sanitize_har_file`)        | Nothing was offered for review                                                     |
| `completed`    | The CLI, after the review           | The user decided every item (redacting any, all or none of them)                   |
| `skipped`      | The CLI, after the review           | The user chose to keep every flagged value; each item is `USER_SKIPPED`            |
| `cancelled`    | The CLI, after the review           | The user left the review without deciding; items stay `FLAGGED`                    |
| `no_tty`       | The CLI, with no terminal to prompt | Nobody was asked; the flagged values remain as captured                            |
| (absent)       | —                                   | No review recorded: a library caller that ran none, or a version that records none |

Without a terminal `get` and `sanitize` never prompt (InquirerPy would fail and read as a cancel): each records `no_tty`
and prints a warning with the flagged count. `sanitize` also writes the report file; `get` writes none — see ADR-6.

### Pre-Sanitization Detection

```python
def appears_sanitized(content: str) -> bool:
    """Check if file already contains redaction placeholders."""
```

Detects common redaction markers to warn users before double-sanitizing.

## Constraints / Invariants

1. **Pass ordering is critical** — Pass 1 must complete before Pass 2, because Pass 2 relies on the salt and flagged
   values from Pass 1's report.
1. **Same salt for both passes** — Pass 2 recreates the hasher with the salt stored in Pass 1's report, ensuring
   consistent hashing across passes.
1. **Scanner order matters** — Earlier scanners in html.py may redact values that later scanners check. For example, MAC
   scanner (pass 1) runs before the IP scanners (passes 4–6), so MAC addresses aren't misidentified as hex strings.
1. **Depth limit prevents stack overflow** — JSON recursive traversal is capped at 50 levels. Exceeding the limit is
   logged, not fatal. Text nested past the parser's own limit is treated as text that does not parse
   (`parse_json_container()`), so hostile nesting never crashes a sanitize run.
1. **Malformed input doesn't abort** — JSON decode errors, redaction failures, and invalid regex patterns are logged but
   don't stop sanitization of other entries.
1. **Format-preserving placeholders sit in reserved ranges** — TEST-NET and documentation IP ranges cannot appear in
   real traffic. Locally administered MACs (`02:…`) can — VMs and randomized Wi-Fi MACs use them — so a placeholder and
   a real locally administered MAC look alike. The sanitizer therefore never skips a MAC that looks like a placeholder
   (see [Idempotency Boundary](#idempotency-boundary)); the cost falls on `validate`, which cannot tell the two apart
   and does not report either.
1. **Known patterns always apply** — MACs, IPs, and emails are auto-redacted regardless of heuristic mode. Heuristic
   mode only affects opaque/suspicious values. A constant MAC (one byte repeated) is not a MAC in this sense.
1. **Cookie metadata is preserved** — In a `Set-Cookie` value, the reserved attributes (`HttpOnly`, `Secure`,
   `SameSite`, `Path`, `Domain`, `Expires`, `Max-Age`, `Partitioned`, `Priority`) survive verbatim; only the cookie
   pair's value is redacted. The reserved-word list is `COOKIE_ATTRIBUTE_NAMES` in
   `src/har_capture/patterns/redaction.py`, and `cookie_segment_actions()` there is the one segment rule the sanitizer
   and `validate` share.
1. **Credit card detection requires Luhn** — A 16-digit number is only redacted as a credit card if it passes Luhn
   checksum validation.
1. **Pass 2 replaces every copy, and only inside strings** — a user-selected value is replaced wherever a string value
   holds it (headers, bodies, URLs), in every form a string carries it (`_user_redaction_forms`: percent-encoded,
   JSON-escaped). Keys, numbers and other structure are never touched, so no choice can corrupt the HAR.
1. **Scanner passes require 100% confidence** — Every regex in the HTML scanner pipeline (passes 0–16) auto-redacts
   without user review. A pattern that produces false positives is a bug. Patterns that cannot achieve 100% confidence
   belong in the heuristic engine (flagged for user review), not the scanner pipeline.
1. **Propagation never widens what counts as a secret** — [Pass 1b](#pass-1b-redacted-value-propagation) only replaces
   values the strict Pass 1 rules already redacted. It introduces no detection of its own, and a value that fails
   eligibility stays flagged for review. Widening eligibility is a scope change and is governed by
   [ADR-12](../ARCHITECTURE_DECISIONS.md#adr-12-redaction-scope-is-anti-drift--redact-more-is-a-change-against-the-founding-contract).
1. **Output is LF-only on every platform** — Every writer that emits a HAR or report pins `newline="\n"` rather than
   letting Python's text mode substitute `os.linesep`. Captures are committed downstream as immutable evidence in repos
   that enforce LF; a CRLF artifact gets rewritten by their hooks, and the same capture would otherwise be
   byte-different depending on which platform ran the tool.
