# Detection rules

This page describes what each built-in detector matches, what it deliberately rejects, and where it can be wrong. For how detections turn into actions, see [Policy and tiers](policy-tiers.md).

## Summary

| Detector | Priority | Categories | Detector tier | Confidence |
| --- | ---: | --- | --- | --- |
| `database` | 95 | `database_credentials` | T4 | High |
| `secrets` | 90 | `private_key` | T4 | High |
| | | `aws_access_key`, `github_token`, `slack_token`, `stripe_key`, `google_api_key`, `jwt` | T3 | High |
| | | `secret` (key/value) | T3 | Medium |
| | | `secret` (entropy, opt-in) | T3 | Low |
| `financial` | 85 | `payment_card`, `iban` | T3 | High |
| `email` | 80 | `email` | T1 | High |
| `identifiers` | 80 | `ssn` (formatted) | T3 | High |
| | | `ssn` (bare digits, with context) | T3 | Medium |
| | | `uk_nino` | T3 | High |
| `ip` | 75 | `ip` / `internal_ip` | T1 / T2 | High |
| `phone` | 70 | `phone` | T1 | High with `+`, otherwise Medium |
| custom | 70 | your category | your tier | your confidence |

*Priority* is only used to break ties during overlap resolution, after tier and span length (see [Architecture](architecture.md#aggregation)). The final tier of a finding is decided by [classification](policy-tiers.md#classification), not by the detector alone.

**Confidence** reads as: `HIGH` = checksum-verified or cryptographically structured; `MEDIUM` = format-validated or supported by nearby context; `LOW` = a bare pattern or heuristic match. **`Validated`** is `true` when a checksum or structural validation passed.

**Common behavior across detectors**

- Spans are byte offsets, aligned to UTF-8 rune boundaries.
- Text that already looks like a redaction placeholder (`[EMAIL_REDACTED]`, `[HMAC_…]`, `[REDACTED]`, or a run of `*`) is skipped, which makes re-processing sanitized output a no-op.
- Detectors emit findings with `Action: ALLOW`; the policy assigns the real action afterward.

---

## Email: `email`

Matches addresses of the form `local@domain.tld`, trimming surrounding punctuation such as `<`, `>`, quotes, brackets, and trailing `.,;:!?`.

An address is accepted only if all of these hold:

- Exactly one `@`; local part up to 64 bytes, domain up to 255, whole address up to 254
- No leading, trailing, or consecutive dots in the local part or domain
- At least two domain labels, each 1 to 63 characters from letters, digits, and hyphens, none starting or ending with a hyphen
- A top-level label of two or more letters

It is **not** matched when the character just before it is one of `. @ % + _ - : /`, which avoids URL credentials such as `https://user@host.com` and fragments of longer tokens.

Not supported: quoted local parts, comments, internationalized (non-ASCII) addresses.

---

## Phone: `phone`

Matches international (`+` prefix) and national forms with spaces, hyphens, dots, and one set of parentheses, with **7 to 15 digits**. Examples that match: `+1 415-555-0132`, `(415) 555-0132`, `+44 20 7946 0958`.

Deliberately rejected, to reduce false positives:

- Unbroken digit runs with no `+` and no separator (`4155550132` is treated as an ID, not a phone number)
- ISO dates (`2024-01-15`) and timestamps
- Dotted version- or IP-like strings (`1.2.3.4`, `10.0.0.1`)
- SSN-shaped values (`123-45-6789`)
- Unbalanced parentheses, or a `+` anywhere but the start
- Candidates directly adjacent to letters, `_`, `/`, or `@`

Confidence is `HIGH` when the number starts with `+`, otherwise `MEDIUM`. Formats are recognized generically by digit count and separators rather than per-country numbering plans.

---

## IP addresses: `ip`, `internal_ip`

**IPv4**: four dot-separated octets, 0 to 255, no leading zeros. Not matched when preceded by a letter or underscore, or when part of a longer dotted number (`1.2.3.4.5`).

**IPv6**: full and `::`-compressed forms, validated with Go's `net/netip`.

Classification into category and tier:

| Address kind | Category | Tier |
| --- | --- | --- |
| Private (`10/8`, `172.16/12`, `192.168/16`, `fc00::/7`), loopback (`127/8`, `::1`), link-local (`169.254/16`, `fe80::/10`) | `internal_ip` | T2 |
| Everything else | `ip` | T1 |

Because public IPs are T1, the default policy redacts them only for `external_transmission`.

---

## Payment cards: `payment_card`

Matches 13 to 19 digits, either continuous or grouped with spaces/hyphens (for example `4111 1111 1111 1111`, `3782-822463-10005`). A candidate must pass **both**:

1. **Issuer check** (prefix and length):

   | Brand | Prefix | Length |
   | --- | --- | --- |
   | Visa | 4 | 13, 16, 19 |
   | Mastercard | 51 to 55, 2221 to 2720 | 16 |
   | American Express | 34, 37 | 15 |
   | Discover | 6011, 65, 644 to 649, 622126 to 622925 | 16, 19 |
   | Diners Club | 300 to 305, 36, 38 | 14 |
   | JCB | 3528 to 3589 | 16 |

2. **Luhn checksum**

Candidates directly adjacent to a dot-and-digit (as in version strings or IPs) are skipped. Cards from other brands or with non-standard lengths are not detected.

## IBAN: `iban`

Matches `CCkk` (two letters, two check digits) followed by the rest of the account number, continuous or in space-separated blocks of four. A candidate must pass:

- The **country-specific length** from the ISO 13616 table (for countries not in the table, a length of 15 to 34 is accepted)
- The **MOD-97-10 checksum**

---

## Government identifiers: `ssn`, `uk_nino`

Controlled by [`IdentifierJurisdictions`](configuration.md#identifierjurisdictions): `US` is on by default; `UK` or `GB` is opt-in.

### US Social Security Number (`ssn`)

- **Formatted** (`AAA-GG-SSSS` or `AAA GG SSSS`): confidence `HIGH`.
- **Nine bare digits**: only when one of these words appears within 50 bytes before or after: `ssn`, `social security`, `social ins…`, `tax id`, `taxpayer id`, `tin`. Confidence `MEDIUM`.

Structurally invalid numbers are rejected: area `000`, `666`, or `9xx`; group `00`; serial `0000`.

### UK National Insurance number (`uk_nino`)

Two letters, six digits (optionally spaced in pairs), and a suffix letter `A` to `D`, case-insensitive. Rejected if the prefix uses letters `D F I Q U V` as the first letter, `D F I O Q U V` as the second, or is one of `BG GB KN NK NT TN ZZ`.

---

## Secrets: `secrets`

### Private keys: `private_key` (T4)

Whole PEM blocks from `-----BEGIN … PRIVATE KEY-----` through `-----END … PRIVATE KEY-----` (RSA, EC, OPENSSH, PGP, and others whose label ends in `PRIVATE KEY`). The finding covers the entire block, headers included.

### Known token formats (T3, `HIGH`)

| Category | Pattern |
| --- | --- |
| `aws_access_key` | `AKIA` or `ASIA` followed by 16 uppercase letters/digits |
| `github_token` | `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_` + 36 to 255 characters; or `github_pat_` + 82 characters |
| `slack_token` | `xoxb-`, `xoxa-`, `xoxp-`, `xoxr-`, `xoxs-` + 10 or more characters |
| `stripe_key` | `sk_live_` or `rk_live_` + 24 or more alphanumerics (test keys are not matched) |
| `google_api_key` | `AIza` + 34 to 35 base64url characters |
| `jwt` | Three base64url segments of 10+ characters, starting with `eyJ` |

### Key/value secrets: `secret` (T3, `MEDIUM`)

The *value* (not the key) is flagged in forms such as `KEY=VALUE`, `KEY: VALUE`, `"key": "value"`, and `Authorization: Bearer <token>`. Recognized key names (case-insensitive):

`password`, `passwd`, `pwd`, `secret`, `api_key`, `apikey`, `token`, `access_token`, `auth`, `bearer`, `client_secret`

Behavior worth knowing:

- Key names match as **substrings**, so `db_password=…`, `mypassword=…`, `csrf_token=…`, and `oauth: …` are all flagged. This improves recall and also produces false positives (for example, a `csrf_token` you consider harmless).
- The value runs up to whitespace, a quote, or one of `; , } ]`. Trailing sentence punctuation is trimmed from unquoted values.
- Empty values and placeholders (`[SECRET_REDACTED]`, `****`) are skipped.

### High-entropy strings (opt-in)

Off by default. Enable with `Config.EntropyDetection`. See [Entropy detection](configuration.md#entropy-detection) for the exact rules. Findings are `secret`, T3, `LOW`, `Validated: false`. Expect noisier results than the pattern-based checks (long identifiers and random-looking IDs can match).

---

## Database credentials: `database_credentials` (T4)

Detected only when a **password is present**. A connection string without credentials is left alone.

| Form | Example |
| --- | --- |
| URL | `postgres://user:pass@host:5432/db`. Schemes: `postgres`, `postgresql`, `mysql`, `mongodb`, `mongodb+srv`, `redis`, `rediss`, `amqp`, `amqps` |
| ADO / ODBC-style | `Server=db;Database=app;User Id=sa;Password=…;` (with `Server`, `Data Source`, `Database`, `Initial Catalog`, or `Host`, and `Password` or `Pwd`, on one line; either order) |
| JDBC | `jdbc:postgresql://host/db?user=u&password=…` (`postgresql`, `mysql`, `oracle`, `sqlserver`, `mariadb`) |

By default only the password is covered by the finding; set [`DatabaseRedactMode`](configuration.md#databaseredactmode) to `DatabaseRedactFullURL` to cover the whole string. Under the default policy, any `database_credentials` finding **blocks** the entire input.

---

## Custom rules

User-defined regex detectors. See [Configuration](configuration.md#custom-rules) and [Extending](extending.md).

---

## Structured scanners

JSON, `.env`, and YAML-line scanning flag values by key name in addition to the detectors above. See [Structured data](structured-data.md).

---

## False positives and false negatives

These detectors are pattern-based. Regular expressions, checksums, and an optional entropy heuristic can produce false positives and cannot reliably find free text, encoded values, split secrets, or non-US/non-UK formats. Details and the full list of known gaps are in [Limitations](limitations.md); measured behavior on the small synthetic corpus is in [Evaluation](evaluation.md).
