# PrivyAI

**Local-first sensitive-data detection, policy, and redaction for Go.**

[![CI](https://github.com/Abhinav-DROID-NG/PrivyAI/actions/workflows/ci.yml/badge.svg)](https://github.com/Abhinav-DROID-NG/PrivyAI/actions/workflows/ci.yml)
![Go 1.22+](https://img.shields.io/badge/go-1.22%2B-00ADD8)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

PrivyAI scans text for sensitive patterns (emails, phone numbers, IP addresses, payment cards, IBANs, government IDs, API keys, private keys, database credentials, and your own custom patterns), assigns each finding a sensitivity **tier**, applies a **policy** (allow, redact, restrict, or block), and returns sanitized text together with metadata-only findings.

It runs entirely in your process: **no network, no database, no cloud service, no LLM, no file I/O, and no third-party dependencies.**

> **Status: pre-release.** The library is tested, fuzzed, and race-checked, but it is not claimed to be production-ready (see [`RELEASE_CHECKLIST.md`](RELEASE_CHECKLIST.md)). It is **not** a complete DLP product and does not guarantee removal of all personal or confidential information. Read [Limitations](docs/limitations.md) before relying on it.

---

## Contents

- [Quick start](#quick-start)
- [What you get back](#what-you-get-back)
- [How it works](#how-it-works)
- [Default behavior](#default-behavior)
- [What it detects](#what-it-detects)
- [Configuration](#configuration)
- [Design guarantees](#design-guarantees)
- [Things to know before you rely on it](#things-to-know-before-you-rely-on-it)
- [Documentation](#documentation)
- [Development](#development)
- [Project layout](#project-layout)
- [License](#license)

---

## Quick start

Requires **Go 1.22 or newer**.

```sh
go get github.com/Abhinav-DROID-NG/PrivyAI@latest
```

```go
package main

import (
	"fmt"
	"log"

	privyai "github.com/Abhinav-DROID-NG/PrivyAI"
)

func main() {
	engine, err := privyai.New(privyai.DefaultConfig())
	if err != nil {
		log.Fatal(err)
	}

	res, err := engine.Process("Contact alice@example.com or +1 415-555-0132 from 10.0.0.5, " +
		"card 4111 1111 1111 1111, SSN 123-45-6789")
	if err != nil {
		log.Fatal(err) // fail closed: never fall back to the original text
	}

	fmt.Println(res.Sanitized)
	fmt.Println(res.Decision)
}
```

Output:

```text
Contact [EMAIL_REDACTED] or [PHONE_REDACTED] from [INTERNAL_IP_REDACTED], card [PAYMENT_CARD_REDACTED], SSN [SSN_REDACTED]
REDACT
```

A runnable version of the smallest example lives in [`examples/basic`](examples/basic):

```sh
go run ./examples/basic
```

> All sample values in this repository are synthetic. `4111 1111 1111 1111` is a well-known test card number, `123-45-6789` is a made-up SSN, and `AKIAIOSFODNN7EXAMPLE` is AWS's documentation example key.

**Next:** [Getting started guide](docs/getting-started.md).

---

## What you get back

`Process` returns a `Result`:

```go
type Result struct {
	Sanitized          string    // text with REDACT findings replaced; empty when blocked
	Findings           []Finding // metadata only: never the matched value
	Decision           Action    // most protective action across all findings
	Blocked            bool
	Restricted         bool
	Conditions         []string  // caller-enforced conditions from RESTRICT rules
	StructuredFallback bool      // structured parsing failed; text was scanned instead
	Stats              Stats     // counts by category and tier
}
```

Each `Finding` describes *where* something was found and *how it was judged*, not *what* it was:

```json
{
  "category": "email",
  "start": 5,
  "end": 22,
  "tier": "T1",
  "source": "email",
  "action": "REDACT",
  "confidence": "HIGH",
  "validated": true
}
```

`start` and `end` are **half-open byte offsets** `[start, end)` into the original input (not rune indexes).

When the decision is `BLOCK`, `Sanitized` is intentionally empty:

```go
res, _ := engine.Process("DATABASE_URL=postgres://admin:hunter2pass@db.internal:5432/app")
// res.Blocked == true, res.Sanitized == "", res.Decision == ActionBlock
```

---

## How it works

```mermaid
flowchart LR
  A[UTF-8 input] --> B[Detectors]
  B --> C[Structured scanners]
  C --> D[Aggregate overlaps]
  D --> E[Classify tiers]
  E --> F[Evaluate policy]
  F --> G{Decision}
  G -->|ALLOW / REDACT / RESTRICT| H[Redact + return result]
  G -->|BLOCK| I[Return no sanitized text]
```

1. **Validate** the input (size limit, UTF-8).
2. **Detect** with the built-in detectors (and any custom rules), plus structured scanners for JSON, `.env`, and YAML-style lines.
3. **Aggregate** duplicate and overlapping spans deterministically.
4. **Classify** each finding into a tier from T0 (public) to T4 (critical).
5. **Evaluate policy** per finding; the overall decision is the most protective action.
6. **Enforce**: redact `REDACT` findings, or return nothing at all on `BLOCK`.

Details: [Architecture](docs/architecture.md).

---

## Default behavior

Tiers describe sensitivity. Policy decides what to do about it. With the built-in policy:

| Tier | Meaning | Default action |
| --- | --- | --- |
| T0 | Public | `ALLOW` |
| T1 | Personal (email, phone, public IP) | `REDACT` for the `external_transmission` context, otherwise `ALLOW` |
| T2 | Confidential (internal IP) | `REDACT` |
| T3 | Restricted (cards, IBAN, SSN/NINO, tokens, secrets) | `REDACT` |
| T4 | Critical (private keys, database credentials) | `BLOCK` |

`Process` uses the `external_transmission` context. Use `ProcessWithOptions` to pick a different context or a structured content type:

```go
res, err := engine.ProcessWithOptions(body, privyai.ProcessOptions{
	ContentType:  privyai.ContentTypeJSON,
	ContextLabel: "local_only", // T1 findings are allowed through in this context
})
```

Policy is configurable as JSON. See [Policy and tiers](docs/policy-tiers.md).

---

## What it detects

| Detector | Categories | Default tier | Notes |
| --- | --- | --- | --- |
| `email` | `email` | T1 | RFC 5321 length and syntax checks |
| `phone` | `phone` | T1 | E.164 and separated national formats; rejects dates, versions, and unbroken digit runs |
| `ip` | `ip`, `internal_ip` | T1, T2 | IPv4 and IPv6; private, loopback, and link-local addresses are `internal_ip` |
| `financial` | `payment_card`, `iban` | T3 | Issuer prefix/length plus Luhn; country length plus MOD-97 |
| `identifiers` | `ssn`, `uk_nino` | T3 | US SSN by default; UK NINO is opt-in via `IdentifierJurisdictions` |
| `secrets` | `aws_access_key`, `github_token`, `slack_token`, `stripe_key`, `google_api_key`, `jwt`, `secret`, `private_key` | T3 (T4 for `private_key`) | Known token formats, PEM blocks, `password=`-style key/value pairs, optional entropy heuristic |
| `database` | `database_credentials` | T4 | URL, ADO/ODBC-style, and JDBC connection strings that contain a password |
| custom | your category | your tier | Regex rules with optional Luhn/MOD-97 validators and required context words |

Per-detector rules, validations, and false-positive notes: [Detection rules](docs/detection-rules.md). Structured formats: [Structured data](docs/structured-data.md).

---

## Configuration

Start from `DefaultConfig()` and change what you need. Everything is in memory; the library never reads files, so load policy and keys yourself and pass the bytes in.

```go
cfg := privyai.DefaultConfig()

// Add a custom detection rule.
cfg.CustomRules = []privyai.CustomRule{{
	Name:       "employee-id",
	Pattern:    `EMP-\d{6}`,
	Category:   "employee_id",
	Tier:       privyai.TierT2Confidential,
	Confidence: privyai.ConfidenceHigh, // required: 1-3
}}

// Keep emails linkable across a document without revealing them.
cfg.Replacement.CategoryStrategies = map[string]privyai.ReplacementStrategy{
	"email": privyai.ReplacementStrategyHMAC,
}
cfg.Replacement.HMACKey = hmacKeyFromYourSecretStore

// Mask all but the last 4 characters of payment cards.
cfg.Replacement.CategoryStrategies["payment_card"] = privyai.ReplacementStrategyPartialMask

// Override the policy.
cfg.PolicyJSON = policyBytes

engine, err := privyai.New(cfg)
```

Every option, its default, and its validation rules: [Configuration reference](docs/configuration.md).

---

## Design guarantees

- **Local only.** Non-test code has no `net/http`, `os/exec`, `syscall`, or `unsafe` imports and performs no file or network I/O.
- **Metadata-only findings.** Raw matched values are never stored in findings, results, diagnostics, or errors.
- **Fail closed by default.** Oversized input, invalid UTF-8, policy failures, and (with the default `FailClosedOnError: true`) detector or redaction failures produce a `BLOCK` result and an error, never the original text.
- **Deterministic.** The same input and configuration always yield the same findings and output. Overlap resolution uses a strict total order.
- **Idempotent.** With the built-in replacement formats, re-processing sanitized output finds nothing new, because redaction placeholders are recognized and skipped.
- **Concurrency-safe.** An `Engine` is immutable after `New` and can be shared across goroutines.
- **Byte-exact spans.** Offsets are validated against UTF-8 rune boundaries before any text is changed.

---

## Things to know before you rely on it

These are easy to trip over; each is covered in more depth in [Troubleshooting](docs/troubleshooting.md).

1. **T4 means `BLOCK` by default.** A private key or a database URL with a password returns an empty `Sanitized` and `Blocked == true`. That is by design.
2. **Only `Process` implies `external_transmission`.** `ProcessWithOptions` with an empty `ContextLabel` does *not*, so T1 findings (emails, phones, public IPs) pass through under the default policy. Context labels are exact-match strings, so a typo such as `external-transmission` silently matches nothing.
3. **`ALLOW` and `RESTRICT` do not redact.** Those findings stay in `Sanitized`. For `RESTRICT`, enforcing `Result.Conditions` is your responsibility.
4. **Always check `err` before using `Result`.** On some error paths the returned `Result` is the zero value, which reads as `ALLOW`.
5. **Custom rules need a `Confidence` (1 to 3) and a deliberate `Tier`.** An unset `Tier` is T0, which the default policy allows through unredacted.
6. **Policy `replacement_label` is parsed but not applied** by the engine yet. Use `Config.Replacement` to control replacement text.
7. **Offsets are bytes.** In `"héllo ✓ alice@example.com"` the email starts at byte 11, not rune 8.

---

## Documentation

| Document | What it covers |
| --- | --- |
| [Getting started](docs/getting-started.md) | Install, first program, reading results, contexts, recipes |
| [Configuration](docs/configuration.md) | Every `Config` field, replacement strategies, custom rules |
| [API reference](docs/API.md) | Public types, functions, errors, JSON shapes, subpackages |
| [Policy and tiers](docs/policy-tiers.md) | Tiers, actions, policy JSON schema, precedence, examples |
| [Detection rules](docs/detection-rules.md) | What each detector matches and rejects |
| [Structured data](docs/structured-data.md) | JSON, `.env`, and YAML-line scanning |
| [Extending](docs/extending.md) | Custom rules, tier overrides, composing the subpackages |
| [Architecture](docs/architecture.md) | Pipeline, package boundaries, aggregation, failure behavior |
| [Troubleshooting](docs/troubleshooting.md) | "Why wasn't this redacted?" and "why was everything blocked?" |
| [Limitations](docs/limitations.md) | Scope, known gaps, security considerations |
| [Evaluation](docs/evaluation.md) | Running and extending the synthetic corpus evaluation |
| [Benchmarks](docs/benchmarks.md) | Measured performance and how to reproduce it |
| [Development](docs/development.md) | Build, test, fuzz, CI, release checklist, contributing |

---

## Development

```sh
make          # lint (go vet + gofmt check), race tests, build
make test     # go test ./...
make cover    # coverage report
make bench    # benchmarks
make fuzz     # time-boxed fuzz runs
make eval     # synthetic corpus evaluation
```

See [Development](docs/development.md) for details.

---

## Project layout

```text
.
├── engine.go, config.go, types.go, errors.go   # public API (package privyai)
├── detector/      # built-in and custom detectors, registry, Finding type
├── structured/    # JSON / .env / YAML-line scanning
├── classifier/    # category -> tier mapping
├── policy/        # JSON policy loading and evaluation
├── redactor/      # span validation and replacement strategies
├── internal/findings/   # overlap resolution (private)
├── examples/basic/      # minimal runnable example
├── eval/ testdata/      # synthetic corpus evaluation
├── benchmarks/ tests/   # benchmarks and integration tests
└── docs/                # documentation
```

---

## License

[MIT](LICENSE) © 2026 Abhinav-DROID-NG
