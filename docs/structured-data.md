# Structured data

Plain-text detectors look at *values*. Structured scanning adds a second signal: the *key* a value sits under. A string like `hunter2pass` has no recognizable pattern, but `"password": "hunter2pass"` clearly does.

Select a format with `ProcessOptions.ContentType`:

| `ContentType` | Constant value | Scanned as |
| --- | --- | --- |
| `ContentTypePlainText` | `text/plain` | No structured scan |
| `ContentTypeJSON` | `application/json` | JSON |
| `ContentTypeEnv` | `text/x-env` | `KEY=VALUE` lines |
| `ContentTypeYAMLLines` | `text/x-yaml-lines` | `key: value` lines |
| `ContentTypeAuto` | `auto` | JSON if the trimmed input starts with `{` or `[`, otherwise no structured scan |

Any other or empty `ContentType` is treated as plain text.

**Structured scanning is additive.** All regular detectors still run over the entire input, and the results are merged during [aggregation](architecture.md#aggregation). Structured scanning only adds findings for values under sensitive keys; it never suppresses detector findings.

## Sensitive keys

A value is flagged when its key matches one of these (after normalization):

| Key | Reported category |
| --- | --- |
| `password`, `passwd`, `pwd`, `secret`, `client_secret` | `secret` |
| `token`, `access_token`, `authorization` | `token` |
| `api_key`, `apikey` | `api_key` |
| `private_key` | `private_key` |
| `ssn` | `ssn` |
| `card_number` | `payment_card` |

Normalization: keys are lower-cased, surrounding whitespace is trimmed, hyphens and spaces become underscores, and underscores are ignored when comparing. So `apiKey`, `API-KEY`, `Api Key`, and `api_key` all match `api_key`, and `Client-Secret` matches `client_secret`.

Findings from structured scanning have tier T3 (T4 for `private_key`), confidence `HIGH`, `Validated: true`, and a `Source` of `structured.json` or `structured.lines`.

> **Category may differ from the table.** If a regular detector flags the exact same span under a different category, aggregation prefers the detector's finding (it has a higher priority). For example, `"token": "abcdef"` is typically reported as `secret` (from the key/value secrets detector) rather than `token`. The span is redacted either way; only the label differs.

## JSON

```go
res, _ := engine.ProcessWithOptions(
	`{"user":"bob","password":"hunter2pass","note":"hi"}`,
	privyai.ProcessOptions{ContentType: privyai.ContentTypeJSON},
)
// {"user":"bob","password":"[SECRET_REDACTED]","note":"hi"}
```

Details:

- The scanner walks the document without re-serializing it, so spans are **exact byte offsets into your original text**. Quotes are not included in the span, which keeps the redacted output valid JSON.
- A string value is flagged when **its own key** is sensitive, at any nesting depth, including inside objects that sit in arrays (`[{"password":"x"}]` works). Empty strings are ignored.
- Array elements are not associated with the array's key (see the known gap below).
- Only the standard JSON string escapes are accepted; Go-specific escape forms are rejected as invalid JSON.
- Nesting deeper than `Config.StructuredMaxDepth` (default 100) is treated as unparsable.

### Known gap: arrays under a sensitive key

Only string values are flagged by key. If a sensitive key holds an **array** (for example `{"password":["alpha1","beta22"]}`), the elements are *not* flagged by the structured scanner. Worse, the plain-text key/value secrets detector can match just the opening `[` as the "value", so the output becomes malformed while the actual strings are left in place. Do not rely on PrivyAI for secrets stored as arrays under a sensitive key; normalize such data to string values first, or add a [custom rule](extending.md) for your format.

### Fallback on invalid JSON

If the input is not valid JSON, structured scanning contributes nothing, the engine falls back to ordinary text detection, and `Result.StructuredFallback` is `true`. It is **not** an error:

```go
res, err := engine.ProcessWithOptions(`{"password":"x"`, privyai.ProcessOptions{
	ContentType: privyai.ContentTypeJSON,
})
// err == nil, res.StructuredFallback == true
// text detectors still ran, so the secret was still found
```

Use `StructuredFallback` to notice when upstream is sending malformed or truncated JSON.

## Environment files

```go
res, _ := engine.ProcessWithOptions(
	"API_KEY=abc123xyz\nexport DB_PASSWORD=\"s3cr3t\"\nNAME=bob",
	privyai.ProcessOptions{ContentType: privyai.ContentTypeEnv},
)
// API_KEY=[SECRET_REDACTED]
// export DB_PASSWORD="[SECRET_REDACTED]"
// NAME=bob
```

- One entry per line. A leading `export ` is allowed.
- The value is everything after the first `=`, with surrounding whitespace and quote characters stripped from the span.
- Empty values are ignored.

## YAML-style lines

```go
res, _ := engine.ProcessWithOptions(
	"password: hunter2\nname: bob",
	privyai.ProcessOptions{ContentType: privyai.ContentTypeYAMLLines},
)
// password: [SECRET_REDACTED]
// name: bob
```

This is a **line-based subset** of YAML, not a YAML parser. It looks at each line for `key: value`. Not supported: anchors and aliases, multi-line scalars (`|`, `>`), flow style (`{a: 1}`), and keys nested by indentation (a line like `  password: x` is matched by its own key only, without regard to its parents).

Other formats (XML, TOML, INI, CSV) are not structurally scanned; use `ContentTypePlainText` and rely on the regular detectors.

## Choosing a content type

| If your input is… | Use |
| --- | --- |
| Always JSON | `ContentTypeJSON` (so you get `StructuredFallback` on malformed input) |
| Might be JSON or text | `ContentTypeAuto` |
| A config or `.env` file | `ContentTypeEnv` or `ContentTypeYAMLLines` |
| Chat text, logs, prose | `ContentTypePlainText` (the default) |

## Using the `structured` package directly

For lower-level use, `structured.Scan(input, format, maxDepth)` returns `([]detector.Finding, fallback bool, error)`. It returns an error only for an unsupported format value; invalid JSON yields `(nil, true, nil)`. It produces findings only. Aggregation, classification, policy, and redaction are separate steps (see [Extending](extending.md#composing-the-subpackages)).
