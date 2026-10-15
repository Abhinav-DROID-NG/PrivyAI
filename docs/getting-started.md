# Getting started

This guide takes you from installation to a correct, defensive integration. It assumes you have read the [README](../README.md) overview.

## 1. Install

PrivyAI needs Go 1.22 or newer and has no third-party dependencies.

```sh
go get github.com/Abhinav-DROID-NG/PrivyAI@latest
```

Import it with an alias, since the package name is `privyai`:

```go
import privyai "github.com/Abhinav-DROID-NG/PrivyAI"
```

## 2. Create an engine once, reuse it everywhere

An `Engine` compiles its detectors and policy in `New`. It is immutable afterward and safe for concurrent use, so create one at startup and share it.

```go
engine, err := privyai.New(privyai.DefaultConfig())
if err != nil {
	log.Fatal(err) // invalid configuration, bad policy JSON, or bad custom rule
}
```

`New` validates everything up front (see [Configuration](configuration.md#validation)), so a configuration mistake fails at startup rather than on the first request.

## 3. Process text

```go
res, err := engine.Process("Send alice@example.com")
if err != nil {
	return err
}
fmt.Println(res.Sanitized) // Send [EMAIL_REDACTED]
```

`Process` is shorthand for `ProcessWithOptions` with plain text and the `external_transmission` context.

## 4. Read the result

| Field | Meaning |
| --- | --- |
| `Sanitized` | The input with every `REDACT` finding replaced. Empty when `Blocked`. |
| `Findings` | One entry per detected span, sorted by `Start`. Metadata only. |
| `Decision` | The most protective action across findings: `BLOCK` > `RESTRICT` > `REDACT` > `ALLOW`. `ALLOW` when nothing was found. |
| `Blocked` | `true` when the decision is `BLOCK` (or a fail-closed error occurred). |
| `Restricted` | `true` when the decision is `RESTRICT`. |
| `Conditions` | Sorted, de-duplicated strings from `RESTRICT` rules. You enforce them. |
| `StructuredFallback` | `true` when structured parsing failed and the input was scanned as plain text instead. |
| `Stats` | `TotalFindings`, `FindingsByCategory`, `FindingsByTier`. Never contains raw values. |

A `Finding` has `Category`, `Start`, `End`, `Tier`, `Source` (the detector or rule that produced it), `Action`, `Confidence` (`LOW`/`MEDIUM`/`HIGH`), and `Validated` (whether a checksum or structural check passed).

`Start` and `End` are half-open **byte** offsets into the original input. They are safe to slice with (`input[f.Start:f.End]`), but treat that substring as sensitive.

## 5. Act on the decision

Check `err` first, then switch on `Decision`:

```go
func sanitizeForUpload(engine *privyai.Engine, text string) (string, error) {
	res, err := engine.Process(text)
	if err != nil {
		// Fail closed. Never fall back to sending the original text.
		return "", fmt.Errorf("privacy check failed: %w", err)
	}

	switch res.Decision {
	case privyai.ActionBlock:
		return "", fmt.Errorf("blocked: %d finding(s), by tier %v",
			res.Stats.TotalFindings, res.Stats.FindingsByTier)

	case privyai.ActionRestrict:
		// RESTRICT findings are NOT redacted. You must enforce res.Conditions
		// (for example: require approval, or route to an internal-only system).
		return "", fmt.Errorf("restricted: conditions %v", res.Conditions)
	}

	return res.Sanitized, nil // ALLOW or REDACT
}
```

> **Why check `err` first?** On several error paths the engine returns a fail-closed `Result` (`Blocked: true`) along with the error. With `FailClosedOnError: false`, a detector or redaction failure returns the zero `Result{}` and the error. The zero value has `Decision == ActionAllow`, so ignoring `err` could turn a failure into a pass.

## 6. Choose a context

The *context label* lets one policy behave differently depending on where text is going. The default policy has one context-sensitive rule: T1 findings (email, phone, public IP) are redacted for `external_transmission` and allowed otherwise.

```go
// Going to a third-party service: emails are redacted.
ext, _ := engine.Process(text)

// Staying inside your own system: emails are allowed.
loc, _ := engine.ProcessWithOptions(text, privyai.ProcessOptions{
	ContextLabel: "local_only",
})
```

Two things to remember:

- Labels are free-form strings compared **exactly**. `"external-transmission"` (hyphen) does not match `"external_transmission"` (underscore).
- `ProcessWithOptions(text, privyai.ProcessOptions{})` has an empty label, which is *not* `external_transmission`. Set the label explicitly whenever you use `ProcessWithOptions`.

## 7. Scan structured content

Tell the engine what the text is so it can also use key names (`"password": "..."`) as signals:

```go
res, err := engine.ProcessWithOptions(body, privyai.ProcessOptions{
	ContentType:  privyai.ContentTypeJSON,
	ContextLabel: "external_transmission",
})
```

| `ContentType` | Use for |
| --- | --- |
| `ContentTypePlainText` (default) | Free text |
| `ContentTypeJSON` | JSON documents |
| `ContentTypeEnv` | `KEY=VALUE` lines, `export KEY=VALUE` |
| `ContentTypeYAMLLines` | Simple `key: value` lines (not full YAML) |
| `ContentTypeAuto` | JSON if the trimmed input starts with `{` or `[`, otherwise plain text |

Structured scanning is *additive*: all the regular detectors still run over the whole text. Details in [Structured data](structured-data.md).

## 8. Customize

The most common first customizations:

```go
cfg := privyai.DefaultConfig()

// Only run some detectors (nil means all built-in detectors).
cfg.EnabledDetectors = []string{"email", "secrets", "financial"}

// Detect UK National Insurance numbers as well as US SSNs.
cfg.IdentifierJurisdictions = []string{"US", "UK"}

// Reject anything over 256 KiB instead of the 10 MiB default.
cfg.MaxInputBytes = 256 * 1024

// Turn on the (noisier) high-entropy secret heuristic.
cfg.EntropyDetection = true

engine, err := privyai.New(cfg)
```

See [Configuration](configuration.md) for all options, [Policy and tiers](policy-tiers.md) to change what happens to each tier, and [Extending](extending.md) for custom rules.

## 9. Recipes

### Keep values correlatable without exposing them

Use HMAC replacement so the same input always maps to the same token under one key:

```go
cfg := privyai.DefaultConfig()
cfg.Replacement.CategoryStrategies = map[string]privyai.ReplacementStrategy{
	"email": privyai.ReplacementStrategyHMAC,
}
cfg.Replacement.HMACKey = key // load from your secret manager; never hard-code
engine, _ := privyai.New(cfg)

res, _ := engine.Process("alice@example.com wrote to bob@example.com, cc alice@example.com")
// [HMAC_…a] wrote to [HMAC_…b], cc [HMAC_…a]   (first and third tokens are identical)
```

Treat the key as a secret: with the key, low-entropy values (phone numbers, for instance) can be recovered by guessing.

### Show where something was found without revealing it

Findings carry offsets and categories, which is enough for UI highlighting or audit logs:

```go
for _, f := range res.Findings {
	log.Printf("found %s at bytes [%d,%d) tier=%s action=%s", f.Category, f.Start, f.End, f.Tier, f.Action)
}
```

`Finding` implements `String()` in the same value-free format, so `log.Println(f)` is also safe.

### Gate on a decision without sending anything

```go
res, err := engine.Process(candidate)
if err != nil || res.Decision == privyai.ActionBlock {
	return errors.New("refusing to transmit")
}
```

### Process many inputs concurrently

```go
var wg sync.WaitGroup
for _, doc := range docs {
	wg.Add(1)
	go func(doc string) {
		defer wg.Done()
		res, err := engine.Process(doc) // same engine, many goroutines
		_ = res
		_ = err
	}(doc)
}
wg.Wait()
```

## 10. Testing your integration

Use synthetic values. These are safe, valid-looking examples that the detectors recognize:

| Category | Example |
| --- | --- |
| `email` | `alice@example.com` |
| `phone` | `+1 415-555-0132` |
| `payment_card` | `4111 1111 1111 1111` (a common test Visa; passes Luhn) |
| `ssn` | `123-45-6789` |
| `iban` | `GB82 WEST 1234 5698 7654 32` (the standard documentation example) |
| `aws_access_key` | `AKIAIOSFODNN7EXAMPLE` (AWS's documentation key) |
| `database_credentials` | `postgres://admin:hunter2pass@db.internal:5432/app` |
| `private_key` | A PEM block with `-----BEGIN RSA PRIVATE KEY-----` / `-----END RSA PRIVATE KEY-----` markers and any body |

Never put real personal data or live credentials in tests or in issue reports.

## Where to go next

- Something wasn't redacted, or everything was blocked: [Troubleshooting](troubleshooting.md)
- Every option explained: [Configuration](configuration.md)
- Change what happens per tier or per context: [Policy and tiers](policy-tiers.md)
- Know what it can't do: [Limitations](limitations.md)
