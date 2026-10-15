# Configuration reference

Engines are configured with a `privyai.Config` passed to `privyai.New`. Always start from `privyai.DefaultConfig()` and change individual fields; a zero-value `Config{}` is *not* equivalent to the defaults (for example, it has no input size limit, `FailClosedOnError` is `false`, and `DefaultTier` is T0).

```go
cfg := privyai.DefaultConfig()
cfg.MaxInputBytes = 1 << 20
engine, err := privyai.New(cfg)
```

The library performs no file I/O. Anything that would normally come from a file (policy, HMAC key) is passed as bytes.

## Quick reference

| Field | Type | Default | Purpose |
| --- | --- | --- | --- |
| `EnabledDetectors` | `[]string` | `nil` (all built-ins) | Which built-in detectors run |
| `PolicyJSON` | `[]byte` | `nil` (built-in policy) | Replace the default policy |
| `PolicyPath` | `string` | `""` | Unsupported; must stay empty |
| `TierOverrides` | `map[string]Tier` | `nil` | Force a tier for a category |
| `DefaultTier` | `Tier` | `T2` | Minimum tier for categories with no built-in mapping |
| `CustomRules` | `[]CustomRule` | `nil` | User-defined regex detectors |
| `Replacement` | `ReplacementConfig` | label strategy | How redacted text is rendered |
| `MaxInputBytes` | `int64` | `10 MiB` | Largest accepted input (`0` = no limit) |
| `EntropyDetection` | `bool` | `false` | Enable the high-entropy secret heuristic |
| `EntropyThreshold` | `float64` | `4.5` | Shannon entropy cutoff (bits per character) |
| `IdentifierJurisdictions` | `[]string` | `["US"]` | Which government ID formats to detect |
| `DatabaseRedactMode` | `DatabaseRedactMode` | `PasswordOnly` | Redact the password or the whole connection string |
| `FailClosedOnError` | `bool` | `true` | Convert detector/redaction failures into a blocked result |
| `FailClosedBehavior` | `FailClosedBehavior` | `NoOutput` | What `Sanitized` contains on a fail-closed result |
| `AllowInvalidUTF8` | `bool` | `false` | Accept input that is not valid UTF-8 |
| `StructuredMaxDepth` | `int` | `100` | JSON nesting limit for structured scanning |

---

## Detectors

### `EnabledDetectors`

`nil` enables every built-in detector. A non-nil slice enables only the named ones.

| Name | Detector |
| --- | --- |
| `email` | Email addresses |
| `phone` | Phone numbers |
| `ip` | IPv4/IPv6, public and internal |
| `secrets` | Tokens, keys, PEM blocks, key/value secrets, optional entropy |
| `financial` | Payment cards and IBANs |
| `identifiers` | SSN and UK NINO |
| `database` | Database connection strings with passwords |

Notes:

- An empty but non-nil slice (`[]string{}`) disables *all* built-in detectors.
- Unrecognized names are ignored without error. Double-check spelling.
- Custom rules are registered whenever `CustomRules` is non-empty, independent of `EnabledDetectors`.
- Structured scanning (see `ContentType`) is not a detector and is not affected by this setting.

### `IdentifierJurisdictions`

Controls the `identifiers` detector. Case-insensitive.

| Value | Enables |
| --- | --- |
| `"US"` | `ssn` (formatted `123-45-6789` or `123 45 6789`; nine bare digits only with a context word such as `ssn`) |
| `"UK"` or `"GB"` | `uk_nino` |

An empty list falls back to `["US"]`. If you supply a non-empty list that omits `"US"`, SSN detection is off.

### Entropy detection

```go
cfg.EntropyDetection = true
cfg.EntropyThreshold = 4.5 // bits per character; values <= 0 fall back to 4.5
```

When enabled, the secrets detector also flags tokens of 20+ characters from `[A-Za-z0-9_-]` that are not pure hex or UUIDs, mix at least three character classes (upper, lower, digit, other), and have Shannon entropy at or above the threshold. These findings are category `secret`, T3, confidence `LOW`, `Validated: false`. Raise the threshold to trade recall for fewer false positives.

### `DatabaseRedactMode`

| Value | What a `database_credentials` finding covers |
| --- | --- |
| `DatabaseRedactPasswordOnly` (default) | Just the password: `postgres://admin:[DATABASE_CREDENTIALS_REDACTED]@db:5432/app` |
| `DatabaseRedactFullURL` | The entire connection string: `[DATABASE_CREDENTIALS_REDACTED]` |

`database_credentials` is T4 and the default policy **blocks** T4, so this setting only changes visible output if your policy redacts T4 instead.

---

## Classification

### `DefaultTier`

Findings from categories that have no built-in tier mapping are raised to at least this tier. It does not lower anything. The default is T2.

### `TierOverrides`

Forces the tier for a category, overriding both the built-in mapping and the detector's own tier. Unlike `DefaultTier`, an override can **lower** a tier as well as raise it.

```go
cfg.TierOverrides = map[string]privyai.Tier{
	"email":       privyai.TierT3Restricted, // treat emails as restricted
	"internal_ip": privyai.TierT1Personal,   // relax internal IPs
}
```

The built-in category-to-tier mapping is listed in [Policy and tiers](policy-tiers.md#classification).

---

## Policy

### `PolicyJSON`

A strict JSON policy document. When empty, the built-in policy is used. Parsing errors cause `New` to fail with an error wrapping `ErrInvalidConfig`.

```go
policyBytes, _ := os.ReadFile("policy.json") // your code, not the library's
cfg.PolicyJSON = policyBytes
```

Schema, precedence, and examples: [Policy and tiers](policy-tiers.md).

### `PolicyPath`

Reserved for callers that load policy bytes themselves. Setting it to anything non-empty makes `New` return `ErrInvalidConfig`. Use `PolicyJSON`.

---

## Replacement

`Config.Replacement` controls what the redacted span is replaced with.

```go
type ReplacementConfig struct {
	DefaultStrategy    ReplacementStrategy
	CategoryStrategies map[string]ReplacementStrategy // per-category override
	FixedMaskText      string                         // for FixedMask; default "****"
	HMACKey            []byte                         // required for HMAC
	HMACLength         int                            // hex chars kept; default 16
	PartialMasks       map[string]PartialMaskConfig   // per-category partial-mask settings
}
```

### Strategies

| Strategy | Example output | Notes |
| --- | --- | --- |
| `ReplacementStrategyLabel` (default) | `[EMAIL_REDACTED]` | Upper-cased category name |
| `ReplacementStrategyFixedMask` | `****` | Text from `FixedMaskText` |
| `ReplacementStrategyPartialMask` | `***************1111` | Keeps some characters; see below |
| `ReplacementStrategyHMAC` | `[HMAC_b6467996db8a66b5]` | HMAC-SHA256 of the raw value, hex, truncated to `HMACLength` |

The strategy for a finding is `CategoryStrategies[category]` if present, otherwise `DefaultStrategy`.

### Partial masking

```go
cfg.Replacement.CategoryStrategies = map[string]privyai.ReplacementStrategy{
	"payment_card": privyai.ReplacementStrategyPartialMask,
}
cfg.Replacement.PartialMasks = map[string]privyai.PartialMaskConfig{
	"payment_card": {KeepChars: 4, KeepEnd: true, MaskChar: '*'},
}
```

- `KeepChars`: how many characters to keep.
- `KeepEnd`: `true` keeps trailing characters, `false` keeps leading ones.
- `MaskChar`: the mask rune; `0` becomes `*`.
- With no entry for the category, the default is "keep the last 4, mask with `*`".
- Counting is per character of the matched text **including separators**: `4111 1111 1111 1111` (19 characters) becomes 15 `*` followed by `1111`.
- If the matched text is no longer than `KeepChars`, everything is masked.

### HMAC

```go
cfg.Replacement.CategoryStrategies = map[string]privyai.ReplacementStrategy{"email": privyai.ReplacementStrategyHMAC}
cfg.Replacement.HMACKey = key
cfg.Replacement.HMACLength = 16 // default; values <= 0 or > 64 fall back to 16
```

- The same value under the same key always yields the same token, so you can tell two occurrences are the same without seeing the value.
- A key is mandatory when HMAC is the default *or* any category's strategy. Otherwise `New` returns `ErrHMACKeyRequired`.
- The key is never serialized (it is excluded from JSON).
- A shorter `HMACLength` means shorter tokens and a higher chance that two different values collide.

---

## Custom rules

`Config.CustomRules` adds regex-based detectors. All rules are compiled once, in `New`.

```go
type CustomRule struct {
	Name            string     // required, becomes Finding.Source
	Pattern         string     // required, Go RE2 syntax
	Category        string     // required, becomes Finding.Category
	Tier            Tier       // see warning below
	Confidence      Confidence // required: LOW, MEDIUM, or HIGH
	Validator       string     // optional: "luhn" or "mod97"
	RequiredContext []string   // optional context words
}
```

```go
cfg.CustomRules = []privyai.CustomRule{
	{
		Name:       "employee-id",
		Pattern:    `EMP-\d{6}`,
		Category:   "employee_id",
		Tier:       privyai.TierT2Confidential,
		Confidence: privyai.ConfidenceHigh,
	},
	{
		Name:            "account-number",
		Pattern:         `\b\d{8}\b`,
		Category:        "account_number",
		Tier:            privyai.TierT3Restricted,
		Confidence:      privyai.ConfidenceMedium,
		RequiredContext: []string{"account"},
	},
}
```

How rules behave:

- **Pattern** uses Go's `regexp` (RE2). The match is the finding span, so use anchors such as `\b` rather than relying on surrounding text. Matches that are already redaction placeholders are skipped.
- **Validator** `"luhn"` keeps a match only if its digits pass the Luhn check; `"mod97"` applies the IBAN MOD-97 check to the match (spaces removed, upper-cased). A passing validator sets `Validated: true`. Unrecognized validator names are ignored.
- **RequiredContext**: at least one of the words must appear (case-insensitive substring) within 50 bytes before or after the match, otherwise the match is dropped.
- A custom rule's tier takes precedence over the unknown-category fallback (`DefaultTier`), and `TierOverrides` still wins over both.

> **Gotchas.**
> - `Confidence` must be `ConfidenceLow`, `ConfidenceMedium`, or `ConfidenceHigh`. Leaving it unset (zero) makes `New` fail with a `*RuleError`.
> - `Tier` is *not* required, but the zero value is `TierT0Public`. A rule with no tier produces T0 findings, which the default policy **allows through unredacted**. Always set `Tier` deliberately.

More examples: [Extending](extending.md).

---

## Safety limits and failure behavior

### `MaxInputBytes`

Inputs longer than this are rejected with `ErrInputTooLarge` before any scanning. `0` disables the limit; negative values are invalid. Because scan time grows roughly linearly with input size (see [Benchmarks](benchmarks.md)), lower this for latency-sensitive paths.

### `AllowInvalidUTF8`

By default, input that is not valid UTF-8 is rejected with `ErrInvalidUTF8`. Set to `true` only if you must process such input and accept the consequences for detectors and span validation.

### `StructuredMaxDepth`

Maximum JSON nesting depth for structured scanning (default 100). Deeper documents are treated as unparsable and fall back to plain-text scanning with `StructuredFallback == true`. Negative values are invalid; `0` uses the default of 100.

### `FailClosedOnError` and `FailClosedBehavior`

These control what happens when something internal goes wrong.

| Situation | Result |
| --- | --- |
| Input too large, invalid UTF-8, policy evaluation failure | **Always** a fail-closed result plus an error |
| Detector panic or redaction failure, `FailClosedOnError: true` (default) | Fail-closed result plus an error |
| Detector panic or redaction failure, `FailClosedOnError: false` | Zero `Result{}` plus an error (`Decision` reads as `ALLOW`, so check `err`) |

A fail-closed result has `Blocked: true` and `Decision: ActionBlock`. `FailClosedBehavior` decides `Sanitized`:

| Value | `Sanitized` on failure |
| --- | --- |
| `FailClosedNoOutput` (default) | `""` |
| `FailClosedRedactAll` | `"[REDACTED]"` |

---

## Validation

`privyai.New` calls `Config.Validate()`, which you can also call yourself. It returns an error wrapping one of these sentinels:

| Problem | Error |
| --- | --- |
| Negative `MaxInputBytes` or `StructuredMaxDepth` | `ErrInvalidConfig` |
| `DefaultTier` outside T0 to T4 | `ErrInvalidConfig` |
| `PolicyPath` set | `ErrInvalidConfig` |
| `TierOverrides` with an empty category or invalid tier | `ErrInvalidConfig` |
| Malformed or unknown-field policy JSON | `ErrInvalidConfig` (message includes the policy problem) |
| HMAC strategy selected without `HMACKey` | `ErrHMACKeyRequired` |
| Custom rule with empty name, empty pattern, bad regex, empty category, invalid tier, or invalid confidence | `*RuleError` (matches `ErrInvalidRule` with `errors.Is`) |

```go
var re *privyai.RuleError
if errors.As(err, &re) {
	log.Printf("rule %q (index %d): %s", re.RuleName, re.RuleIndex, re.Reason)
}
```

Error messages never include raw input.
