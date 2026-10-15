# Policy and tiers

PrivyAI separates two questions:

1. **How sensitive is this?** Answered by *classification*, which assigns each finding a tier from T0 to T4.
2. **What should we do about it?** Answered by *policy*, which maps each finding (by category, tier, and context) to an action.

Tiers express sensitivity only; they never dictate an action by themselves.

## Tiers

| Tier | Name | Intended meaning |
| --- | --- | --- |
| T0 | Public | Non-sensitive |
| T1 | Personal | Personal or identifying data needing selective redaction |
| T2 | Confidential | Must be redacted before external transmission |
| T3 | Restricted | Payment cards, credentials, government IDs |
| T4 | Critical | Private keys, database credentials |

In Go: `TierT0Public` ... `TierT4Critical`. `privyai.ParseTier` accepts `"T3"`, `"t3"`, `"3"`, `"restricted"`, and `"tier3"` (case-insensitive). Tiers marshal to JSON as `"T0"` to `"T4"`.

## Classification

After detection and aggregation, each finding's tier is decided like this:

1. If `Config.TierOverrides` has an entry for the category, that tier is used (it can raise or lower).
2. Otherwise, if a custom rule defines that category, the rule's tier is used.
3. Otherwise the tier is raised, never lowered, to the built-in mapping for that category.
4. Categories with no built-in mapping are raised to at least `Config.DefaultTier` (default T2).

### Built-in mapping

| Category | Tier |
| --- | --- |
| `email`, `phone`, `ip` | T1 |
| `internal_ip` | T2 |
| `ssn`, `uk_nino`, `payment_card`, `iban` | T3 |
| `aws_access_key`, `github_token`, `slack_token`, `stripe_key`, `google_api_key`, `jwt`, `secret` | T3 |
| `private_key`, `database_credentials` | T4 |

Structured scanning can also produce the categories `token` and `api_key` (from keys such as `access_token` and `api_key`). These have no built-in mapping; the scanner assigns them T3 directly, and `DefaultTier` can only raise that.

## Actions

| Action | Effect |
| --- | --- |
| `ALLOW` | The span is left in the output unchanged |
| `REDACT` | The span is replaced according to `Config.Replacement` |
| `RESTRICT` | The span is **left in the output**; the result is marked `Restricted` and carries `Conditions` that *you* must enforce |
| `BLOCK` | No sanitized text is returned at all (`Sanitized == ""`, `Blocked == true`) |

Severity order is `BLOCK > RESTRICT > REDACT > ALLOW`. The overall `Result.Decision` is the most severe action across all findings, or `ALLOW` when there are none.

Only findings whose action is `REDACT` are changed in the output. In a `RESTRICT` result, `REDACT` findings are still redacted and `RESTRICT` findings are left as-is.

## The default policy

```json
{
  "rules": [
    {"id":"t0-allow","min_tier":"T0","max_tier":"T0","action":"ALLOW"},
    {"id":"t1-external-redact","min_tier":"T1","max_tier":"T1","context":"external_transmission","action":"REDACT"},
    {"id":"t1-default-allow","min_tier":"T1","max_tier":"T1","action":"ALLOW"},
    {"id":"t2-redact","min_tier":"T2","max_tier":"T2","action":"REDACT"},
    {"id":"t3-redact","min_tier":"T3","max_tier":"T3","action":"REDACT"},
    {"id":"t4-block","min_tier":"T4","max_tier":"T4","action":"BLOCK"}
  ]
}
```

This is embedded in the library as `policy.DefaultJSON` and is equivalent to `policy.Default()`.

Behaviors that follow from it:

- T1 is redacted only when the context label is exactly `external_transmission`.
- Any private key or database credential makes the whole result `BLOCK`.
- A policy with **no** matching rule fails closed (see below).

## Writing a policy

Pass a JSON document in `Config.PolicyJSON`:

```go
cfg := privyai.DefaultConfig()
cfg.PolicyJSON = policyBytes
engine, err := privyai.New(cfg)
```

### Rule fields

| Field | Type | Meaning |
| --- | --- | --- |
| `id` | string | Optional label for humans |
| `name` | string | Optional label for humans |
| `category` | string | Exact category (`"email"`) or a [`path.Match`](https://pkg.go.dev/path#Match) glob (`"*_key"`, `"aws_*"`) |
| `min_tier` | string | Inclusive lower tier bound, e.g. `"T2"` |
| `max_tier` | string | Inclusive upper tier bound |
| `context` | string | Matches only when the processing context label equals this exactly |
| `action` | string | **Required.** `ALLOW`, `REDACT`, `RESTRICT`, or `BLOCK` (case-insensitive) |
| `conditions` | string array | Reported when this rule's action is applied; meaningful for `RESTRICT` |
| `priority` | integer | Optional explicit priority; see precedence |
| `replacement_label` | string | Parsed and validated, but **not currently applied** by the engine |

All matching fields are optional, but a rule must set at least one of `category`, `min_tier`, `max_tier`, or `context`. Omitted tier bounds are unbounded. A rule matches a finding when **every** field it sets matches.

### Strict loading

Policy JSON is decoded strictly. These are all errors (and cause `privyai.New` to fail with `ErrInvalidConfig`):

- Unknown fields, at the top level or inside a rule
- Trailing data after the JSON document
- An empty `rules` list
- A rule that sets none of `category`, `min_tier`, `max_tier`, `context`
- A tier given as anything other than a string (`"T3"` is accepted, the number `3` is not)
- An unknown action name
- `min_tier` greater than `max_tier`
- An invalid glob in `category`

### Precedence

When several rules match one finding, the winner is chosen in this order:

1. **Explicit priority.** A rule with a `priority` beats one without; between two prioritized rules the higher number wins.
2. **Specificity.** Exact category (most specific) > glob category > tier bounds > anything else.
3. **Protectiveness.** More severe action wins: `BLOCK`, then `RESTRICT`, then `REDACT`, then `ALLOW`.
4. **Rule order.** The earlier rule in the document wins.

Note that `context` does **not** add specificity. In the default policy, `t1-external-redact` and `t1-default-allow` have the same specificity; the former wins in the external context only because `REDACT` is more protective than `ALLOW` (step 3). To make a rule *relax* an action in some context, give it a more specific scope (an exact category) or an explicit `priority`.

### No matching rule: fail closed

If no rule matches a finding, or evaluation fails, the engine does not guess permissively:

- T3 and T4 findings become `BLOCK`
- T0 to T2 findings become `REDACT`

## Examples

### Allow internal IPs locally, redact everything else personal

```json
{
  "rules": [
    {"id":"keep-internal-ips-local","category":"internal_ip","context":"local_only","action":"ALLOW"},
    {"id":"t1-redact","min_tier":"T1","max_tier":"T1","action":"REDACT"},
    {"id":"t2-redact","min_tier":"T2","max_tier":"T2","action":"REDACT"},
    {"id":"t3-redact","min_tier":"T3","max_tier":"T3","action":"REDACT"},
    {"id":"t4-block","min_tier":"T4","max_tier":"T4","action":"BLOCK"}
  ]
}
```

With the input `host 10.0.0.5 mail a@b.com`:

| Context | Output | Decision |
| --- | --- | --- |
| `local_only` | `host 10.0.0.5 mail [EMAIL_REDACTED]` | `REDACT` |
| `external_transmission` | `host [INTERNAL_IP_REDACTED] mail [EMAIL_REDACTED]` | `REDACT` |

The exact-category rule (specificity 4) beats `t2-redact` (tier bounds, specificity 2), so the internal IP survives in `local_only`.

### Require review for emails (RESTRICT)

```json
{
  "rules": [
    {"id":"email-restrict","category":"email","action":"RESTRICT",
     "conditions":["needs_legal_review","no_third_party_logging"]},
    {"id":"t1-allow","min_tier":"T1","max_tier":"T1","action":"ALLOW"},
    {"id":"t2-redact","min_tier":"T2","max_tier":"T2","action":"REDACT"},
    {"id":"t3-redact","min_tier":"T3","max_tier":"T3","action":"REDACT"},
    {"id":"t4-redact","min_tier":"T4","max_tier":"T4","action":"REDACT"}
  ]
}
```

Processing `mail alice@example.com from 10.1.2.3 db postgres://admin:hunter2pass@db.internal:5432/app` produces:

```text
Sanitized:  mail alice@example.com from [INTERNAL_IP_REDACTED] db postgres://admin:[DATABASE_CREDENTIALS_REDACTED]@db.internal:5432/app
Decision:   RESTRICT
Restricted: true
Conditions: [needs_legal_review no_third_party_logging]
```

The email is **not** redacted (RESTRICT never redacts); the internal IP and database password are redacted (their rules say `REDACT`); and `Conditions` tells your code what it must enforce before the text goes anywhere. The engine does not enforce conditions itself.

### Block a whole family of categories

```json
{"id":"block-keys","category":"*_key","action":"BLOCK"}
```

`*_key` matches `aws_access_key`, `stripe_key`, `google_api_key`, and `private_key`.

## Checking a policy for mistakes

`Policy.Validate()` returns non-fatal warnings. The engine does not call it for you, so run it in your own startup or CI checks:

```go
p, err := privyai.LoadPolicy(policyBytes)
if err != nil {
	log.Fatal(err)
}
for _, w := range p.Validate().Warnings {
	log.Println("policy warning:", w)
}
```

It reports two kinds of warning:

- **`rule N allows T3/T4 content`**: a rule with `ALLOW` whose tier bounds reach T3 or T4. Treat these as worth a close look.
- **`rules N and M have equal precedence; protective action wins`**: two rules with the same precedence but different actions. This check is conservative: it compares specificity only and does **not** check whether the two rules' tier ranges or contexts can ever match the same finding. As a result, a policy made of separate per-tier rules (including the built-in one, which yields 11 such warnings) will trigger it even though those rules never conflict. Use it as a prompt to double-check overlapping rules, not as a pass/fail gate.

## Context labels in practice

The context is an arbitrary string supplied per call in `ProcessOptions.ContextLabel`. The library gives no meaning to any label except what your policy gives it. The default policy knows one: `external_transmission`. Pick a small vocabulary (for example `external_transmission`, `local_only`, `audit_log`), reuse constants rather than string literals, and write policy rules for each.
