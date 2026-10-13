# Detection rules

| Detector | Categories | Default tiers |
|---|---|---|
| Email | `email` | T1 |
| Phone | `phone` | T1 |
| IP | `ip`, `internal_ip` | T1, T2 |
| Secrets | cloud tokens, JWT, `secret`, `private_key` | T3/T4 |
| Financial | `payment_card`, `iban` | T3 |
| Identifiers | `ssn`, `uk_nino` | T3 |
| Database | `database_credentials` | T4 |
| Custom | configured category | configured tier |

Detectors validate boundaries and, where applicable, Luhn or MOD-97 checks.
Regex and entropy heuristics can produce false positives and cannot reliably
detect free text, encoded values, split secrets, or non-US formats.
