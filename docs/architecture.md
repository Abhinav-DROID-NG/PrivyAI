# Architecture

The engine pipeline is:

```mermaid
flowchart LR
  A[Original UTF-8 input] --> B[Detectors]
  B --> C[Structured scanners]
  C --> D[Aggregate overlaps]
  D --> E[Classify tiers]
  E --> F[Evaluate policy]
  F --> G[Enforce redaction/block/restrict]
  G --> H[Result metadata and sanitized text]
```

Detectors emit metadata-only findings with byte offsets into the original
input. Aggregation resolves duplicate and overlapping spans deterministically.
Classification raises detector tiers to configured mappings unless an explicit
override is present. Policy produces the overall action; only REDACT findings
reach the redactor. BLOCK returns no sanitized text.

The engine is immutable after `New` and safe for concurrent use. The core uses
no network or file I/O. Structured JSON failures fall back to ordinary detector
scanning and set `Result.StructuredFallback`.
