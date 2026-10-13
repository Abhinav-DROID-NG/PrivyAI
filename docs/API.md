# API

The module path is `github.com/Abhinav-DROID-NG/PrivyAI`. The root package is
the stable entry point:

```go
engine, err := privyai.New(privyai.DefaultConfig())
result, err := engine.Process(input)
```

`Engine` is immutable after construction and safe for concurrent use.
`Process` applies the default `external_transmission` context. Use
`ProcessWithOptions` when selecting a context or structured content type:

```go
result, err := engine.ProcessWithOptions(input, privyai.ProcessOptions{
	ContentType:  privyai.ContentTypeJSON,
	ContextLabel: "local_only",
})
```

`Result` contains the sanitized output, metadata-only findings, the most
protective decision, restriction conditions, and aggregate statistics. A
`BLOCK` decision intentionally returns no sanitized input. A `RESTRICT`
decision reports conditions; the caller is responsible for enforcing them.

All findings use half-open byte offsets `[Start, End)` into the original input
bytes. Offsets are not rune indexes and must not be converted before applying
redaction. Raw matched values are not stored in findings, results, diagnostics,
or errors.

The `detector`, `classifier`, `policy`, `structured`, and `redactor` packages
provide lower-level operations for callers that need custom detectors,
policies, structured scanning, or redaction. The root aliases the main domain
types so callers do not need to import those packages for ordinary use.
