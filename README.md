# PrivyAI Core

PrivyAI Core is a standalone, local-first Go library for detecting selected
sensitive patterns, classifying findings, applying policy, and redacting text.
It is **not** a complete DLP product and does not guarantee removal of all
personal or confidential information.

## Usage

```go
engine, err := privyai.New(privyai.DefaultConfig())
if err != nil { log.Fatal(err) }
result, err := engine.Process("Send alice@example.com")
if err != nil { log.Fatal(err) }
fmt.Println(result.Sanitized)
```

Configure policy with `Config.PolicyJSON`; the core performs no file I/O.
Structured input is selected with `ProcessOptions.ContentType` using JSON,
environment lines, or the supported YAML-style `key: value` subset.

```sh
go test ./...
go test -race ./...
go test -bench=. -benchmem ./benchmarks
go test -coverprofile=coverage.out ./...
make eval
```

All detectors use synthetic test data. The project is an MVP and must not be
used as the sole control for regulated data, complete PII removal, or secret
rotation.
