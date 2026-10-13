# PrivyAI Core

PrivyAI is a standalone, local-first Go library for detecting selected
sensitive patterns, classifying findings, evaluating policy, and redacting
text. It has no network, database, cloud, or LLM dependency.

It is **not** a complete DLP product and does not guarantee removal of all
personal or confidential information.

## Installation

```sh
go get github.com/Abhinav-DROID-NG/PrivyAI
```

## Usage

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
	result, err := engine.Process("Send alice@example.com")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(result.Sanitized)
}
```

`Process` uses the default `external_transmission` context. Use
`ProcessWithOptions` to select a policy context or structured format. Supported
structured formats are JSON, `KEY=VALUE` environment lines, and the supported
YAML-style `key: value` line subset.

Configure policy with `Config.PolicyJSON`; the library performs no file I/O.
Default actions are:

| Tier | Default action |
| --- | --- |
| T0 | ALLOW |
| T1 | REDACT for external transmission, otherwise ALLOW |
| T2 | REDACT |
| T3 | REDACT |
| T4 | BLOCK |

Built-in detection categories include email, phone, IPv4/IPv6, internal IP,
payment cards, IBAN, SSN, UK NINO, secrets, database credentials, and custom
rules. Findings expose only metadata and half-open byte spans; raw matched
values are never stored in findings or errors.

```sh
go test ./...
go vet ./...
go test -race ./...
go test -bench=. -benchmem ./benchmarks
go test -coverprofile=coverage.out ./...
make eval
```

All detectors use synthetic test data. The project must not be used as the sole
control for regulated data, complete PII removal, or secret rotation. See
[`docs/limitations.md`](docs/limitations.md) for the threat model and known
gaps. A runnable example is in [`examples/basic`](examples/basic).
