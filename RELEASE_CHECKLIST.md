# Release checklist

This checklist records verified repository state only.

- [x] Build, vet, formatting, and race tests pass (`go build ./...`, `go vet ./...`, `gofmt -l .`, `go test -race ./...`).
- [x] Structured fuzz targets have completed 60-second runs.
- [x] JSON fuzz regression is committed under `structured/testdata/fuzz`.
- [x] Documentation for architecture, detection rules, policy, limitations, API, evaluation, and benchmarks exists.
- [x] Benchmark command exists: `go test -bench=. -benchmem ./benchmarks`.
- [x] Evaluation command exists: `make eval`.
- [ ] Full Phase 9 corpus thresholds: not met; current harness has eight smoke samples only.
- [ ] Coverage target of 85%: measured at 82.5% overall.
- [x] Network-import audit: non-test core imports contain no forbidden `net/http`, `os/exec`, `syscall`, or `unsafe` imports.
- [x] Benchmark run completed on Linux amd64, 12th Gen Intel(R) Core(TM) i5-12450H.
- [ ] Staticcheck: not verified.
- [ ] Production readiness: not claimed.

## Not ready for

Do not use this version as the sole control for regulated data, secret
rotation, complete PII removal, or a guarantee that sensitive content is
absent.
