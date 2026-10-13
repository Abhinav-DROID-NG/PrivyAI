# Benchmarks

Run `go test -bench=. -benchmem ./benchmarks`. Results depend on the machine,
Go version, and compiler. No unmeasured performance claims are made here.

Measured on Linux amd64, 12th Gen Intel(R) Core(TM) i5-12450H:

| Input | ns/op | B/op | allocs/op |
|---:|---:|---:|---:|
| 100 B | 61,783 | 479 | 5 |
| 10 KB | 6,843,716 | 494 | 5 |
| 1 MB | 918,375,686 | 47,380 | 31 |
