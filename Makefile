.PHONY: all build test test-race lint cover bench fuzz eval clean

all: lint test-race build

build:
	go build ./...

test:
	go test ./...

test-race:
	go test -race ./...

lint:
	go vet ./...
	@test -z "$$(gofmt -l .)" || (echo "Unformatted files found:" && gofmt -l . && exit 1)

cover:
	go test -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out

bench:
	go test -bench=. -benchmem ./...

fuzz:
	@echo "Running fuzz tests (time-boxed)..."
	go test -run=^$$ -fuzz=FuzzProcess -fuzztime=10s .
	go test -run=^$$ -fuzz=FuzzEmailDetector -fuzztime=10s ./detector

eval:
	go test -v -run=TestEvaluation ./eval

clean:
	rm -f coverage.out coverage.html profile.out
