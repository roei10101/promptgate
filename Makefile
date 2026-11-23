.PHONY: all build test lint fmt run

all: lint test build

build:
	go build -o bin/promptgate ./cmd/promptgate

test:
	go test -race -cover ./...

lint:
	@test -z "$$(gofmt -l .)" || (echo "gofmt needed on:"; gofmt -l .; exit 1)
	go vet ./...

fmt:
	gofmt -w .

# Example: make run UPSTREAM=http://localhost:11434
run:
	go run ./cmd/promptgate -upstream $(UPSTREAM)
