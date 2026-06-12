.PHONY: run build test docker-up docker-down tidy fmt

# Default: build and run with zero dependencies (SQLite + local storage)
all: build run

build:
	go build -o bin/shorebird-server ./cmd/server

run:
	go run ./cmd/server

test:
	go test ./... -v

# Docker with full stack (PostgreSQL + MinIO)
# Uses profiles so docker compose up (no args) does nothing.
docker-up:
	docker compose --profile full up -d

docker-down:
	docker compose --profile full down

tidy:
	go mod tidy

fmt:
	go fmt ./...
