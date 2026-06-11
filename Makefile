.PHONY: run build test migrate-up migrate-down docker-up docker-down

# Default target
all: build

# Build the server binary
build:
	go build -o bin/shorebird-server ./cmd/server

# Run the server locally
run:
	go run ./cmd/server

# Run tests
test:
	go test ./... -v

# Docker Compose
docker-up:
	docker compose up -d
	docker compose logs -f

docker-down:
	docker compose down

# Database migrations
migrate-up:
	goose -dir internal/db/migrations postgres "postgres://shorebird:shorebird@localhost:5432/shorebird?sslmode=disable" up

migrate-down:
	goose -dir internal/db/migrations postgres "postgres://shorebird:shorebird@localhost:5432/shorebird?sslmode=disable" down

# Tidy dependencies
tidy:
	go mod tidy

# Format code
fmt:
	go fmt ./...

# Lint
lint:
	golangci-lint run ./...
