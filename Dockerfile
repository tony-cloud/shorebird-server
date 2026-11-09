# Build stage
FROM golang:1.26.10-alpine AS builder

WORKDIR /app

# Install build dependencies
RUN apk add --no-cache git ca-certificates

# Copy go mod files first for caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source
COPY . .

# Build. SERVER_VERSION (vMAJOR.MINOR.PATCH[-pre]) is reported by --version and
# the self-update status; the image never pins an update signing key.
ARG SERVER_VERSION=
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath \
    -ldflags "-s -w ${SERVER_VERSION:+-X github.com/shorebird-server/internal/version.Version=${SERVER_VERSION}}" \
    -o shorebird-server ./cmd/server

# Runtime stage
FROM alpine:3.20

RUN apk add --no-cache ca-certificates tzdata

# The image is immutable: the server reports self-update as managed
# externally and never replaces its own binary. Update by pulling a new image.
ENV SHOREBIRD_SERVER_MANAGED_EXTERNALLY=docker

WORKDIR /app
COPY --from=builder /app/shorebird-server .
COPY --from=builder /app/web ./web

EXPOSE 8080

ENTRYPOINT ["./shorebird-server"]
