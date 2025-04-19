# Stage 1: Build the application
FROM golang:alpine AS builder

# Install build dependencies
RUN apk add --no-cache gcc musl-dev sqlite-dev

WORKDIR /app

# Copy Go module files first for better layer caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY main.go ./

# Build the application with CGO enabled (required for sqlite3)
RUN go build -ldflags="-s -w" .

# Stage 2: Create the runtime image
FROM alpine:latest

# Install runtime dependencies for SQLite
RUN apk --no-cache add ca-certificates sqlite-libs

WORKDIR /app

# Copy the binary from the builder stage
COPY --from=builder /app/gurl .

# Copy templates directory
COPY templates ./templates

# Create user
RUN adduser gurl -D -H

RUN mkdir /data && chown gurl /data
VOLUME /data

USER gurl

# Expose the port
EXPOSE 8080

# Set the entry point
ENTRYPOINT ["/app/gurl", "-db", "/data/gurl.db"]
