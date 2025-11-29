# Build stage
FROM golang:1.24-alpine AS builder

WORKDIR /app

# Copy go mod and sum files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux go build -o sns-counter-api main.go

# Final stage
FROM gcr.io/distroless/static:nonroot

# Copy the binary from builder stage
COPY --from=builder /app/sns-counter-api /

# Expose port 8080
EXPOSE 8080

# Environment variables
ENV PORT=8080

# Use nonroot user
USER nonroot:nonroot

# Run the binary
ENTRYPOINT ["/sns-counter-api"]