# Stage 1: Build the Go application
FROM golang:1.25-alpine AS builder

# Set the working directory inside the container
WORKDIR /app

# Copy the go.mod and go.sum files first to cache dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the application source code
COPY . .

# Build the Go application into a single binary
RUN CGO_ENABLED=0 GOOS=linux go build -o main ./main.go

# Stage 2: Final image to run the application
FROM alpine:latest

# Add certificates for HTTPS/SSL connections
RUN apk --no-cache add ca-certificates

# Set the working directory
WORKDIR /app

# Copy the binary and migrations from the builder stage
COPY --from=builder /app/main .
COPY --from=builder /app/migrations ./migrations

# Expose the application port
EXPOSE 8080

# The command to run the application
CMD ["./main"]