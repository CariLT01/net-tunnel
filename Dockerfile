# Stage 1: Build
FROM golang:1.25.8 AS builder

WORKDIR /app

# Copy only the server module files first
COPY server/go.mod server/go.sum ./
RUN go mod download

# Copy the rest of the server code
COPY server/ ./

# Build the binary (adjust path if needed)
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o app ./src

# Stage 2: Runtime
FROM alpine:latest

WORKDIR /root/

COPY --from=builder /app/app .

CMD ["./app"]