# Build image
FROM golang:1.19-alpine as build

WORKDIR /build

# Cache go.mod for pre-downloading dependencies and only redownloading them in subsequent builds if they change
COPY go.mod go.sum ./
RUN go mod download && go mod verify
# Copy source code
COPY . .
# Build
RUN go build -v

# Build image
FROM alpine:3.16 as certs

RUN apk add ca-certificates

# Final image
FROM scratch

COPY --from=certs /etc/ssl/certs /etc/ssl/certs
COPY --from=build /build/letsgo-nats /letsgo-nats

# Create certs directory and nats conf directory
RUN mkdir -p /etc/certs \
    && mkdir -p /etc/nats

# Copy binary
# Define default command
CMD ["/letsgo-nats"]
