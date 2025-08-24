ARG GO_VERSION=1
FROM golang:${GO_VERSION}-bookworm AS builder

WORKDIR /usr/src/app
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY . .
ARG OTEL_SERVICE_NAME=oidc-authorizer
ARG OTEL_SERVICE_VERSION=1.0.0
ENV OTEL_SERVICE_NAME=${OTEL_SERVICE_NAME}
ENV OTEL_SERVICE_VERSION=${OTEL_SERVICE_VERSION}
RUN go build -v -o /run-app cmd/main.go


FROM debian:stable-slim
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*
COPY --from=builder /run-app /usr/local/bin/
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

CMD ["run-app"]
