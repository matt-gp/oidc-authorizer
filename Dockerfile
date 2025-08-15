ARG GO_VERSION=1
FROM golang:${GO_VERSION}-bookworm AS builder

WORKDIR /usr/src/app
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY . .
ARG DOCKER_IMAGE_NAME=oidc-authorizer
ARG DOCKER_IMAGE_VERSION=latest
RUN go build -v -ldflags "-X main.Version=${DOCKER_IMAGE_VERSION} -X main.AppName=${DOCKER_IMAGE_NAME}" -o /run-app cmd/app/app.go


FROM debian:stable-slim
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*
COPY --from=builder /run-app /usr/local/bin/
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

CMD ["run-app"]
