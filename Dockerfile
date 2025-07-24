ARG GO_VERSION=1
FROM golang:${GO_VERSION}-bookworm AS builder

WORKDIR /usr/src/app
COPY oidc-authorizer/go.mod oidc-authorizer/go.sum ./
RUN go mod download && go mod verify
COPY oidc-authorizer .
RUN go build -v -o /run-app cmd/app/app.go


FROM debian:stable-slim
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*
COPY --from=builder /run-app /usr/local/bin/
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

ARG DOCKER_IMAGE_NAME=oidc-authorizer
ARG DOCKER_IMAGE_VERSION=latest
ENV DOCKER_IMAGE_NAME=${DOCKER_IMAGE_NAME}
ENV DOCKER_IMAGE_VERSION=${DOCKER_IMAGE_VERSION}

CMD ["run-app"]
