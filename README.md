# OIDC Authorizer

[![Release](https://github.com/matt-gp/oidc-authorizer/actions/workflows/release.yml/badge.svg)](https://github.com/matt-gp/oidc-authorizer/actions/workflows/release.yml)
[![Test](https://github.com/matt-gp/oidc-authorizer/actions/workflows/test-go.yml/badge.svg)](https://github.com/matt-gp/oidc-authorizer/actions/workflows/test-go.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/matt-gp/oidc-authorizer)](https://goreportcard.com/report/github.com/matt-gp/oidc-authorizer)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A lightweight, high-performance OIDC JWT token authorizer for AWS API Gateway Lambda functions, written in Go. This authorizer dynamically handles v1, v2, and WebSocket payloads without requiring configuration changes and includes comprehensive OpenTelemetry observability.

## 🚀 Features

- **Multi-payload Support**: Automatically detects and handles API Gateway v1, v2, and WebSocket authorization requests
- **Zero Configuration**: Works out of the box with sensible defaults
- **OIDC Compliant**: Full OpenID Connect JWT token validation
- **High Performance**: Built in Go for minimal cold start times
- **Flexible Claims**: Configurable principal ID claims mapping
- **OpenTelemetry Integration**: Full observability with traces, metrics, and logs
- **Container Ready**: Available as Docker images for easy deployment

## 📦 Installation

### Using Docker (Recommended)

```bash
# Pull the latest image
docker pull ghcr.io/matt-gp/oidc-authorizer:latest

# Run with environment variables
docker run -e JWKS_URI="https://your-oidc-provider/.well-known/jwks.json" \
           -e ACCEPTED_ISSUERS="https://your-oidc-provider" \
           ghcr.io/matt-gp/oidc-authorizer:latest
```

### Building from Source

```bash
# Clone the repository
git clone https://github.com/matt-gp/oidc-authorizer.git
cd oidc-authorizer

# Build the binary
go build -o oidc-authorizer cmd/app/app.go

# Run
./oidc-authorizer
```

## ⚙️ Configuration

The authorizer is configured using environment variables:

### Core Configuration

| Environment Variable | Description | Default | Required |
|---------------------|-------------|---------|----------|
| `JWKS_URI` | The URI of the JSON Web Key Set | - | ✅ |
| `ACCEPTED_ISSUERS` | Comma-separated list of accepted token issuers | - | ✅ |
| `PRINCIPAL_ID_CLAIMS` | Comma-separated list of JWT claims to use for principal ID | `sub` | ❌ |

### OpenTelemetry Configuration

**Default Behavior**: All exporters default to `console` output, making it easy to get started with observability in development and testing environments. For production deployments, set exporters to `otlp` and configure the appropriate endpoint.

| Environment Variable | Description | Default | Required |
|---------------------|-------------|---------|----------|
| `OTEL_SERVICE_NAME` | Service name for OpenTelemetry | `oidc-authorizer` | ❌ |
| `OTEL_SERVICE_VERSION` | Service version for OpenTelemetry | `1.0.0` | ❌ |
| `OTEL_SDK_DISABLED` | Disable OpenTelemetry SDK | `false` | ❌ |
| `OTEL_TRACES_EXPORTER` | Traces exporter (otlp, console, none) | `console` | ❌ |
| `OTEL_METRICS_EXPORTER` | Metrics exporter (otlp, prometheus, console, none) | `console` | ❌ |
| `OTEL_LOGS_EXPORTER` | Logs exporter (otlp, console, none) | `console` | ❌ |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | OTLP endpoint URL | - | ❌ |
| `OTEL_EXPORTER_OTLP_HEADERS` | OTLP headers (key=value,key2=value2) | - | ❌ |
| `OTEL_PROPAGATORS` | Propagator types (tracecontext, baggage) | `tracecontext,baggage` | ❌ |
| `OTEL_TRACES_SAMPLER` | Sampling strategy | `parentbased_always_on` | ❌ |
| `OTEL_TRACES_SAMPLER_ARG` | Sampler argument (e.g., ratio for traceidratio) | `1.0` | ❌ |
| `OTEL_RESOURCE_ATTRIBUTES` | Resource attributes (key=value,key2=value2) | - | ❌ |

### Legacy Configuration

| Environment Variable | Description | Default | Required |
|---------------------|-------------|---------|----------|
| `LOG_LEVEL` | Log level (fallback when OTEL disabled) | `info` | ❌ |

### Example Configuration

#### Basic Configuration
```bash
export JWKS_URI="https://your-oidc-provider.com/.well-known/jwks.json"
export ACCEPTED_ISSUERS="https://your-oidc-provider.com,https://another-provider.com"
export PRINCIPAL_ID_CLAIMS="sub,preferred_username"
```

#### With OpenTelemetry Observability
```bash
# Core configuration
export JWKS_URI="https://your-oidc-provider.com/.well-known/jwks.json"
export ACCEPTED_ISSUERS="https://your-oidc-provider.com"

# OpenTelemetry configuration
export OTEL_SERVICE_NAME="my-oidc-authorizer"
export OTEL_SERVICE_VERSION="2.0.0"
export OTEL_EXPORTER_OTLP_ENDPOINT="https://your-otel-collector:4317"
export OTEL_EXPORTER_OTLP_HEADERS="api-key=your-api-key"
export OTEL_TRACES_SAMPLER="traceidratio"
export OTEL_TRACES_SAMPLER_ARG="0.1"
export OTEL_RESOURCE_ATTRIBUTES="environment=production,region=us-east-1"
```

#### Development with Console Output (Default)
```bash
# Core configuration
export JWKS_URI="https://your-oidc-provider.com/.well-known/jwks.json"
export ACCEPTED_ISSUERS="https://your-oidc-provider.com"

# Console exporters are now the default - no additional configuration needed!
# OpenTelemetry traces, metrics, and logs will be output to the console.
# This is perfect for development, testing, and troubleshooting.

# To explicitly set console exporters (optional):
# export OTEL_TRACES_EXPORTER="console"
# export OTEL_METRICS_EXPORTER="console"
# export OTEL_LOGS_EXPORTER="console"
```

## 🏗️ AWS Lambda Deployment

### Using AWS SAM

```yaml
# template.yaml
Parameters:
  JwksUri:
    Type: String
    Description: JWKS URI for token validation
  AcceptedIssuers:
    Type: String
    Description: Comma-separated list of accepted issuers
  OtelEndpoint:
    Type: String
    Default: ""
    Description: OpenTelemetry OTLP endpoint (optional)

Resources:
  OidcAuthorizerFunction:
    Type: AWS::Serverless::Function
    Properties:
      CodeUri: .
      Handler: bootstrap
      Runtime: provided.al2
      Environment:
        Variables:
          # Core configuration
          JWKS_URI: !Ref JwksUri
          ACCEPTED_ISSUERS: !Ref AcceptedIssuers
          PRINCIPAL_ID_CLAIMS: "sub,preferred_username"
          
          # OpenTelemetry configuration
          OTEL_SERVICE_NAME: "oidc-authorizer"
          OTEL_SERVICE_VERSION: "1.0.0"
          OTEL_EXPORTER_OTLP_ENDPOINT: !Ref OtelEndpoint
          OTEL_TRACES_EXPORTER: !If [HasOtelEndpoint, "otlp", "console"]
          OTEL_METRICS_EXPORTER: !If [HasOtelEndpoint, "otlp", "console"]
          OTEL_LOGS_EXPORTER: !If [HasOtelEndpoint, "otlp", "console"]
          OTEL_RESOURCE_ATTRIBUTES: !Sub "service.name=oidc-authorizer,aws.lambda.function.name=${AWS::StackName}"
      Events:
        ApiGatewayAuthorizer:
          Type: Api
          Properties:
            Auth:
              Authorizer: OidcAuthorizer

Conditions:
  HasOtelEndpoint: !Not [!Equals [!Ref OtelEndpoint, ""]]
```

### Using Terraform

```hcl
resource "aws_lambda_function" "oidc_authorizer" {
  function_name = "oidc-authorizer"
  role         = aws_iam_role.lambda_role.arn
  
  image_uri    = "ghcr.io/matt-gp/oidc-authorizer:latest"
  package_type = "Image"
  
  environment {
    variables = {
      # Core configuration
      JWKS_URI = "https://your-oidc-provider.com/.well-known/jwks.json"
      ACCEPTED_ISSUERS = "https://your-oidc-provider.com"
      PRINCIPAL_ID_CLAIMS = "sub,preferred_username"
      
      # OpenTelemetry configuration
      OTEL_SERVICE_NAME = "oidc-authorizer"
      OTEL_SERVICE_VERSION = "1.0.0"
      OTEL_EXPORTER_OTLP_ENDPOINT = var.otel_endpoint
      OTEL_TRACES_EXPORTER = var.otel_endpoint != "" ? "otlp" : "console"
      OTEL_METRICS_EXPORTER = var.otel_endpoint != "" ? "otlp" : "console"
      OTEL_LOGS_EXPORTER = var.otel_endpoint != "" ? "otlp" : "console"
      OTEL_RESOURCE_ATTRIBUTES = "service.name=oidc-authorizer,aws.lambda.function.name=${var.function_name}"
    }
  }
}

variable "otel_endpoint" {
  description = "OpenTelemetry OTLP endpoint"
  type        = string
  default     = ""
}

variable "function_name" {
  description = "Lambda function name"
  type        = string
  default     = "oidc-authorizer"
}
```

## 🔧 API Gateway Integration

The authorizer automatically detects the API Gateway payload format:

- **API Gateway v1.0**: Legacy REST API format
- **API Gateway v2.0**: HTTP API format  
- **WebSocket**: WebSocket API format

### Authorization Header Formats

The authorizer accepts tokens in these formats:

```
Authorization: Bearer <jwt-token>
Authorization: <jwt-token>
```

## 📊 Observability

The OIDC Authorizer includes comprehensive OpenTelemetry integration for full observability:

### Traces
- **Request tracing**: Complete request lifecycle with span hierarchy
- **JWT validation spans**: Detailed timing for token validation steps
- **Error attribution**: Failed requests with error details and stack traces
- **Distributed tracing**: Correlation with upstream and downstream services

### Metrics
- **Request counters**: Total requests, success/failure rates
- **Response time histograms**: P50, P95, P99 latency measurements
- **Error rate metrics**: Authentication failure rates by reason
- **Token validation timing**: JWT processing performance metrics

### Logs
- **Structured logging**: JSON-formatted logs with consistent fields
- **Correlation IDs**: Trace and span IDs for request correlation
- **Security events**: Authentication failures, token validation errors
- **Performance logs**: Request timing and resource usage

### Integration Examples

#### OpenTelemetry Collector (Local)
```bash
# For local development with OpenTelemetry Collector
export OTEL_EXPORTER_OTLP_ENDPOINT="http://localhost:4317"
export OTEL_TRACES_EXPORTER="console"
export OTEL_METRICS_EXPORTER="console"
export OTEL_LOGS_EXPORTER="console"
```

Example `otel-collector.yaml`:
```yaml
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317
      http:
        endpoint: 0.0.0.0:4318

processors:
  batch:

exporters:
  logging:
    loglevel: debug
  jaeger:
    endpoint: jaeger:14250
    tls:
      insecure: true
  prometheus:
    endpoint: "0.0.0.0:8889"

service:
  pipelines:
    traces:
      receivers: [otlp]
      processors: [batch]
      exporters: [logging, jaeger]
    metrics:
      receivers: [otlp]
      processors: [batch]
      exporters: [logging, prometheus]
    logs:
      receivers: [otlp]
      processors: [batch]
      exporters: [logging]
```

#### Prometheus Metrics
```bash
export OTEL_METRICS_EXPORTER="prometheus"
export OTEL_EXPORTER_PROMETHEUS_PORT="9090"
```

#### Grafana Cloud
```bash
export OTEL_EXPORTER_OTLP_ENDPOINT="https://otlp-gateway.grafana.net/otlp"
export OTEL_EXPORTER_OTLP_HEADERS="Authorization=Basic base64(instance_id:api_key)"
```

## 🧪 Testing

```bash
# Run all tests
go test ./...

# Run with coverage
go test -cover ./...

# Run specific package tests
go test ./internal/handler/...
```

## 🚢 Docker Images

Docker images are automatically built and published to GitHub Container Registry:

- **Latest**: `ghcr.io/matt-gp/oidc-authorizer:latest`
- **Tagged**: `ghcr.io/matt-gp/oidc-authorizer:main-abc1234`

Images are available for both `linux/amd64` and `linux/arm64` architectures.

## 📝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

- 📖 [Documentation](https://github.com/matt-gp/oidc-authorizer/wiki)
- 🐛 [Issue Tracker](https://github.com/matt-gp/oidc-authorizer/issues)
- 💬 [Discussions](https://github.com/matt-gp/oidc-authorizer/discussions)
