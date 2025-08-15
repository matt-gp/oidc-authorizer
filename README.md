# OIDC Authorizer

[![Release](https://github.com/matt-gp/oidc-authorizer/actions/workflows/release.yml/badge.svg)](https://github.com/matt-gp/oidc-authorizer/actions/workflows/release.yml)
[![Test](https://github.com/matt-gp/oidc-authorizer/actions/workflows/test-go.yml/badge.svg)](https://github.com/matt-gp/oidc-authorizer/actions/workflows/test-go.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/matt-gp/oidc-authorizer)](https://goreportcard.com/report/github.com/matt-gp/oidc-authorizer)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A lightweight, high-performance OIDC JWT token authorizer for AWS API Gateway Lambda functions, written in Go. This authorizer dynamically handles v1, v2, and WebSocket payloads without requiring configuration changes.

## 🚀 Features

- **Multi-payload Support**: Automatically detects and handles API Gateway v1, v2, and WebSocket authorization requests
- **Zero Configuration**: Works out of the box with sensible defaults
- **OIDC Compliant**: Full OpenID Connect JWT token validation
- **High Performance**: Built in Go for minimal cold start times
- **Flexible Claims**: Configurable principal ID claims mapping
- **Comprehensive Logging**: Structured logging with configurable levels
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

| Environment Variable | Description | Default | Required |
|---------------------|-------------|---------|----------|
| `JWKS_URI` | The URI of the JSON Web Key Set | - | ✅ |
| `ACCEPTED_ISSUERS` | Comma-separated list of accepted token issuers | - | ✅ |
| `PRINCIPAL_ID_CLAIMS` | Comma-separated list of JWT claims to use for principal ID | `sub` | ❌ |
| `LOG_LEVEL` | Log level (debug, info, warn, error) | `info` | ❌ |

### Example Configuration

```bash
export JWKS_URI="https://your-oidc-provider.com/.well-known/jwks.json"
export ACCEPTED_ISSUERS="https://your-oidc-provider.com,https://another-provider.com"
export PRINCIPAL_ID_CLAIMS="sub,preferred_username"
export LOG_LEVEL="debug"
```

## 🏗️ AWS Lambda Deployment

### Using AWS SAM

```yaml
# template.yaml
Resources:
  OidcAuthorizerFunction:
    Type: AWS::Serverless::Function
    Properties:
      CodeUri: .
      Handler: bootstrap
      Runtime: provided.al2
      Environment:
        Variables:
          JWKS_URI: !Ref JwksUri
          ACCEPTED_ISSUERS: !Ref AcceptedIssuers
      Events:
        ApiGatewayAuthorizer:
          Type: Api
          Properties:
            Auth:
              Authorizer: OidcAuthorizer
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
      JWKS_URI = "https://your-oidc-provider.com/.well-known/jwks.json"
      ACCEPTED_ISSUERS = "https://your-oidc-provider.com"
    }
  }
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
