# Contributing to OIDC Authorizer

Thank you for your interest in contributing to OIDC Authorizer! We welcome contributions from the community and are grateful for any help you can provide.

## 📋 Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Making Changes](#making-changes)
- [Testing](#testing)
- [Submitting Changes](#submitting-changes)
- [Release Process](#release-process)

## 📜 Code of Conduct

This project adheres to a code of conduct. By participating, you are expected to uphold this code. Please be respectful and constructive in all interactions.

## 🚀 Getting Started

### Prerequisites

- Go 1.24+ installed
- Docker installed (for containerized testing)
- Git installed
- A GitHub account

### Development Setup

1. **Fork the repository** on GitHub
2. **Clone your fork** locally:
   ```bash
   git clone https://github.com/YOUR_USERNAME/oidc-authorizer.git
   cd oidc-authorizer
   ```

3. **Add the original repository as upstream**:
   ```bash
   git remote add upstream https://github.com/matt-gp/oidc-authorizer.git
   ```

4. **Install dependencies**:
   ```bash
   go mod download
   ```

5. **Install development tools**:
   ```bash
   # Install mockgen for generating mocks
   go install go.uber.org/mock/mockgen@latest
   
   # Install golangci-lint for linting
   curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(go env GOPATH)/bin v1.54.2
   ```

6. **Set up local OpenTelemetry development environment** (optional):
   ```bash
   # For local development with observability
   export OTEL_SERVICE_NAME="oidc-authorizer-dev"
   export OTEL_SERVICE_VERSION="dev"
   export OTEL_TRACES_EXPORTER="console"
   export OTEL_METRICS_EXPORTER="console"
   export OTEL_LOGS_EXPORTER="console"
   export OTEL_LOG_LEVEL="debug"
   ```

7. **Generate mocks and verify setup**:
   ```bash
   go generate ./...
   go test ./...
   ```

## � Mock Generation (Critical Step)

**⚠️ Important**: The project uses generated mocks for testing. You **must** run `go generate` before your code will compile successfully.

### Why Mock Generation is Required

This project uses `gomock` to generate mock implementations of interfaces for testing. These mocks are not stored in the repository and must be generated locally.

### Generating Mocks

**Before making any changes or running tests**, generate the required mock files:

```bash
# Generate all mocks (this is required for compilation)
go generate ./...
```

This command will:
- Generate `internal/handler/handler_mock.go` from the `Handler` interface
- Create any other mock files defined with `//go:generate` directives

### When to Regenerate Mocks

You need to regenerate mocks when:
- **First time setup** (required for initial compilation)
- **Interface changes**: When you modify any interface that has mocks
- **New interfaces**: When you add new interfaces with `//go:generate` directives
- **Build failures**: When you see "undefined" errors related to mock types

### Verification

After generating mocks, verify everything works:

```bash
# Verify compilation
go build ./...

# Run tests
go test ./...
```

If you see errors like `undefined: MockHandler` or similar, you likely need to run `go generate ./...`.

## �🔨 Making Changes

### Branching Strategy

1. **Create a feature branch** from `main`:
   ```bash
   git checkout main
   git pull upstream main
   git checkout -b feature/your-feature-name
   ```

2. **Use descriptive branch names**:
   - `feature/add-new-claim-support`
   - `bugfix/fix-websocket-parsing`
   - `docs/update-readme`

### Development Guidelines

#### Code Style

- Follow Go conventions and best practices
- Use `gofmt` to format your code
- Use meaningful variable and function names
- Add comments for exported functions and complex logic
- Keep functions small and focused

#### Commit Messages

Use conventional commit format:

```
type(scope): description

[optional body]

[optional footer]
```

Examples:
- `feat(handler): add support for custom claims`
- `fix(auth): resolve token validation edge case`
- `docs(readme): update installation instructions`
- `test(service): add unit tests for token validation`

#### Code Organization

```
oidc-authorizer/
├── cmd/app/           # Application entry point
├── internal/
│   ├── handler/       # HTTP handlers and routing
│   ├── service/       # Business logic
│   └── otel/         # OpenTelemetry utilities and configuration
├── .github/
│   └── workflows/     # CI/CD workflows
├── Dockerfile         # Container definition
└── README.md
```

### OpenTelemetry Integration

When adding new features, ensure proper observability integration:

- **Logging**: Use OpenTelemetry structured logging from `internal/otel/logging.go`
- **Tracing**: Add spans for significant operations using OpenTelemetry Go SDK
- **Metrics**: Include relevant metrics for performance and error tracking
  - All metrics must use the `oidc_authorizer_` prefix
  - Metric labels should use dots (`.`) instead of underscores (`_`) following OpenTelemetry semantic conventions
  - Example: `attribute.String("event.type", "validation")` not `attribute.String("event-type", "validation")`
- **Context**: Pass context through function calls for trace correlation

#### Logging Guidelines

```go
// Use structured logging with OpenTelemetry
import "github.com/matt-gp/oidc-authorizer/internal/otel"

func YourFunction(ctx context.Context) {
    logger := otel.GetLogger()
    
    // Info logging with structured fields
    logger.InfoContext(ctx, "Processing request",
        otel.String("operation", "token-validation"),
        otel.String("issuer", issuer))
    
    // Error logging with error attribute
    if err != nil {
        logger.ErrorContext(ctx, "Validation failed",
            otel.Err(err),
            otel.String("token_id", tokenID))
    }
}
```

#### Metrics Guidelines

```go
// Creating metrics with proper naming
func NewService(meter metric.Meter) (*Service, error) {
    // Use oidc_authorizer_ prefix for all metrics
    counter, err := meter.Int64Counter(
        "oidc_authorizer_operation_total",
        metric.WithDescription("Total number of operations"),
    )
    
    // Use dots in attribute keys following OpenTelemetry conventions
    attributes := []attribute.KeyValue{
        attribute.String("status", "success"),
        attribute.String("event.type", "validation"), // Use dots, not underscores
        attribute.String("operation.name", "token_check"),
    }
    
    counter.Add(ctx, 1, metric.WithAttributes(attributes...))
}
```

#### Testing with OpenTelemetry

- Tests use console exporters to avoid network dependencies
- OpenTelemetry is configured in test setup with appropriate test resource attributes
- Mock OpenTelemetry components when testing integration points

## 🧪 Testing

### Running Tests

```bash
# Run all tests
go test ./...

# Run tests with coverage
go test -cover ./...

# Run tests in verbose mode
go test -v ./...

# Run specific package tests
go test ./internal/handler/...

# Run tests with OpenTelemetry observability (console output)
OTEL_TRACES_EXPORTER=console OTEL_LOGS_EXPORTER=console go test -v ./...
```

### Testing Environment Variables

The test suite uses these OpenTelemetry configurations:

```bash
# Test-specific OpenTelemetry settings (automatically set in tests)
OTEL_SERVICE_NAME="oidc-authorizer-test"
OTEL_SERVICE_VERSION="test"
OTEL_TRACES_EXPORTER="console"
OTEL_METRICS_EXPORTER="console"  
OTEL_LOGS_EXPORTER="console"
OTEL_RESOURCE_ATTRIBUTES="service.name=oidc-authorizer-test,service.version=test"
```

### Writing Tests

- Write unit tests for all new functionality
- Use table-driven tests where appropriate
- Mock external dependencies using gomock
- Aim for >80% code coverage
- Include both positive and negative test cases
- Ensure OpenTelemetry integration doesn't interfere with test reliability

#### Example Test Structure with OpenTelemetry

```go
func TestYourFunction(t *testing.T) {
    // Setup test context with OpenTelemetry
    ctx := context.Background()
    
    tests := []struct {
        name     string
        input    string
        expected string
        wantErr  bool
    }{
        {
            name:     "valid input",
            input:    "test", 
            expected: "result",
            wantErr:  false,
        },
        // more test cases...
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            result, err := YourFunction(ctx, tt.input)
            
            if (err != nil) != tt.wantErr {
                t.Errorf("YourFunction() error = %v, wantErr %v", err, tt.wantErr)
                return
            }
            
            if result != tt.expected {
                t.Errorf("YourFunction() = %v, want %v", result, tt.expected)
            }
        })
    }
}
```

#### Testing OpenTelemetry Integration

```go
func TestWithObservability(t *testing.T) {
    // Tests automatically use console exporters
    // No network dependencies or external services needed
    ctx := context.Background()
    
    // Your test code here - OpenTelemetry will output to console
    // which can be captured and verified if needed
    result, err := FunctionWithTracing(ctx, input)
    
    assert.NoError(t, err)
    assert.Equal(t, expected, result)
}
```

### Generating Mocks

**Critical**: Mocks must be generated before code compilation. See the [Mock Generation](#-mock-generation-critical-step) section above for details.

When you modify interfaces, regenerate mocks:

```bash
go generate ./...
```

## 📤 Submitting Changes

### Before Submitting

1. **Regenerate mocks if interfaces changed**:
   ```bash
   go generate ./...
   ```

2. **Ensure tests pass**:
   ```bash
   go test ./...
   ```

3. **Run linting**:
   ```bash
   golangci-lint run
   ```

4. **Update documentation** if needed

### Pull Request Process

1. **Push your branch** to your fork:
   ```bash
   git push origin feature/your-feature-name
   ```

2. **Create a Pull Request** on GitHub with:
   - Clear title and description
   - Reference any related issues
   - Include testing instructions
   - Add screenshots/examples if applicable

3. **Pull Request Template**:
   ```markdown
   ## Description
   Brief description of changes

   ## Type of Change
   - [ ] Bug fix
   - [ ] New feature
   - [ ] Breaking change
   - [ ] Documentation update

   ## Testing
   - [ ] Tests pass locally
   - [ ] New tests added for new functionality
   - [ ] Manual testing performed

   ## Checklist
   - [ ] Code follows project style guidelines
   - [ ] Self-review completed
   - [ ] Documentation updated
   - [ ] No breaking changes (or breaking changes documented)
   ```

### Review Process

- Maintainers will review your PR within a few days
- Address any feedback promptly
- Keep your branch updated with main:
  ```bash
  git checkout main
  git pull upstream main
  git checkout feature/your-feature-name
  git rebase main
  ```

## 🚀 Release Process

Releases are automated through GitHub Actions:

1. **Merge to main** triggers the release workflow
2. **Docker images** are built and pushed to GHCR
3. **Tags** follow the format: `{branch}-{short-sha}`
4. **GitHub releases** are created automatically

### Version Format

- **Main branch**: `main-abc1234`
- **Feature branches**: `feature-name-abc1234`

## 🎯 Areas for Contribution

We welcome contributions in these areas:

- **Bug fixes**: Check the [issues](https://github.com/matt-gp/oidc-authorizer/issues) for known bugs
- **Features**: Propose new features in discussions first
- **Documentation**: Improve README, add examples, write tutorials
- **Testing**: Increase test coverage, add integration tests
- **Performance**: Optimize code for better performance
- **Security**: Security audits and improvements

## 🆘 Getting Help

- 💬 [GitHub Discussions](https://github.com/matt-gp/oidc-authorizer/discussions) for questions
- 🐛 [GitHub Issues](https://github.com/matt-gp/oidc-authorizer/issues) for bugs
- 📧 Email maintainers for security issues

## 🙏 Thank You

Your contributions make this project better for everyone. We appreciate your time and effort!
